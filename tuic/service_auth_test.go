package tuic

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/logger"
)

// Embed the interfaces so any unexpected QUIC operation fails the test.
type authTestConn struct {
	quic.Connection
	export func(string, []byte, int) ([]byte, error)
}

func (c *authTestConn) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{ExportKeyingMaterial: c.export}
}

func (c *authTestConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	return nil
}

type authTestStream struct {
	quic.ReceiveStream
	*bytes.Reader
}

func (s *authTestStream) Read(p []byte) (int, error)      { return s.Reader.Read(p) }
func (s *authTestStream) CancelRead(quic.StreamErrorCode) {}

func authTestRequest(user byte, valid bool) *authTestStream {
	request := make([]byte, AuthenticateLen)
	request[0], request[1], request[2] = Version, CommandAuthenticate, user
	if valid {
		copy(request[18:], bytes.Repeat([]byte{user}, 32))
	}
	return &authTestStream{Reader: bytes.NewReader(request)}
}

func authTestSession(t *testing.T) *serverSession[string] {
	t.Helper()
	service := &Service[string]{logger: logger.NOP()}
	service.UpdateUsers([]string{"first", "second"}, [][16]byte{{1}, {2}}, []string{"password1", "password2"})
	conn := &authTestConn{export: func(label string, context []byte, length int) ([]byte, error) {
		if len(label) != 16 || length != 32 || string(context) != map[byte]string{1: "password1", 2: "password2"}[label[0]] {
			t.Error("unexpected TLS exporter inputs")
		}
		return bytes.Repeat([]byte{label[0]}, length), nil
	}}
	return &serverSession[string]{
		Service: service, ctx: context.Background(), quicConn: conn,
		connDone: make(chan struct{}), authDone: make(chan struct{}),
	}
}

func authTestPublished(s *serverSession[string]) bool {
	select {
	case <-s.authDone:
		return true
	default:
		return false
	}
}

func TestAuthConcurrent(t *testing.T) {
	s := authTestSession(t)
	conn := s.quicConn.(*authTestConn)
	export := conn.export
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	conn.export = func(label string, context []byte, length int) ([]byte, error) {
		token, err := export(label, context, length)
		arrived <- struct{}{}
		<-release
		return token, err
	}
	type result struct {
		user string
		err  error
	}
	results := make(chan result, 2)
	for i, user := range []string{"first", "second"} {
		go func(id byte, user string) {
			results <- result{user, s.handleUniStream(authTestRequest(id, true))}
		}(byte(i+1), user)
	}
	// Both requests have passed the initial authDone check and reached the
	// exporter. Release them together to contend for identity publication.
	<-arrived
	<-arrived
	close(release)
	var winner string
	for i := 0; i < 2; i++ {
		result := <-results
		if result.err == nil {
			if winner != "" {
				t.Fatal("both authentication requests succeeded")
			}
			winner = result.user
		} else if result.err.Error() != "authentication: multiple authentication requests" {
			t.Fatalf("unexpected authentication error: %v", result.err)
		}
	}
	if winner == "" || !authTestPublished(s) || s.authUser != winner {
		t.Fatalf("winner = %q, published identity = %q", winner, s.authUser)
	}
}

func TestAuthTimeout(t *testing.T) {
	t.Run("timeout wins during token validation", func(t *testing.T) {
		s := authTestSession(t)
		conn := s.quicConn.(*authTestConn)
		export := conn.export
		arrived := make(chan struct{})
		release := make(chan struct{})
		conn.export = func(label string, context []byte, length int) ([]byte, error) {
			close(arrived)
			<-release
			return export(label, context, length)
		}
		result := make(chan error, 1)
		go func() { result <- s.handleUniStream(authTestRequest(1, true)) }()
		<-arrived
		// A zero timeout fires immediately, while authentication is in flight.
		s.handleAuthTimeout()
		close(release)
		if err := <-result; err == nil || !strings.Contains(err.Error(), "authentication timeout") {
			t.Fatalf("late authentication error = %v", err)
		}
		if authTestPublished(s) || s.authUser != "" {
			t.Fatalf("authentication published after timeout: %q", s.authUser)
		}
		select {
		case <-s.connDone:
		default:
			t.Fatal("timeout did not close session")
		}
	})
	t.Run("authentication wins", func(t *testing.T) {
		s := authTestSession(t)
		if err := s.handleUniStream(authTestRequest(1, true)); err != nil {
			t.Fatal(err)
		}
		s.handleAuthTimeout()
		if !authTestPublished(s) || s.authUser != "first" {
			t.Fatal("successful authentication lost")
		}
		select {
		case <-s.connDone:
			t.Fatal("timeout closed authenticated session")
		default:
		}
	})
}

func TestAuthInvalidToken(t *testing.T) {
	s := authTestSession(t)
	if err := s.handleUniStream(authTestRequest(1, false)); err == nil || err.Error() != "authentication: token mismatch" {
		t.Fatalf("invalid token error = %v", err)
	}
	if authTestPublished(s) || s.authUser != "" {
		t.Fatalf("invalid token published identity %q", s.authUser)
	}
}

func TestAuthRepeated(t *testing.T) {
	s := authTestSession(t)
	if err := s.handleUniStream(authTestRequest(1, true)); err != nil {
		t.Fatal(err)
	}
	if err := s.handleUniStream(authTestRequest(2, true)); err == nil || err.Error() != "authentication: multiple authentication requests" {
		t.Fatalf("repeated authentication error = %v", err)
	}
	if !authTestPublished(s) || s.authUser != "first" {
		t.Fatalf("repeated authentication changed identity to %q", s.authUser)
	}
}
