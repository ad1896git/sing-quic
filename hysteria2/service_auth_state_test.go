package hysteria2

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/quicvarint"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type authTestConn struct {
	quic.Connection
	congestionCalls atomic.Int32
	receiveCalls    chan struct{}
	setup           func()
}

func (c *authTestConn) SetCongestionControl(congestion.CongestionControl) {
	c.congestionCalls.Add(1)
	if c.setup != nil {
		c.setup()
	}
}
func (c *authTestConn) ReceiveDatagram(context.Context) ([]byte, error) {
	c.receiveCalls <- struct{}{}
	return nil, context.Canceled
}
func (c *authTestConn) CloseWithError(quic.ApplicationErrorCode, string) error { return nil }

func authTestSession(conn *authTestConn) *serverSession[string] {
	session := &serverSession[string]{
		Service: &Service[string]{
			logger:            logger.NOP(),
			masqueradeHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }),
		},
		ctx: context.Background(), quicConn: conn, connDone: make(chan struct{}),
	}
	session.UpdateUsers([]string{"alice", "bob"}, []string{"alice-key", "bob-key"})
	return session
}

func authTestRequest(key string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://hysteria/auth", nil)
	protocol.AuthRequestToHeader(r.Header, protocol.AuthRequest{Auth: key, Rx: 1})
	return r
}

func authTestReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for authentication test barrier")
	}
	var zero T
	return zero
}

func TestAuthConcurrentFirstWinner(t *testing.T) {
	const contenders = 32
	conn := &authTestConn{receiveCalls: make(chan struct{}, contenders)}
	s := authTestSession(conn)
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(contenders)
	done.Add(contenders)
	responses := make([]*httptest.ResponseRecorder, contenders)
	for i := range responses {
		responses[i] = httptest.NewRecorder()
		key := "alice-key"
		if i%2 != 0 {
			key = "bob-key"
		}
		r := authTestRequest(key)
		// Parsing a valid, zero-padded Rx widens the original check/publish race
		// without sleeps or a production-only test hook.
		r.Header.Set(protocol.CommonHeaderCCRX, strings.Repeat("0", 1<<18)+"1")
		go func(w *httptest.ResponseRecorder, r *http.Request) {
			defer done.Done()
			ready.Done()
			<-start
			s.ServeHTTP(w, r)
		}(responses[i], r)
	}
	ready.Wait()
	close(start)
	done.Wait()
	for _, response := range responses {
		if response.Code != protocol.StatusAuthOK {
			t.Fatalf("status = %d", response.Code)
		}
	}
	calls := conn.congestionCalls.Load()
	// Each successful setup launches a receiver. Wait for every observed setup's
	// receiver before asserting, rather than sampling possibly unscheduled goroutines.
	for i := int32(0); i < calls; i++ {
		authTestReceive(t, conn.receiveCalls)
	}
	if calls != 1 {
		t.Fatalf("congestion setups / UDP receive loops = %d, want 1", calls)
	}
	winner := s.authUser // All handlers have joined; the identity is now immutable.
	if winner != "alice" && winner != "bob" {
		t.Fatalf("winner = %q", winner)
	}
	for _, key := range []string{"alice-key", "bob-key", "invalid"} {
		response := httptest.NewRecorder()
		s.ServeHTTP(response, authTestRequest(key))
		if response.Code != protocol.StatusAuthOK {
			t.Fatalf("repeat status = %d", response.Code)
		}
		if s.authUser != winner {
			t.Fatalf("identity changed from %q to %q", winner, s.authUser)
		}
	}
	if conn.congestionCalls.Load() != 1 {
		t.Fatal("repeated authentication repeated setup")
	}
}

type authTestHandler struct {
	ServerHandler
	users chan string
}

func (h *authTestHandler) NewConnection(ctx context.Context, _ net.Conn, _ M.Metadata) error {
	user, _ := auth.UserFromContext[string](ctx)
	h.users <- user
	return nil
}

type authTestStream struct {
	quic.Stream
	reader *bytes.Reader
	closed chan struct{}
}

func (s *authTestStream) Read(p []byte) (int, error)      { return s.reader.Read(p) }
func (s *authTestStream) CancelRead(quic.StreamErrorCode) {}
func (s *authTestStream) Close() error                    { close(s.closed); return nil }

func TestAuthStreamDuringSetup(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	conn := &authTestConn{receiveCalls: make(chan struct{}, 1), setup: func() { close(entered); <-release }}
	s := authTestSession(conn)
	handler := &authTestHandler{users: make(chan string, 1)}
	s.handler = handler
	// Pre-authentication streams must still be left to HTTP/3 (no waiting).
	if hijacked, err := s.handleStream0(protocol.FrameTypeTCPRequest, 0, nil, nil); hijacked || err != nil {
		t.Fatalf("pre-auth stream = %v, %v", hijacked, err)
	}
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.ServeHTTP(response, authTestRequest("alice-key")); close(done) }()
	authTestReceive(t, entered)
	defer func() { close(release); authTestReceive(t, done); authTestReceive(t, conn.receiveCalls) }()
	// The winning request is still in setup, but publication is complete.
	// A competing valid user must neither change the identity nor repeat setup.
	repeatDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { w := httptest.NewRecorder(); s.ServeHTTP(w, authTestRequest("bob-key")); repeatDone <- w }()
	if w := authTestReceive(t, repeatDone); w.Code != protocol.StatusAuthOK {
		t.Fatalf("repeat status = %d", w.Code)
	}
	request := protocol.WriteTCPRequest("example.com:443", nil)
	defer request.Release()
	reader := bytes.NewReader(request.Bytes())
	if _, err := quicvarint.Read(reader); err != nil {
		t.Fatal(err)
	}
	stream := &authTestStream{reader: reader, closed: make(chan struct{})}
	if hijacked, err := s.handleStream0(protocol.FrameTypeTCPRequest, 0, stream, nil); !hijacked || err != nil {
		t.Fatalf("published stream = %v, %v", hijacked, err)
	}
	if user := authTestReceive(t, handler.users); user != "alice" {
		t.Fatalf("stream user = %q, want alice", user)
	}
	authTestReceive(t, stream.closed)
}

func TestAuthMasquerade(t *testing.T) {
	s := authTestSession(&authTestConn{})
	for _, r := range []*http.Request{
		authTestRequest("invalid"),
		httptest.NewRequest(http.MethodGet, "https://hysteria/auth", nil),
		httptest.NewRequest(http.MethodPost, "https://example.com/auth", nil),
		httptest.NewRequest(http.MethodPost, "https://hysteria/other", nil),
	} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusTeapot {
			t.Fatalf("masquerade status = %d", w.Code)
		}
	}
	if s.authenticated {
		t.Fatal("masqueraded request authenticated")
	}
}
