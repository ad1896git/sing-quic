package hysteria

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type authTestLogger struct {
	logger.Logger
	mu   sync.Mutex
	text string
}

func (l *authTestLogger) Error(args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.text += fmt.Sprint(args...)
}

func (l *authTestLogger) Debug(args ...any) { l.Error(args...) }

type authTestHandler struct {
	ServerHandler
	called chan string
}

func (h *authTestHandler) NewConnection(ctx context.Context, conn net.Conn, _ M.Metadata) error {
	defer conn.Close()
	user, _ := auth.UserFromContext[string](ctx)
	h.called <- user
	return nil
}

func TestAuthFailurePasswords(t *testing.T) {
	const password = "correct-password"
	const wrongPassword = "wrong-password-secret-F01"
	for _, test := range []struct {
		name     string
		password string
		ok       bool
	}{
		{"wrong", wrongPassword, false},
		{"correct", password, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
			}
			certificate, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: privateKey}},
				NextProtos:   []string{DefaultALPN},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{
				InsecureSkipVerify: true, // Ephemeral loopback certificate.
				NextProtos:         []string{DefaultALPN},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseWithError(0, "")
			server, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			log := new(authTestLogger)
			handler := &authTestHandler{called: make(chan string, 1)}
			session := &serverSession[string]{
				Service: &Service[string]{
					logger: log, handler: handler,
					sendBPS: MinSpeedBPS, receiveBPS: MinSpeedBPS, udpDisabled: true,
				},
				ctx: ctx, quicConn: server, connDone: make(chan struct{}),
			}
			session.UpdateUsers([]string{"test-user"}, []string{password})
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				session.handleConnection()
			}()
			defer func() {
				server.CloseWithError(0, "")
				select {
				case <-finished:
				case <-ctx.Done():
					t.Error("server session did not finish")
				}
			}()
			control, err := client.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			control.SetDeadline(time.Now().Add(5 * time.Second))
			if err := WriteClientHello(control, ClientHello{
				Auth: test.password, SendBPS: MinSpeedBPS, RecvBPS: MinSpeedBPS,
			}); err != nil {
				t.Fatal(err)
			}
			hello, helloErr := ReadServerHello(control)
			if test.ok {
				if helloErr != nil {
					t.Fatal(helloErr)
				}
				if !hello.OK || hello.SendBPS != MinSpeedBPS || hello.RecvBPS != MinSpeedBPS {
					t.Fatalf("unexpected success response: %+v", hello)
				}
				stream, err := client.OpenStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				request := WriteClientRequest(ClientRequest{Host: "example.com", Port: 80}, nil)
				defer request.Release()
				if _, err := stream.Write(request.Bytes()); err != nil {
					t.Fatal(err)
				}
				select {
				case user := <-handler.called:
					if user != "test-user" {
						t.Fatalf("handler user = %q, want test-user", user)
					}
				case <-ctx.Done():
					t.Fatal("authenticated handler was not called")
				}
				return
			}
			// QUIC may deliver the connection close before the failure response.
			if helloErr == nil && (hello.OK || hello.Message != "Wrong password") {
				t.Fatalf("unexpected failure response: %+v", hello)
			}
			select {
			case <-client.Context().Done():
			case <-ctx.Done():
				t.Fatal("wrong-password client connection was not closed")
			}
			cause := context.Cause(client.Context())
			var closeErr *quic.ApplicationError
			if !errors.As(cause, &closeErr) || !closeErr.Remote || closeErr.ErrorCode != ErrorCodeAuthError || closeErr.ErrorMessage != "auth error" {
				t.Fatalf("unexpected client close error: %v", cause)
			}
			select {
			case <-finished:
			case <-ctx.Done():
				t.Fatal("wrong-password server session did not finish")
			}
			select {
			case <-handler.called:
				t.Fatal("handler called for wrong password")
			default:
			}
			if session.connErr == nil || session.connErr.Error() != "authentication failed" {
				t.Fatalf("unexpected authentication error: %v", session.connErr)
			}
			log.mu.Lock()
			defer log.mu.Unlock()
			if !strings.Contains(log.text, "authentication failed") {
				t.Fatalf("authentication failure was not logged: %q", log.text)
			}
			for _, secret := range []string{wrongPassword, password} {
				if strings.Contains(cause.Error(), secret) || strings.Contains(log.text, secret) {
					t.Fatal("password leaked in close reason or log")
				}
			}
		})
	}
}
