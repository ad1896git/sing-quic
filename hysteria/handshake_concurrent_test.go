package hysteria

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
)

// Establish real QUIC before starting the application handshake budget. Both
// peers send keepalive packets while application stream I/O is stalled.
func handshakeKeepAlivePair(t *testing.T) (quic.Connection, quic.Connection) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	config := &quic.Config{KeepAlivePeriod: 20 * time.Millisecond, MaxIdleTimeout: 2 * time.Second}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}},
		NextProtos:   []string{DefaultALPN},
	}, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, // Ephemeral loopback certificate.
		NextProtos:         []string{DefaultALPN},
	}, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.CloseWithError(0, "") })
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.CloseWithError(0, "") })
	return client, server
}

type handshakeConnectedTLS struct {
	connSyncTLSBase
	connSyncQUICBase
	conn quic.Connection
}

func (f *handshakeConnectedTLS) Dial(context.Context, net.PacketConn, net.Addr, *quic.Config) (quic.Connection, error) {
	return f.conn, nil
}

func TestHandshakeDeadlineKeepAlivePeerStalls(t *testing.T) {
	local, peer := handshakeKeepAlivePair(t)
	client := handshakeClient(t, nil)
	client.tlsConfig = &handshakeConnectedTLS{conn: local}
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTestBudget)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := client.offer(ctx); err == nil {
			t.Error("peer without ServerHello succeeded")
		}
	}()
	handshakeWait(t, done)
	handshakeWait(t, local.Context().Done())
	handshakeWait(t, peer.Context().Done())
	var closeErr *quic.ApplicationError
	if !errors.As(context.Cause(peer.Context()), &closeErr) {
		t.Fatalf("peer closed without application close: %v", context.Cause(peer.Context()))
	}
}

func TestHandshakeDeadlineServerKeepAliveStalls(t *testing.T) {
	peer, local := handshakeKeepAlivePair(t)
	session := &serverSession[string]{
		Service: &Service[string]{logger: new(authTestLogger)},
		ctx:     context.Background(), quicConn: local, connDone: make(chan struct{}),
	}
	// Open a control stream but send no ClientHello. QUIC announces streams
	// only when data is sent, so the server remains in AcceptStream.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := peer.OpenStreamSync(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); session.handleConnectionTimeout(handshakeTestBudget) }()
	handshakeWait(t, done)
	handshakeWait(t, local.Context().Done())
	handshakeWait(t, peer.Context().Done())
	var closeErr *quic.ApplicationError
	if !errors.As(context.Cause(peer.Context()), &closeErr) || closeErr.ErrorCode != ErrorCodeProtocolError {
		t.Fatalf("peer close = %v, want protocol error", context.Cause(peer.Context()))
	}
}

func TestHandshakeDeadlineConcurrentOffers(t *testing.T) {
	for _, success := range []bool{false, true} {
		name := "timeout"
		if success {
			name = "success"
		}
		t.Run(name, func(t *testing.T) {
			const callers = 8
			release := make(chan struct{}, 1)
			defer close(release)
			entered := make(chan struct{}, callers)
			client := handshakeClient(t, func(q *handshakeQUIC, peer net.Conn) {
				serverDone := make(chan struct{})
				t.Cleanup(func() { q.CloseWithError(0, ""); handshakeWait(t, serverDone) })
				go func() {
					defer close(serverDone)
					if _, err := ReadClientHello(peer); err != nil {
						return
					}
					entered <- struct{}{}
					select {
					case <-release:
					case <-q.Context().Done():
						return
					}
					if err := WriteServerHello(peer, ServerHello{OK: true, RecvBPS: MinSpeedBPS}); err != nil {
						t.Error(err)
					}
				}()
			})
			ctx, cancel := context.WithTimeout(context.Background(), handshakeTestBudget)
			defer cancel()
			start := make(chan struct{})
			var ready, finished sync.WaitGroup
			ready.Add(callers)
			finished.Add(callers)
			conns := make([]*clientQUICConnection, callers)
			errs := make([]error, callers)
			for i := 0; i < callers; i++ {
				go func(i int) {
					defer finished.Done()
					ready.Done()
					<-start
					conns[i], errs[i] = client.offer(ctx)
				}(i)
			}
			done := make(chan struct{})
			go func() { finished.Wait(); close(done) }()
			allReady := make(chan struct{})
			go func() { ready.Wait(); close(allReady) }()
			handshakeWait(t, allReady)
			close(start)
			handshakeWait(t, entered)
			if success {
				// Let concurrent callers contend while the handshake is pending.
				<-time.After(20 * time.Millisecond)
				release <- struct{}{}
			}
			handshakeWait(t, done)
			for i := range conns {
				if success {
					if errs[i] != nil || conns[i] == nil || conns[i] != conns[0] {
						t.Fatalf("caller %d: connection %p, error %v; want %p", i, conns[i], errs[i], conns[0])
					}
				} else if errs[i] == nil {
					t.Fatalf("caller %d succeeded after stalled handshake", i)
				}
			}
		})
	}
}

func TestHandshakeDeadlineSuccessAfterBudget(t *testing.T) {
	serverDone := make(chan struct{})
	var transport *handshakeQUIC
	client := handshakeClient(t, func(q *handshakeQUIC, peer net.Conn) {
		transport = q
		t.Cleanup(func() { q.CloseWithError(0, ""); handshakeWait(t, serverDone) })
		go func() {
			defer close(serverDone)
			if _, err := ReadClientHello(peer); err != nil {
				t.Error(err)
				return
			}
			if err := WriteServerHello(peer, ServerHello{OK: true, RecvBPS: MinSpeedBPS}); err != nil {
				t.Error(err)
				return
			}
			b := make([]byte, 1)
			if _, err := io.ReadFull(peer, b); err != nil {
				t.Error(err)
				return
			}
			if _, err := peer.Write(b); err != nil {
				t.Error(err)
			}
		}()
	})
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTestBudget)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := client.offer(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		<-ctx.Done() // Wait past the original request/handshake budget.
		transport.stream.mu.Lock()
		deadline := transport.stream.deadline
		transport.stream.mu.Unlock()
		if !deadline.IsZero() {
			t.Error("temporary control stream deadline was not cleared")
			return
		}
		stream, err := conn.quicConn.OpenStreamSync(context.Background())
		if err != nil {
			t.Error(err)
			return
		}
		// Use the cleared stream deadline for the round trip; cleanup bounds
		// I/O if it stalls, so resetting the deadline cannot mask a regression.
		if _, err := stream.Write([]byte{42}); err != nil {
			t.Error(err)
			return
		}
		b := make([]byte, 1)
		if _, err := io.ReadFull(stream, b); err != nil || b[0] != 42 {
			t.Errorf("echo = %v, %v", b, err)
		}
	}()
	handshakeWait(t, done)
	handshakeWait(t, serverDone)
}
