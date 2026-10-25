package hysteria

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	M "github.com/sagernet/sing/common/metadata"
)

const handshakeTestBudget = 150 * time.Millisecond

// Use full duplex streams with real blocking I/O and deadlines. The QUIC
// transport stays active until explicitly closed, independently of stream I/O.
type handshakeStream struct {
	quic.Stream
	net.Conn
	mu           sync.Mutex
	deadline     time.Time
	writeStarted chan struct{}
	writeOnce    sync.Once
}

func (s *handshakeStream) Read(p []byte) (int, error) { return s.Conn.Read(p) }
func (s *handshakeStream) Write(p []byte) (int, error) {
	if s.writeStarted != nil {
		s.writeOnce.Do(func() { close(s.writeStarted) })
	}
	return s.Conn.Write(p)
}
func (s *handshakeStream) Close() error { return s.Conn.Close() }
func (s *handshakeStream) SetReadDeadline(deadline time.Time) error {
	return s.Conn.SetReadDeadline(deadline)
}
func (s *handshakeStream) SetWriteDeadline(deadline time.Time) error {
	return s.Conn.SetWriteDeadline(deadline)
}
func (s *handshakeStream) SetDeadline(deadline time.Time) error {
	s.mu.Lock()
	s.deadline = deadline
	s.mu.Unlock()
	return s.Conn.SetDeadline(deadline)
}

type handshakeQUIC struct {
	quic.Connection
	ctx      context.Context
	cancel   context.CancelFunc
	stream   *handshakeStream
	peer     net.Conn
	incoming chan quic.Stream
}

func handshakePair() (*handshakeQUIC, net.Conn) {
	local, peer := net.Pipe()
	// Bound the scripted peer as well, including successful-handshake setup.
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	q := &handshakeQUIC{ctx: ctx, cancel: cancel, stream: &handshakeStream{Conn: local}, peer: peer, incoming: make(chan quic.Stream, 1)}
	q.incoming <- q.stream
	return q, peer
}
func (q *handshakeQUIC) Context() context.Context { return q.ctx }
func (q *handshakeQUIC) CloseWithError(quic.ApplicationErrorCode, string) error {
	q.cancel()
	q.stream.Close()
	q.peer.Close()
	return nil
}
func (q *handshakeQUIC) AcceptStream(ctx context.Context) (quic.Stream, error) {
	select {
	case stream := <-q.incoming:
		return stream, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-q.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (q *handshakeQUIC) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return q.stream, nil
}
func (q *handshakeQUIC) SetCongestionControl(congestion.CongestionControl) {}
func (q *handshakeQUIC) ConnectionState() quic.ConnectionState             { return quic.ConnectionState{} }

func handshakeWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake or request remained blocked")
	}
}

func handshakeServer(t *testing.T, timeout time.Duration) (*handshakeQUIC, net.Conn, <-chan struct{}) {
	t.Helper()
	q, peer := handshakePair()
	session := &serverSession[string]{Service: &Service[string]{logger: new(authTestLogger),
		userMap: map[string]string{"password": "user"}, sendBPS: MinSpeedBPS, receiveBPS: MinSpeedBPS, udpDisabled: true},
		ctx: context.Background(), quicConn: q, connDone: make(chan struct{})}
	done := make(chan struct{})
	go func() { defer close(done); session.handleConnectionTimeout(timeout) }()
	t.Cleanup(func() { q.CloseWithError(0, ""); handshakeWait(t, done) })
	return q, peer, done
}

func TestHandshakeDeadlineServerPartialHello(t *testing.T) {
	q, peer, done := handshakeServer(t, handshakeTestBudget)
	var hello bytes.Buffer
	if err := WriteClientHello(&hello, ClientHello{SendBPS: MinSpeedBPS, RecvBPS: MinSpeedBPS, Auth: "password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write(hello.Bytes()[:hello.Len()/2]); err != nil {
		t.Fatal(err)
	}
	handshakeWait(t, done)
	handshakeWait(t, q.Context().Done())
}

func TestHandshakeDeadlineServerConnectionClose(t *testing.T) {
	q, _, done := handshakeServer(t, ProtocolTimeout)
	q.CloseWithError(0, "")
	handshakeWait(t, done)
}

func TestHandshakeDeadlineServerAccept(t *testing.T) {
	q, peer := handshakePair()
	<-q.incoming // No stream is opened during the handshake.
	session := &serverSession[string]{Service: &Service[string]{logger: new(authTestLogger)},
		ctx: context.Background(), quicConn: q, connDone: make(chan struct{})}
	defer peer.Close()
	defer q.CloseWithError(0, "")
	done := make(chan struct{})
	go func() { defer close(done); session.handleConnectionTimeout(handshakeTestBudget) }()
	handshakeWait(t, done)
}

type handshakeClientTLS struct {
	connSyncTLSBase
	connSyncQUICBase
	serve func(*handshakeQUIC, net.Conn)
}

func (f *handshakeClientTLS) Dial(context.Context, net.PacketConn, net.Addr, *quic.Config) (quic.Connection, error) {
	q, peer := handshakePair()
	f.serve(q, peer)
	return q, nil
}

func handshakeClient(t *testing.T, serve func(*handshakeQUIC, net.Conn)) *Client {
	t.Helper()
	client := &Client{ctx: context.Background(), dialer: new(connSyncDialer),
		tlsConfig: &handshakeClientTLS{serve: serve}, sendBPS: MinSpeedBPS, receiveBPS: MinSpeedBPS, udpDisabled: true}
	t.Cleanup(func() { client.CloseWithError(net.ErrClosed) })
	return client
}

// Each connection sends half a ServerHello, leaving its transport alive.
func handshakeStallingClient(t *testing.T) (*Client, <-chan struct{}) {
	t.Helper()
	entered := make(chan struct{}, 8)
	client := handshakeClient(t, func(q *handshakeQUIC, peer net.Conn) {
		t.Cleanup(func() { q.CloseWithError(0, "") })
		go func() {
			if _, err := ReadClientHello(peer); err != nil {
				return
			}
			var hello bytes.Buffer
			if WriteServerHello(&hello, ServerHello{OK: true, RecvBPS: MinSpeedBPS}) != nil {
				return
			}
			if _, err := peer.Write(hello.Bytes()[:hello.Len()/2]); err != nil {
				return
			}
			entered <- struct{}{}
		}()
	})
	return client, entered
}

func TestHandshakeDeadlineClientPartialHello(t *testing.T) {
	client, entered := handshakeStallingClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTestBudget)
	defer cancel()
	first := make(chan struct{})
	go func() {
		defer close(first)
		if _, err := client.DialConn(ctx, M.Socksaddr{}); err == nil {
			t.Error("partial ServerHello succeeded")
		}
	}()
	handshakeWait(t, entered)
	second := make(chan struct{})
	go func() {
		defer close(second)
		ctx, cancel := context.WithTimeout(context.Background(), 2*handshakeTestBudget)
		defer cancel()
		if _, err := client.DialConn(ctx, M.Socksaddr{}); err == nil {
			t.Error("second request succeeded")
		}
	}()
	handshakeWait(t, second)
	handshakeWait(t, first)
}

func TestHandshakeDeadlineClientCancellation(t *testing.T) {
	client, entered := handshakeStallingClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan struct{})
	go func() {
		defer close(first)
		if _, err := client.offer(ctx); err == nil {
			t.Error("canceled handshake succeeded")
		}
	}()
	handshakeWait(t, entered)
	cancel()
	handshakeWait(t, first)
	unlocked := make(chan struct{})
	go func() { client.connAccess.Lock(); client.connAccess.Unlock(); close(unlocked) }()
	handshakeWait(t, unlocked)
}

func TestHandshakeDeadlineClientWriteCancellation(t *testing.T) {
	entered := make(chan struct{})
	client := handshakeClient(t, func(q *handshakeQUIC, _ net.Conn) {
		t.Cleanup(func() { q.CloseWithError(0, "") })
		q.stream.writeStarted = entered // The peer never reads, so WriteClientHello blocks.
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := client.offer(ctx); err == nil {
			t.Error("canceled write succeeded")
		}
	}()
	handshakeWait(t, entered)
	cancel()
	handshakeWait(t, done)
}

func TestHandshakeDeadlineServerWrite(t *testing.T) {
	_, peer, done := handshakeServer(t, handshakeTestBudget)
	if err := WriteClientHello(peer, ClientHello{SendBPS: MinSpeedBPS, RecvBPS: MinSpeedBPS, Auth: "password"}); err != nil {
		t.Fatal(err)
	}
	// The peer never reads the response.
	handshakeWait(t, done)
}

func TestHandshakeDeadlineServerSuccess(t *testing.T) {
	q, peer, _ := handshakeServer(t, handshakeTestBudget)
	if err := WriteClientHello(peer, ClientHello{SendBPS: MinSpeedBPS, RecvBPS: MinSpeedBPS, Auth: "password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadServerHello(peer); err != nil {
		t.Fatal(err)
	}
	<-time.After(2 * handshakeTestBudget)
	select {
	case <-q.ctx.Done():
		t.Fatal("successful connection closed at handshake deadline")
	default:
	}
	q.stream.mu.Lock()
	deadline := q.stream.deadline
	q.stream.mu.Unlock()
	if !deadline.IsZero() {
		t.Fatal("temporary stream deadline was not cleared")
	}
	// Exercise the established stream after the original deadline.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := q.stream.Write([]byte{42})
		if err != nil {
			t.Error(err)
		}
	}()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1)
	if _, err := io.ReadFull(peer, b); err != nil || b[0] != 42 {
		t.Fatalf("established stream = %v, %v", b, err)
	}
	handshakeWait(t, done)
}

func TestHandshakeDeadlineClientSuccess(t *testing.T) {
	serverDone := make(chan struct{})
	client := handshakeClient(t, func(q *handshakeQUIC, peer net.Conn) {
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
	requestCtx, cancel := context.WithTimeout(context.Background(), handshakeTestBudget)
	defer cancel()
	conn, err := client.offer(requestCtx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	<-time.After(2 * handshakeTestBudget)
	stream, err := conn.quicConn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(time.Second))
	if _, err = stream.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err = io.ReadFull(stream, b); err != nil || b[0] != 42 {
		t.Fatalf("echo = %v, %v", b, err)
	}
	handshakeWait(t, serverDone)
}
