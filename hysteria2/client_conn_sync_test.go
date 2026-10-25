package hysteria2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

// Use the TLS adapter seam to exercise real offer/offerNew publication without
// a network server or timing-dependent handshakes. Unexpected QUIC calls panic.
type (
	connSyncTLSBase  = aTLS.Config
	connSyncQUICBase = qtls.Config
	connSyncTLS      struct {
		connSyncTLSBase
		connSyncQUICBase
		mu      sync.Mutex
		conns   []*connSyncQUIC
		entered chan struct{}
		release chan struct{}
	}
)

func (f *connSyncTLS) makeConn() *connSyncQUIC {
	ctx, cancel := context.WithCancel(context.Background())
	q := &connSyncQUIC{ctx: ctx, cancel: cancel, receiverDone: make(chan struct{})}
	f.mu.Lock()
	f.conns = append(f.conns, q)
	f.mu.Unlock()
	if f.entered != nil {
		f.entered <- struct{}{}
		<-f.release
	}
	return q
}

func (f *connSyncTLS) Dial(context.Context, net.PacketConn, net.Addr, *quic.Config) (quic.Connection, error) {
	return f.makeConn(), nil
}

func (f *connSyncTLS) CreateTransport(_ net.PacketConn, ptr *quic.EarlyConnection, _ M.Socksaddr, _ *quic.Config) http.RoundTripper {
	return connSyncRoundTrip(func(*http.Request) (*http.Response, error) {
		*ptr = f.makeConn()
		header := make(http.Header)
		protocol.AuthResponseToHeader(header, protocol.AuthResponse{UDPEnabled: true, Rx: 1000000})
		return &http.Response{StatusCode: protocol.StatusAuthOK, Header: header, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	})
}

type connSyncRoundTrip func(*http.Request) (*http.Response, error)

func (f connSyncRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type connSyncQUIC struct {
	quic.EarlyConnection
	ctx          context.Context
	cancel       context.CancelFunc
	closes       atomic.Int32
	session      atomic.Uint32
	receiverDone chan struct{}
}

func (q *connSyncQUIC) Context() context.Context { return q.ctx }
func (q *connSyncQUIC) CloseWithError(quic.ApplicationErrorCode, string) error {
	q.closes.Add(1)
	q.cancel()
	return nil
}
func (q *connSyncQUIC) SetCongestionControl(congestion.CongestionControl) {}
func (q *connSyncQUIC) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{SupportsDatagrams: true, ExportKeyingMaterial: func(string, []byte, int) ([]byte, error) { return make([]byte, 32), nil }}
}

func (q *connSyncQUIC) ReceiveDatagram(context.Context) ([]byte, error) {
	defer close(q.receiverDone)
	<-q.ctx.Done()
	return nil, net.ErrClosed
}

func (q *connSyncQUIC) OpenStream() (quic.Stream, error) {
	var response []byte
	return &connSyncStream{Reader: bytes.NewReader(response)}, nil
}

func (q *connSyncQUIC) OpenStreamSync(context.Context) (quic.Stream, error) {
	return q.OpenStream()
}

func (q *connSyncQUIC) OpenUniStream() (quic.SendStream, error) {
	return &connSyncStream{Reader: bytes.NewReader(nil)}, nil
}

type connSyncStream struct {
	quic.Stream
	*bytes.Reader
}

func (s *connSyncStream) Read(p []byte) (int, error)      { return s.Reader.Read(p) }
func (s *connSyncStream) Write(p []byte) (int, error)     { return len(p), nil }
func (s *connSyncStream) Close() error                    { return nil }
func (s *connSyncStream) CancelRead(quic.StreamErrorCode) {}

type connSyncRaw struct {
	net.Conn
	closes atomic.Int32
	closed chan struct{}
}

func (r *connSyncRaw) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}

func (r *connSyncRaw) Close() error {
	if r.closes.Add(1) == 1 {
		close(r.closed)
	}
	return nil
}

type connSyncDialer struct {
	N.Dialer
	mu  sync.Mutex
	raw []*connSyncRaw
}

func (d *connSyncDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	r := &connSyncRaw{closed: make(chan struct{})}
	d.mu.Lock()
	d.raw = append(d.raw, r)
	d.mu.Unlock()
	return r, nil
}

func connSyncClient(t *testing.T, f *connSyncTLS) (*Client, *connSyncDialer) {
	t.Helper()
	d := new(connSyncDialer)
	c := &Client{ctx: context.Background(), dialer: d, tlsConfig: f, sendBPS: 1000000, receiveBPS: 1000000}
	return c, d
}

func connSyncCheckClosed(t *testing.T, f *connSyncTLS, d *connSyncDialer) {
	t.Helper()
	f.mu.Lock()
	conns := append([]*connSyncQUIC(nil), f.conns...)
	f.mu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, r := range d.raw {
		select {
		case <-r.closed:
		case <-time.After(5 * time.Second):
			t.Fatal("raw connection leaked")
		}
		if r.closes.Load() != 1 {
			t.Errorf("connection %d raw closes = %d, want 1", i, r.closes.Load())
		}
	}
	for i, q := range conns {
		select {
		case <-q.receiverDone:
		case <-time.After(5 * time.Second):
			t.Fatal("datagram receiver did not exit")
		}
		if q.closes.Load() != 1 {
			t.Errorf("connection %d QUIC closes = %d, want 1", i, q.closes.Load())
		}
	}
}

func TestClientConnectionConcurrencyRequests(t *testing.T) {
	f := new(connSyncTLS)
	c, d := connSyncClient(t, f)
	defer c.CloseWithError(net.ErrClosed)
	for round := 0; round < 8; round++ {
		initial, err := c.offer(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var workers sync.WaitGroup
		for worker := 0; worker < 4; worker++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				for i := 0; i < 8; i++ {
					var conn io.Closer
					var err error
					if i%2 == 0 {
						conn, err = c.DialConn(context.Background(), M.Socksaddr{})
					} else {
						conn, err = c.ListenPacket(context.Background())
					}
					if err != nil {
						t.Error(err)
						return
					}
					if err = conn.Close(); err != nil {
						t.Error(err)
					}
				}
			}()
		}
		workers.Add(2)
		go func() {
			defer workers.Done()
			<-start
			for i := 0; i < 8; i++ {
				_ = c.CloseWithError(net.ErrClosed)
			}
		}()
		go func() { defer workers.Done(); <-start; initial.quicConn.(*connSyncQUIC).cancel() }()
		close(start)
		workers.Wait()
		_ = c.CloseWithError(net.ErrClosed)
		reconnected, err := c.offer(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if reconnected == initial || !reconnected.active() || reconnected.connDone == nil || reconnected.udpConnMap == nil {
			t.Fatal("reconnect did not publish an initialized, active connection")
		}
	}
	_ = c.CloseWithError(net.ErrClosed)
	connSyncCheckClosed(t, f, d)
}

func TestClientConnectionConcurrencyCloseDuringCreation(t *testing.T) {
	f := &connSyncTLS{entered: make(chan struct{}), release: make(chan struct{})}
	c, d := connSyncClient(t, f)
	offered := make(chan error, 1)
	go func() { _, err := c.offer(context.Background()); offered <- err }()
	<-f.entered
	closed := make(chan struct{})
	closeErr := errors.New("network changed during creation")
	go func() { _ = c.CloseWithError(closeErr); close(closed) }()
	// Wait until CloseWithError is blocked on the publication lock. A returned
	// close is a regression: it missed the connection still being initialized.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-closed:
			close(f.release)
			<-offered
			_ = c.CloseWithError(net.ErrClosed)
			t.Fatal("CloseWithError returned before in-flight creation published")
		case <-deadline:
			t.Fatal("CloseWithError did not reach publication lock")
		default:
		}
		stack := make([]byte, 1<<16)
		n := runtime.Stack(stack, true)
		waiting := false
		for _, goroutine := range strings.Split(string(stack[:n]), "\n\n") {
			if strings.Contains(goroutine, "(*Client).CloseWithError") && strings.Contains(goroutine, "sync.(*RWMutex).Lock") {
				waiting = true
				break
			}
		}
		if waiting {
			break
		}
		runtime.Gosched()
	}
	close(f.release)
	if err := <-offered; err != nil {
		t.Fatal(err)
	}
	<-closed
	c.connAccess.RLock()
	conn := c.conn
	c.connAccess.RUnlock()
	if conn == nil || conn.active() || conn.connErr != closeErr {
		t.Fatal("in-flight connection was not closed with requested error")
	}
	connSyncCheckClosed(t, f, d)
	// A network-change close must permit a later connection.
	f.entered = nil
	reconnected, err := c.offer(context.Background())
	if err != nil || reconnected == conn || !reconnected.active() {
		t.Fatalf("reconnect = (%v, %v)", reconnected, err)
	}
	_ = c.CloseWithError(net.ErrClosed)
	connSyncCheckClosed(t, f, d)
}
