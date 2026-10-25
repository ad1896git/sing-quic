package hysteria2

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
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	M "github.com/sagernet/sing/common/metadata"
)

// Use the TLS adapter seam with real hop workers. Cancelling the peer's
// QUIC context models the notification delivered by a server disconnect.
type hopFinalizePacket struct {
	net.PacketConn
	closes atomic.Int32
	closed chan struct{}
}

func (p *hopFinalizePacket) Close() error {
	n := p.closes.Add(1)
	err := p.PacketConn.Close()
	if n == 1 {
		close(p.closed)
	}
	return err
}

// No sockets are needed: the hop receive worker blocks until Close.
type hopFinalizeMemoryPacket struct {
	net.PacketConn
	done chan struct{}
	once sync.Once
}

func (p *hopFinalizeMemoryPacket) ReadFrom([]byte) (int, net.Addr, error) {
	<-p.done
	return 0, nil, net.ErrClosed
}
func (p *hopFinalizeMemoryPacket) Close() error { p.once.Do(func() { close(p.done) }); return nil }

type hopFinalizeDialer struct {
	connSyncDialer
	packets []*hopFinalizePacket
}

func (d *hopFinalizeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	p := &hopFinalizeMemoryPacket{done: make(chan struct{})}
	tracked := &hopFinalizePacket{PacketConn: p, closed: make(chan struct{})}
	d.packets = append(d.packets, tracked)
	return tracked, nil
}

func hopFinalizeWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("hop resources were not finalised")
	}
}

func hopFinalizeClient(t *testing.T, disabled bool) (*Client, *hopFinalizeDialer, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	d := new(hopFinalizeDialer)
	c := &Client{
		ctx: ctx, dialer: d, tlsConfig: new(connSyncTLS),
		serverAddr: M.ParseSocksaddr("127.0.0.1:443"), hopPorts: "443", hopInterval: 5 * time.Second,
		sendBPS: 1000000, receiveBPS: 1000000, udpDisabled: disabled,
	}
	t.Cleanup(func() { cancel(); _ = c.CloseWithError(net.ErrClosed) })
	return c, d, cancel
}

func hopFinalizeCheck(t *testing.T, conn *clientQUICConnection, d *hopFinalizeDialer, index int) {
	t.Helper()
	hopFinalizeWait(t, d.packets[index].closed)
	hopFinalizeWait(t, d.raw[index].closed)
	// Synchronise with completion of sync.Once, then exercise repeated cleanup.
	conn.closeWithError(net.ErrClosed)
	conn.closeWithError(net.ErrClosed)
	if n := d.packets[index].closes.Load(); n != 1 {
		t.Errorf("hop socket closes = %d, want 1", n)
	}
	if n := d.raw[index].closes.Load(); n != 1 {
		t.Errorf("raw closes = %d, want 1", n)
	}
	if n := conn.quicConn.(*connSyncQUIC).closes.Load(); n != 1 {
		t.Errorf("QUIC closes = %d, want 1", n)
	}
}

func TestHopFinalizePeerClose(t *testing.T) {
	for _, disabled := range []bool{true, false} {
		t.Run("UDPDisabled="+strconv.FormatBool(disabled), func(t *testing.T) {
			c, d, _ := hopFinalizeClient(t, disabled)
			conn, err := c.offer(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			conn.quicConn.(*connSyncQUIC).cancel()
			hopFinalizeCheck(t, conn, d, 0)
		})
	}
}

func TestHopFinalizeApplicationCancel(t *testing.T) {
	for _, disabled := range []bool{true, false} {
		t.Run("UDPDisabled="+strconv.FormatBool(disabled), func(t *testing.T) {
			c, d, cancel := hopFinalizeClient(t, disabled)
			conn, err := c.offer(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			hopFinalizeCheck(t, conn, d, 0)
		})
	}
}

func TestHopFinalizeReconnect(t *testing.T) {
	c, d, _ := hopFinalizeClient(t, true)
	var previous *clientQUICConnection
	for i := 0; i < 5; i++ {
		conn, err := c.offer(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if conn == previous {
			t.Fatal("dead connection was reused")
		}
		if previous != nil {
			hopFinalizeCheck(t, previous, d, i-1)
		}
		previous = conn
		conn.quicConn.(*connSyncQUIC).cancel()
	}
	hopFinalizeCheck(t, previous, d, 4)
}

// Deliberately omit the watcher to check offer's fallback independently of
// goroutine scheduling.
func TestHopFinalizeStaleBeforeReplacement(t *testing.T) {
	c, d, _ := hopFinalizeClient(t, true)
	q := new(connSyncTLS).makeConn()
	raw, err := d.DialContext(context.Background(), "udp", c.serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := d.ListenPacket(context.Background(), c.serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	old := &clientQUICConnection{quicConn: q, rawConn: raw, packetConn: packet, connDone: make(chan struct{})}
	c.conn = old
	q.cancel()
	replacement, err := c.offer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if replacement == old {
		t.Fatal("dead connection was reused")
	}
	hopFinalizeCheck(t, old, d, 0)
}

// Keep the QUIC interface dependency explicit in this fixture.
var _ quic.Connection = (*connSyncQUIC)(nil)

type hopFinalizeBody struct{ closes atomic.Int32 }

func (b *hopFinalizeBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *hopFinalizeBody) Close() error             { b.closes.Add(1); return nil }

type hopFinalizeAuthTLS struct {
	connSyncTLS
	body   *hopFinalizeBody
	status int
	err    error
}

func (f *hopFinalizeAuthTLS) CreateTransport(_ net.PacketConn, ptr *quic.EarlyConnection, _ M.Socksaddr, _ *quic.Config) http.RoundTripper {
	return connSyncRoundTrip(func(*http.Request) (*http.Response, error) {
		*ptr = f.makeConn()
		return &http.Response{StatusCode: f.status, Body: f.body}, f.err
	})
}

func TestHopFinalizeAuthFailureBody(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			c, d, _ := hopFinalizeClient(t, true)
			body := new(hopFinalizeBody)
			c.tlsConfig = &hopFinalizeAuthTLS{body: body, status: status}
			if conn, err := c.offer(context.Background()); err == nil || conn != nil {
				t.Fatalf("offer = (%v, %v), want authentication failure", conn, err)
			}
			if n := body.closes.Load(); n != 1 {
				t.Errorf("response body closes = %d, want 1", n)
			}
			hopFinalizeWait(t, d.packets[0].closed)
			hopFinalizeWait(t, d.raw[0].closed)
		})
	}
	t.Run("transport error with response", func(t *testing.T) {
		c, _, _ := hopFinalizeClient(t, true)
		body := new(hopFinalizeBody)
		want := errors.New("authentication transport failed")
		c.tlsConfig = &hopFinalizeAuthTLS{body: body, err: want}
		if _, err := c.offer(context.Background()); !errors.Is(err, want) {
			t.Fatalf("offer error = %v, want %v", err, want)
		}
		if n := body.closes.Load(); n != 1 {
			t.Errorf("response body closes = %d, want 1", n)
		}
	})
}

// Exercise the actual server close notification as well as the deterministic
// adapter tests above. This test requires loopback UDP sockets.
type hopFinalizeNetworkDialer struct {
	hopFinalizeDialer
	rawConn *connSyncRaw
}

func (d *hopFinalizeNetworkDialer) DialContext(ctx context.Context, network string, addr M.Socksaddr) (net.Conn, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, network, addr.String())
	if err != nil {
		return nil, err
	}
	d.rawConn = &connSyncRaw{Conn: raw, closed: make(chan struct{})}
	return &hopFinalizeNetworkRaw{connSyncRaw: d.rawConn}, nil
}

func (d *hopFinalizeNetworkDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	tracked := &hopFinalizePacket{PacketConn: packet, closed: make(chan struct{})}
	d.packets = append(d.packets, tracked)
	return tracked, nil
}

type hopFinalizeNetworkRaw struct{ *connSyncRaw }

func (r *hopFinalizeNetworkRaw) RemoteAddr() net.Addr { return r.Conn.RemoteAddr() }
func (r *hopFinalizeNetworkRaw) Close() error {
	_ = r.Conn.Close()
	return r.connSyncRaw.Close()
}

type hopFinalizeNetworkTLS struct {
	initTestTLSBase
	config *tls.Config
}

func (c hopFinalizeNetworkTLS) Config() (*tls.Config, error) { return c.config, nil }

func TestHopFinalizeServerClose(t *testing.T) {
	for _, disabled := range []bool{true, false} {
		t.Run("UDPDisabled="+strconv.FormatBool(disabled), func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
			der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}},
				NextProtos:   []string{"h3"},
			}, &quic.Config{EnableDatagrams: true})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			peers := make(chan quic.Connection, 1)
			serverErrors := make(chan error, 1)
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				peer, err := listener.Accept(ctx)
				if err != nil {
					serverErrors <- err
					return
				}
				peers <- peer
				server := &http3.Server{EnableDatagrams: true, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{UDPEnabled: true, Rx: 1000000})
					w.WriteHeader(protocol.StatusAuthOK)
				})}
				_ = server.ServeQUICConn(peer)
			}()
			defer func() { cancel(); _ = listener.Close(); hopFinalizeWait(t, serverDone) }()
			d := new(hopFinalizeNetworkDialer)
			addr := M.ParseSocksaddr(listener.Addr().String())
			c := &Client{
				ctx: ctx, dialer: d, serverAddr: addr,
				tlsConfig:  hopFinalizeNetworkTLS{config: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}},
				quicConfig: &quic.Config{EnableDatagrams: !disabled}, hopPorts: strconv.Itoa(int(addr.Port)), hopInterval: 5 * time.Second,
				udpDisabled: disabled, sendBPS: 1000000, receiveBPS: 1000000,
			}
			defer c.CloseWithError(net.ErrClosed)
			conn, err := c.offer(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var peer quic.Connection
			select {
			case peer = <-peers:
			case err := <-serverErrors:
				t.Fatal(err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if err := peer.CloseWithError(0, "test server shutdown"); err != nil {
				t.Fatal(err)
			}
			hopFinalizeWait(t, d.packets[0].closed)
			hopFinalizeWait(t, d.rawConn.closed)
			conn.closeWithError(net.ErrClosed)
			_ = c.CloseWithError(net.ErrClosed)
			if n := d.packets[0].closes.Load(); n != 1 {
				t.Errorf("hop socket closes = %d, want 1", n)
			}
			if n := d.rawConn.closes.Load(); n != 1 {
				t.Errorf("raw closes = %d, want 1", n)
			}
		})
	}
}
