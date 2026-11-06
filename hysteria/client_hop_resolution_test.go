package hysteria

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	M "github.com/sagernet/sing/common/metadata"
)

// hopResolutionServer is a name only the test dialer can resolve, like a
// name that only the host's DNS policy (sing-box router) knows. The system
// resolver never answers for the reserved .invalid TLD.
const hopResolutionServer = "hop-resolution.invalid"

// hopResolutionDialer resolves every destination to resolved, as the host
// dialer does, and records what the client asked for.
type hopResolutionDialer struct {
	hopFinalizeNetworkDialer
	resolved M.Socksaddr
	dialed   []M.Socksaddr
	listened []M.Socksaddr
}

func (d *hopResolutionDialer) DialContext(ctx context.Context, network string, addr M.Socksaddr) (net.Conn, error) {
	d.dialed = append(d.dialed, addr)
	return d.hopFinalizeNetworkDialer.DialContext(ctx, network, d.resolved)
}

func (d *hopResolutionDialer) ListenPacket(ctx context.Context, addr M.Socksaddr) (net.PacketConn, error) {
	d.listened = append(d.listened, addr)
	return d.hopFinalizeNetworkDialer.ListenPacket(ctx, addr)
}

// Keep real QUIC I/O, but retain its default congestion controller. Replacing
// the controller races with ACK processing in the pinned quic-go; this test
// exercises address resolution and resource ownership, not congestion control.
type hopResolutionTLS struct {
	hopFinalizeNetworkTLS
	connSyncQUICBase
}

func (c hopResolutionTLS) Dial(ctx context.Context, packet net.PacketConn, addr net.Addr, config *quic.Config) (quic.Connection, error) {
	conn, err := quic.Dial(ctx, packet, addr, c.config, config)
	if err != nil {
		return nil, err
	}
	return hopResolutionQUIC{conn}, nil
}

type hopResolutionQUIC struct{ quic.Connection }

func (hopResolutionQUIC) SetCongestionControl(congestion.CongestionControl) {}

func TestHopResolutionUsesDialerAddress(t *testing.T) {
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
		NextProtos:   []string{DefaultALPN},
	}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	peers := make(chan quic.Connection, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		peer, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		// Listener.Close in the pinned quic-go can leave accepted peers alive.
		// Own the peer explicitly, including when setup fails before it is read.
		peerDone := make(chan struct{})
		go func() {
			defer close(peerDone)
			select {
			case <-ctx.Done():
				_ = peer.CloseWithError(0, "test context ended")
			case <-peer.Context().Done():
			}
		}()
		defer func() {
			_ = peer.CloseWithError(0, "test server shutdown")
			<-peerDone
		}()
		peers <- peer
		stream, err := peer.AcceptStream(ctx)
		if err == nil {
			_, err = ReadClientHello(stream)
		}
		if err == nil {
			_ = WriteServerHello(stream, ServerHello{OK: true, RecvBPS: 1000000})
		}
		<-peer.Context().Done()
	}()
	resolved := M.ParseSocksaddr(listener.Addr().String())
	d := &hopResolutionDialer{resolved: resolved}
	c := &Client{
		ctx: ctx, dialer: d, serverAddr: M.ParseSocksaddrHostPort(hopResolutionServer, resolved.Port),
		tlsConfig:  hopResolutionTLS{hopFinalizeNetworkTLS: hopFinalizeNetworkTLS{config: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{DefaultALPN}}}},
		quicConfig: &quic.Config{}, hopPorts: strconv.Itoa(int(resolved.Port)), hopInterval: 5 * time.Second,
		udpDisabled: true, sendBPS: 1000000, receiveBPS: 1000000,
	}
	defer func() {
		// Use a fresh deadline: the handshake context may already have expired.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cancel()
		clientDone := make(chan struct{})
		go func() {
			defer close(clientDone)
			_ = c.CloseWithError(net.ErrClosed)
		}()
		listenerDone := make(chan struct{})
		go func() {
			defer close(listenerDone)
			_ = listener.Close()
		}()
		clientClosed := hopResolutionWait(t, cleanupCtx, "client close", clientDone)
		hopResolutionWait(t, cleanupCtx, "listener close", listenerDone)
		hopResolutionWait(t, cleanupCtx, "server and accepted peer", serverDone)
		if !clientClosed {
			return
		}
		if d.rawConn != nil {
			hopResolutionWait(t, cleanupCtx, "raw socket close", d.rawConn.closed)
			if n := d.rawConn.closes.Load(); n != 1 {
				t.Errorf("raw socket closes = %d, want 1", n)
			}
		}
		for i, packet := range d.packets {
			hopResolutionWait(t, cleanupCtx, "hop socket "+strconv.Itoa(i)+" close", packet.closed)
			if n := packet.closes.Load(); n != 1 {
				t.Errorf("hop socket %d closes = %d, want 1", i, n)
			}
		}
	}()
	if _, err := c.offer(ctx); err != nil {
		t.Fatal(err)
	}
	if len(d.dialed) != 1 || d.dialed[0] != c.serverAddr {
		t.Fatalf("dialed = %v, want [%v]", d.dialed, c.serverAddr)
	}
	// The hop socket is opened for the resolved address, not the name.
	if len(d.listened) != 1 || d.listened[0] != resolved {
		t.Fatalf("hop ListenPacket destinations = %v, want [%v]", d.listened, resolved)
	}
	select {
	case peer := <-peers:
		// The handshake reached the resolved IP and hop port from the hop socket.
		if got, want := peer.RemoteAddr().String(), d.packets[0].LocalAddr().String(); got != want {
			t.Fatalf("server saw client %s, want hop socket %s", got, want)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

// Report the specific owner that did not exit without skipping other checks.
func hopResolutionWait(t *testing.T, ctx context.Context, name string, done <-chan struct{}) bool {
	t.Helper()
	select {
	case <-done:
		return true
	default:
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Errorf("%s did not finish: %v", name, ctx.Err())
		return false
	}
	return true
}

// unresolvedRaw models a dialer that could not resolve the server, for
// example a detour through a proxy that resolves names remotely.
type unresolvedRaw struct{ *connSyncRaw }

func (r *unresolvedRaw) RemoteAddr() net.Addr { return &net.UDPAddr{Port: 443} }

type unresolvedDialer struct{ hopFinalizeDialer }

func (d *unresolvedDialer) DialContext(ctx context.Context, network string, addr M.Socksaddr) (net.Conn, error) {
	conn, err := d.hopFinalizeDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &unresolvedRaw{conn.(*connSyncRaw)}, nil
}

func TestHopResolutionRequiresResolvedAddress(t *testing.T) {
	d := new(unresolvedDialer)
	c := &Client{
		ctx: context.Background(), dialer: d, tlsConfig: new(connSyncTLS),
		serverAddr: M.ParseSocksaddrHostPort(hopResolutionServer, 443), hopPorts: "443", hopInterval: 5 * time.Second,
		sendBPS: 1000000, receiveBPS: 1000000, udpDisabled: true,
	}
	conn, err := c.offerNew(context.Background())
	if err == nil || conn != nil {
		t.Fatalf("offerNew = (%v, %v), want failure", conn, err)
	}
	if !strings.Contains(err.Error(), "port hopping needs a resolved server address") {
		t.Fatalf("offerNew error = %v", err)
	}
	if len(d.packets) != 0 {
		t.Fatalf("hop sockets opened = %d, want 0", len(d.packets))
	}
	hopFinalizeWait(t, d.raw[0].closed)
}
