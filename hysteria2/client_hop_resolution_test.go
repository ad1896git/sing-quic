package hysteria2

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
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
		NextProtos:   []string{"h3"},
	}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	peers := make(chan quic.Connection, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		peer, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		peers <- peer
		server := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{Rx: 1000000})
			w.WriteHeader(protocol.StatusAuthOK)
		})}
		_ = server.ServeQUICConn(peer)
	}()
	defer func() { cancel(); _ = listener.Close(); hopFinalizeWait(t, serverDone) }()
	resolved := M.ParseSocksaddr(listener.Addr().String())
	d := &hopResolutionDialer{resolved: resolved}
	c := &Client{
		ctx: ctx, dialer: d, serverAddr: M.ParseSocksaddrHostPort(hopResolutionServer, resolved.Port),
		tlsConfig:  hopFinalizeNetworkTLS{config: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}},
		quicConfig: &quic.Config{}, hopPorts: strconv.Itoa(int(resolved.Port)), hopInterval: 5 * time.Second,
		udpDisabled: true, sendBPS: 1000000, receiveBPS: 1000000,
	}
	defer c.CloseWithError(net.ErrClosed)
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
