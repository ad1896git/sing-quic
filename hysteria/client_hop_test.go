package hysteria

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	hop "github.com/sagernet/sing-quic/udphop"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

// Embedding the interface makes unexpected QUIC calls fail immediately.
type closeTestQUICConn struct {
	quic.Connection
	order *[]string
}

func (c *closeTestQUICConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	*c.order = append(*c.order, "quic")
	return nil
}

type closeTestRawConn struct {
	net.Conn
	order  *[]string
	closes int
}

func (c *closeTestRawConn) Close() error {
	c.closes++
	if c.order != nil {
		*c.order = append(*c.order, "raw")
	}
	return c.Conn.Close()
}

type closeTestPacketConn struct {
	net.PacketConn
	order  *[]string
	closes int
}

func (c *closeTestPacketConn) Close() error {
	c.closes++
	*c.order = append(*c.order, "packet")
	return c.PacketConn.Close()
}

func TestClientClosePacketConn(t *testing.T) {
	for _, hopping := range []bool{false, true} {
		t.Run(strconv.FormatBool(hopping), func(t *testing.T) {
			server, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			raw, err := net.Dial("udp", server.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			var order []string
			rawConn := &closeTestRawConn{Conn: raw, order: &order}
			defer raw.Close()
			// Earlier subtests may still be exiting their workers.
			waitCloseTestHopGoroutines(t, 0)
			var packetConn net.PacketConn
			if hopping {
				packetConn, err = hop.NewUDPHopPacketConn("127.0.0.1", strconv.Itoa(server.LocalAddr().(*net.UDPAddr).Port), 5*time.Second, func() (net.PacketConn, error) {
					return net.ListenPacket("udp", "127.0.0.1:0")
				})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				packetConn = bufio.NewUnbindPacketConn(rawConn)
			}
			defer packetConn.Close()
			if hopping {
				waitCloseTestHopGoroutines(t, 2)
			}
			tracked := &closeTestPacketConn{PacketConn: packetConn, order: &order}
			conn := &clientQUICConnection{
				quicConn:   &closeTestQUICConn{order: &order},
				rawConn:    rawConn,
				packetConn: tracked,
				connDone:   make(chan struct{}),
			}
			if !hopping {
				conn.rawConn = nil // Owned by the packet connection, as in offerNew.
			}
			client := &Client{conn: conn}
			closeErr := errors.New("test close")
			if err := client.CloseWithError(closeErr); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWithError(closeErr); err != nil {
				t.Fatal(err)
			}
			expected := []string{"quic", "packet", "raw"}
			if !reflect.DeepEqual(order, expected) {
				t.Fatalf("close order = %v, want %v", order, expected)
			}
			if rawConn.closes != 1 {
				t.Fatalf("raw Close calls = %d, want 1", rawConn.closes)
			}
			if tracked.closes != 1 {
				t.Fatalf("packet Close calls = %d, want 1", tracked.closes)
			}
			if conn.connErr != closeErr {
				t.Fatalf("close error = %v", conn.connErr)
			}
			select {
			case <-conn.connDone:
			default:
				t.Fatal("connection close was not signaled")
			}
			if hopping {
				waitCloseTestHopGoroutines(t, 0)
				if _, err := packetConn.WriteTo([]byte("closed"), server.LocalAddr()); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("hop WriteTo after Close = %v, want net.ErrClosed", err)
				}
			}
		})
	}
}

type initTestDialer struct {
	N.Dialer
	raw    *closeTestRawConn
	packet net.PacketConn
}

func (d *initTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.raw, nil
}

func (d *initTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	var err error
	d.packet, err = net.ListenPacket("udp", "127.0.0.1:0")
	return d.packet, err
}

type initTestTLSBase = aTLS.Config

type initTestTLSConfig struct {
	initTestTLSBase
	err error
}

func (c initTestTLSConfig) Config() (*tls.Config, error) { return nil, c.err }

func TestClientInitFailureClosesPacketConn(t *testing.T) {
	for _, ports := range []string{"", "443", "invalid"} {
		t.Run("ports="+ports, func(t *testing.T) {
			server, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			raw, err := net.Dial("udp", server.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			dialer := &initTestDialer{raw: &closeTestRawConn{Conn: raw}}
			initErr := errors.New("TLS init failed")
			client := &Client{
				ctx: context.Background(), dialer: dialer,
				serverAddr: M.ParseSocksaddr(server.LocalAddr().String()),
				hopPorts:   ports, hopInterval: 5 * time.Second,
				tlsConfig: initTestTLSConfig{err: initErr},
			}
			// Earlier subtests may still be exiting their workers.
			waitCloseTestHopGoroutines(t, 0)
			conn, err := client.offerNew(context.Background())
			if err == nil || conn != nil {
				t.Fatalf("offerNew = (%v, %v), want failure", conn, err)
			}
			if ports != "invalid" && !errors.Is(err, initErr) {
				t.Fatalf("offerNew error = %v, want %v", err, initErr)
			}
			waitCloseTestHopGoroutines(t, 0)
			if dialer.raw.closes != 1 {
				t.Fatalf("raw Close calls = %d, want 1", dialer.raw.closes)
			}
			if dialer.packet != nil {
				defer dialer.packet.Close()
				if _, err := dialer.packet.WriteTo([]byte("closed"), server.LocalAddr()); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("hop socket WriteTo after failure = %v, want net.ErrClosed", err)
				}
			}
		})
	}
}

// Count only the hop workers, excluding unrelated runtime and QUIC goroutines.
func closeTestHopGoroutines() int {
	stack := make([]byte, 1<<20)
	n := runtime.Stack(stack, true)
	return strings.Count(string(stack[:n]), "github.com/sagernet/sing-quic/udphop.(*udpHopPacketConn).hopLoop(") +
		strings.Count(string(stack[:n]), "github.com/sagernet/sing-quic/udphop.(*udpHopPacketConn).recvLoop(")
}

func waitCloseTestHopGoroutines(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if closeTestHopGoroutines() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("hop goroutines = %d, want %d", closeTestHopGoroutines(), want)
}
