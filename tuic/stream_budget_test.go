package tuic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
)

func TestIncomingStreamBudgetConstructors(t *testing.T) {
	service, err := NewService[string](ServiceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]int64{
		"service bidirectional":  service.quicConfig.MaxIncomingStreams,
		"service unidirectional": service.quicConfig.MaxIncomingUniStreams,
		"client unidirectional":  client.quicConfig.MaxIncomingUniStreams,
	} {
		if got != 100 {
			t.Errorf("%s = %d, want 100", name, got)
		}
	}
}

// Exercise the actual constructor configs over an in-memory packet link. Only 100 streams and
// one replacement are ever opened; no high-numbered stream frames are used.
func TestIncomingStreamBudgetTransport(t *testing.T) {
	service, err := NewService[string](ServiceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := streamBudgetTLS(t)
	for _, tc := range []struct {
		name             string
		config           *quic.Config
		uni              bool
		receiverIsClient bool
	}{
		{name: "service_bidirectional", config: service.quicConfig},
		{name: "service_unidirectional", config: service.quicConfig, uni: true},
		{name: "client_unidirectional", config: client.quicConfig, uni: true, receiverIsClient: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			serverConfig, clientConfig := tc.config, &quic.Config{}
			if tc.receiverIsClient {
				serverConfig, clientConfig = clientConfig, serverConfig
			}
			serverPacket, clientPacket := streamBudgetPacketPair()
			defer serverPacket.Close()
			defer clientPacket.Close()
			listener, err := quic.Listen(serverPacket, serverTLS, serverConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			dialed, err := quic.Dial(ctx, clientPacket, serverPacket.LocalAddr(), &tls.Config{
				InsecureSkipVerify: true, // Ephemeral self-signed certificate, in-memory link only.
				NextProtos:         serverTLS.NextProtos,
			}, clientConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer dialed.CloseWithError(0, "")
			accepted, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer accepted.CloseWithError(0, "")
			sender, receiver := dialed, accepted
			if tc.receiverIsClient {
				sender, receiver = receiver, sender
			}

			var firstSend quic.SendStream
			var firstReceive quic.ReceiveStream
			for i := 0; i < 100; i++ {
				var send quic.SendStream
				if tc.uni {
					send, err = sender.OpenUniStream()
				} else {
					send, err = sender.OpenStream()
				}
				if err != nil {
					t.Fatalf("open stream %d: %v", i+1, err)
				}
				if err = send.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				// A write makes the stream visible to Accept on the peer.
				if _, err = send.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
				var receive quic.ReceiveStream
				if tc.uni {
					receive, err = receiver.AcceptUniStream(ctx)
				} else {
					receive, err = receiver.AcceptStream(ctx)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err = receive.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				var b [1]byte
				if _, err = io.ReadFull(receive, b[:]); err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					firstSend, firstReceive = send, receive
				}
			}
			if tc.uni {
				_, err = sender.OpenUniStream()
			} else {
				_, err = sender.OpenStream()
			}
			var limitErr *quic.StreamLimitReachedError
			if !errors.As(err, &limitErr) {
				t.Fatalf("open stream 101 = %v, want StreamLimitReachedError", err)
			}

			// FIN must be consumed, and both directions of a bidirectional stream
			// must close, before QUIC returns stream credit to the sender.
			if err = firstSend.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = io.Copy(io.Discard, firstReceive); err != nil {
				t.Fatal(err)
			}
			if !tc.uni {
				if err = firstReceive.(quic.Stream).Close(); err != nil {
					t.Fatal(err)
				}
				if err = firstSend.(quic.Stream).SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err = io.Copy(io.Discard, firstSend.(quic.Stream)); err != nil {
					t.Fatal(err)
				}
			}
			// Wait for the asynchronous MAX_STREAMS update without polling or sleeps.
			if tc.uni {
				firstSend, err = sender.OpenUniStreamSync(ctx)
			} else {
				firstSend, err = sender.OpenStreamSync(ctx)
			}
			if err != nil {
				t.Fatalf("open replacement after close: %v", err)
			}
			defer firstSend.CancelWrite(0)
			if tc.uni {
				_, err = sender.OpenUniStream()
			} else {
				_, err = sender.OpenStream()
			}
			if !errors.As(err, &limitErr) {
				t.Fatalf("open beyond replenished budget = %v, want StreamLimitReachedError", err)
			}
		})
	}
}

func streamBudgetTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: key}},
		NextProtos:   []string{"stream-budget-test"},
	}
}

// net.Pipe provides bounded buffering and deadlines. A length prefix preserves
// packet boundaries without requiring sockets or a background fixture goroutine.
type streamBudgetPacketConn struct {
	net.Conn
	local, remote *net.UDPAddr
}

func streamBudgetPacketPair() (*streamBudgetPacketConn, *streamBudgetPacketConn) {
	a, b := net.Pipe()
	addrA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001}
	addrB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10002}
	return &streamBudgetPacketConn{a, addrA, addrB}, &streamBudgetPacketConn{b, addrB, addrA}
}

func (c *streamBudgetPacketConn) LocalAddr() net.Addr { return c.local }

func (c *streamBudgetPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var header [2]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return 0, nil, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size > len(p) {
		return 0, nil, io.ErrShortBuffer
	}
	n, err := io.ReadFull(c.Conn, p[:size])
	return n, c.remote, err
}

func (c *streamBudgetPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if len(p) > 65535 {
		return 0, io.ErrShortBuffer
	}
	packet := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(packet[:2], uint16(len(p)))
	copy(packet[2:], p)
	if _, err := c.Conn.Write(packet); err != nil {
		return 0, err
	}
	return len(p), nil
}
