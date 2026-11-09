package hysteria

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-quic/internal/testquic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type transportCloseHandler struct {
	ServerHandler
	packets chan N.PacketConn
}

func (h *transportCloseHandler) NewPacketConnection(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
	h.packets <- conn
	return nil
}

// Hysteria's hold stream already propagates transport closure to both packet
// endpoints. Keep this comparison on real QUIC to guard that distinction.
func TestUDPSessionTransportClose(t *testing.T) {
	for _, mode := range []string{"peer", "local"} {
		t.Run(mode, func(t *testing.T) {
			_, local, peer := testquic.Pair(t, 0)
			caller, cancel := context.WithCancel(context.Background())
			defer cancel()
			parent := &clientQUICConnection{quicConn: local, rawConn: io.NopCloser(strings.NewReader("")), connDone: make(chan struct{}), udpConnMap: make(map[uint32]*udpPacketConn)}
			client := &Client{ctx: caller, conn: parent}
			handler := &transportCloseHandler{packets: make(chan N.PacketConn, 1)}
			session := &serverSession[string]{
				Service: &Service[string]{handler: handler, logger: logger.NOP(), udpTimeout: time.Hour},
				ctx:     caller, quicConn: peer, connDone: make(chan struct{}), udpConnMap: make(map[uint32]*udpPacketConn),
			}
			done := make(chan error, 1)
			go func() {
				stream, err := peer.AcceptStream(caller)
				if err == nil {
					err = session.handleStream(stream)
				}
				done <- err
			}()
			defer func() {
				_ = client.CloseWithError(net.ErrClosed)
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(time.Second):
					t.Error("server hold stream leaked")
				}
			}()
			packet, err := client.ListenPacket(caller, M.ParseSocksaddr("127.0.0.1:53"))
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			var serverPacket N.PacketConn
			select {
			case serverPacket = <-handler.packets:
			case <-time.After(time.Second):
				t.Fatal("no server packet session")
			}
			defer serverPacket.Close()
			results := make(chan error, 2)
			read := func() {
				go func() { _, _, err := packet.ReadFrom(make([]byte, 64)); results <- err }()
				go func() {
					buffer := buf.New()
					defer buffer.Release()
					_, err := serverPacket.ReadPacket(buffer)
					results <- err
				}()
			}
			read()
			select {
			case err := <-results:
				t.Fatalf("read returned before close: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			if mode == "peer" {
				session.closeWithError(net.ErrClosed)
			} else {
				_ = client.CloseWithError(net.ErrClosed)
			}
			check := func() {
				t.Helper()
				for i := 0; i < 2; i++ {
					select {
					case err := <-results:
						if !errors.Is(err, io.ErrClosedPipe) {
							t.Errorf("read = %v", err)
						}
					case <-time.After(time.Second):
						cancel()
						for j := i; j < 2; j++ {
							<-results
						}
						t.Fatal("packet read remained blocked after transport close")
					}
				}
			}
			check()
			if caller.Err() != nil {
				t.Fatal("transport close canceled caller context")
			}
			read()
			check()
		})
	}
}
