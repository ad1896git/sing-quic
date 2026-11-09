package hysteria2

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
)

// Real QUIC closure must release all packet read APIs, independently of the
// caller/service context. Each API uses a distinct session on the same parent.
func TestUDPSessionTransportClose(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			for _, mode := range []string{"peer", "local"} {
				t.Run(mode, func(t *testing.T) {
					_, local, peer := testquic.Pair(t, 0)
					caller, cancel := context.WithCancel(context.Background())
					defer cancel()
					done := make(chan struct{})
					var packets []*udpPacketConn
					var closeLocal func()
					var checkClosed func()
					if side == "client" {
						parent := &clientQUICConnection{quicConn: local, rawConn: io.NopCloser(strings.NewReader("")), connDone: make(chan struct{}), udpConnMap: make(map[uint32]*udpPacketConn)}
						client := &Client{ctx: caller, conn: parent}
						closeLocal = func() { _ = client.CloseWithError(net.ErrClosed) }
						for i := 0; i < 3; i++ {
							packet, err := client.ListenPacket(caller)
							if err != nil {
								t.Fatal(err)
							}
							packets = append(packets, packet.(*udpPacketConn))
						}
						checkClosed = func() {
							parent.udpAccess.RLock()
							defer parent.udpAccess.RUnlock()
							if len(parent.udpConnMap) != 0 {
								t.Error("closed client retained UDP sessions")
							}
						}
						go func() { defer close(done); client.loopMessages(parent) }()
					} else {
						session, handler := lifecycleTestSession(t)
						session.ctx, session.quicConn = caller, local
						session.logger = logger.NOP()
						session.connDone = make(chan struct{})

						closeLocal = func() { session.closeWithError(net.ErrClosed) }
						for i := 0; i < 3; i++ {
							packet, _ := lifecycleTestCreate(t, session, handler, uint32(i))
							packets = append(packets, packet)
						}
						checkClosed = func() {
							// A packet already dispatched when transport close began must not
							// recreate a session after the table was drained.
							session.handleUDPMessage(lifecycleTestMessage(99))
							session.udpAccess.RLock()
							defer session.udpAccess.RUnlock()
							if len(session.udpConnMap) != 0 {
								t.Error("closed server admitted a UDP session")
							}
						}
						go func() { defer close(done); session.loopMessages() }()
					}
					defer func() {
						closeLocal()
						select {
						case <-done:
						case <-time.After(time.Second):
							t.Error("transport receive loop leaked")
						}
					}()
					for _, packet := range packets {
						defer packet.Close()
					}
					read := func(i int) error {
						switch i {
						case 0:
							_, _, err := packets[i].ReadFrom(make([]byte, 64))
							return err
						case 1:
							buffer := buf.New()
							defer buffer.Release()
							_, err := packets[i].ReadPacket(buffer)
							return err
						default:
							buffer, _, err := packets[i].WaitReadPacket()
							if buffer != nil {
								buffer.Release()
							}
							return err
						}
					}
					results := make(chan error, 3)
					for i := range packets {
						go func(i int) { results <- read(i) }(i)
					}
					// Verify reads are pending before closing the transport.
					select {
					case err := <-results:
						t.Fatalf("read returned before close: %v", err)
					case <-time.After(20 * time.Millisecond):
					}
					if mode == "peer" {
						_ = peer.CloseWithError(0, "peer closed")
					} else {
						closeLocal()
					}
					check := func() {
						t.Helper()
						for completed := 0; completed < len(packets); completed++ {
							select {
							case err := <-results:
								if !errors.Is(err, io.ErrClosedPipe) {
									t.Errorf("read = %v, want closed pipe", err)
								}
							case <-time.After(time.Second):
								// Always join the readers even on unfixed code.
								cancel()
								for remaining := completed; remaining < len(packets); remaining++ {
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
					// Wait for the parent cleanup callback, then verify map removal and
					// defragger shutdown as well as cancellation.
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Fatal("parent cleanup did not finish")
					}
					checkClosed()
					for _, packet := range packets {
						packet.defragger.access.Lock()
						closed := packet.defragger.closed
						packet.defragger.access.Unlock()
						if !closed {
							t.Error("closed packet retained defragger")
						}
						// Model a packet queued before cancellation. Closed sessions must
						// prefer the close error over buffered data on every read API.
						packet.inputPacket(lifecycleTestMessage(packet.sessionID))
						defer func(p *udpPacketConn) {
							select {
							case message := <-p.data:
								message.releaseMessage()
							default:
							}
						}(packet)
					}
					// Future reads on those same sessions must also return a close error.
					for i := range packets {
						go func(i int) { results <- read(i) }(i)
					}
					check()
					// Idempotence includes concurrent transport receive-loop shutdown.
					closeLocal()
				})
			}
		})
	}
}

// Preserve the existing packet lifetime when its context is canceled.
func TestUDPSessionContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	parent := &clientQUICConnection{quicConn: &connSyncQUIC{ctx: context.Background()}, connDone: make(chan struct{}), udpConnMap: make(map[uint32]*udpPacketConn)}
	client := &Client{ctx: ctx, conn: parent}
	packet, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	cancel()
	_, _, err = packet.ReadFrom(make([]byte, 1))
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("read after context cancellation = %v", err)
	}
	if !parent.active() {
		t.Fatal("packet context cancellation closed parent")
	}
}
