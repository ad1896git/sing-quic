package hysteria2

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type lifecycleTestHandler struct {
	ServerHandler
	connections chan N.PacketConn
	handle      func(context.Context, N.PacketConn, M.Metadata) error
}

func (h *lifecycleTestHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	if h.handle != nil {
		return h.handle(ctx, conn, metadata)
	}
	h.connections <- conn
	return nil
}

func lifecycleTestSession(t *testing.T) (*serverSession[string], *lifecycleTestHandler) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	handler := &lifecycleTestHandler{connections: make(chan N.PacketConn, 64)}
	s := &serverSession[string]{
		Service: &Service[string]{handler: handler, udpTimeout: time.Hour},
		ctx:     ctx, udpConnMap: make(map[uint32]*udpPacketConn),
	}
	return s, handler
}

func lifecycleTestMessage(id uint32) *udpMessage {
	message := allocMessage()
	message.sessionID = id
	message.fragmentTotal = 1
	message.destination = "example.com:53"
	message.data = buf.As([]byte("packet"))
	return message
}

func lifecycleTestCreate(t *testing.T, s *serverSession[string], h *lifecycleTestHandler, id uint32) (*udpPacketConn, N.PacketConn) {
	t.Helper()
	message := lifecycleTestMessage(id)
	s.handleUDPMessage(message)
	conn := <-h.connections
	t.Cleanup(func() { conn.Close() })
	buffer := buf.New()
	defer buffer.Release()
	destination, err := conn.ReadPacket(buffer)
	if err != nil || string(buffer.Bytes()) != "packet" || destination != M.ParseSocksaddr("example.com:53") {
		t.Fatalf("first packet = %q, %v, %v", buffer.Bytes(), destination, err)
	}
	// ReadPacket has returned the first message to the pool before Close.
	s.udpAccess.RLock()
	raw := s.udpConnMap[id]
	s.udpAccess.RUnlock()
	return raw, conn
}

func TestUDPSessionLifecycleFirstPacket(t *testing.T) {
	s, h := lifecycleTestSession(t)
	zero := newUDPPacketConn(s.ctx, nil, func() {})
	other := newUDPPacketConn(s.ctx, nil, func() {})
	s.udpConnMap[0], s.udpConnMap[9] = zero, other
	_, conn := lifecycleTestCreate(t, s, h, 7)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	s.udpAccess.RLock()
	defer s.udpAccess.RUnlock()
	if s.udpConnMap[7] != nil {
		t.Error("closed session 7 remains in the map")
	}
	if s.udpConnMap[0] != zero || s.udpConnMap[9] != other {
		t.Error("closing session 7 deleted an unrelated session (including session 0)")
	}
}

func TestUDPSessionLifecycleReusedID(t *testing.T) {
	s, h := lifecycleTestSession(t)
	// Keep this message queued so its ID is still 7: this isolates the
	// identity guard from the separate pooled-message regression above.
	message := lifecycleTestMessage(7)
	s.handleUDPMessage(message)
	oldConn := <-h.connections
	old := s.udpConnMap[7]
	t.Cleanup(func() {
		oldConn.Close()
		message.releaseMessage()
	})
	// Cancellation precedes the old handler's eventual Close, allowing a new
	// first packet to replace the canceled connection under the same ID.
	old.closeWithError(context.Canceled)
	live, _ := lifecycleTestCreate(t, s, h, 7)
	if old == live {
		t.Fatal("canceled connection was reused")
	}
	if err := oldConn.Close(); err != nil {
		t.Fatal(err)
	}
	s.udpAccess.RLock()
	defer s.udpAccess.RUnlock()
	if s.udpConnMap[7] != live {
		t.Fatal("old session removed the live session with the same ID")
	}
}
