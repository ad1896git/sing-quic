package tuic

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type lifecycleTestHandler struct {
	ServiceHandler
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
		ctx:     ctx, udpConnMap: make(map[uint16]*udpPacketConn),
	}
	return s, handler
}

func lifecycleTestMessage(id uint16) *udpMessage {
	message := allocMessage()
	message.sessionID = id
	message.fragmentTotal = 1
	message.destination = M.ParseSocksaddr("example.com:53")
	message.data = buf.As([]byte("packet"))
	return message
}

func lifecycleTestCreate(t *testing.T, s *serverSession[string], h *lifecycleTestHandler, id uint16) (*udpPacketConn, N.PacketConn) {
	t.Helper()
	message := lifecycleTestMessage(id)
	s.handleUDPMessage(message, false)
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
	zero := newUDPPacketConn(s.ctx, nil, false, true, func() {})
	other := newUDPPacketConn(s.ctx, nil, false, true, func() {})
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
	s.handleUDPMessage(message, false)
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

func TestUDPSessionLifecycleConcurrentFirstPackets(t *testing.T) {
	const packets = 32
	s, h := lifecycleTestSession(t)
	ctx, cancel := context.WithCancel(s.ctx)
	s.ctx = ctx
	t.Cleanup(cancel)
	var handlers atomic.Int32
	processed := make(chan struct{}, packets)
	exited := make(chan struct{}, packets)
	h.handle = func(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
		handlers.Add(1)
		defer func() {
			conn.Close()
			exited <- struct{}{}
		}()
		buffer := buf.New()
		defer buffer.Release()
		for {
			buffer.Reset()
			if _, err := conn.ReadPacket(buffer); err != nil {
				return nil
			}
			processed <- struct{}{}
		}
	}
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(packets)
	done.Add(packets)
	for i := 0; i < packets; i++ {
		go func() {
			defer done.Done()
			message := lifecycleTestMessage(7)
			ready.Done()
			<-start
			s.handleUDPMessage(message, false)
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	// Every created handler owns at least its first packet. Consuming all
	// packets ensures even late-scheduled handlers have incremented the count.
	for i := 0; i < packets; i++ {
		<-processed
	}
	count := handlers.Load()
	s.udpAccess.RLock()
	entries := len(s.udpConnMap)
	s.udpAccess.RUnlock()
	// Cancel the parent too, so even orphan handlers on unfixed code exit.
	cancel()
	if count != 1 || entries != 1 {
		t.Errorf("handlers = %d, map entries = %d; want 1 each", count, entries)
	}
	for i := int32(0); i < count; i++ {
		<-exited
	}
}

type lifecycleTestStream struct {
	quic.ReceiveStream
	*bytes.Reader
}

func (s *lifecycleTestStream) Read(p []byte) (int, error)      { return s.Reader.Read(p) }
func (s *lifecycleTestStream) CancelRead(quic.StreamErrorCode) {}

func lifecycleTestDissociate(s *serverSession[string], id uint16) error {
	return s.handleUniStream(&lifecycleTestStream{Reader: bytes.NewReader([]byte{
		Version, CommandDissociate, byte(id >> 8), byte(id),
	})})
}

func TestUDPSessionLifecycleDissociateTwice(t *testing.T) {
	s, h := lifecycleTestSession(t)
	s.connDone, s.authDone = make(chan struct{}), make(chan struct{})
	close(s.authDone)
	zero := newUDPPacketConn(s.ctx, nil, false, true, func() {})
	s.udpConnMap[0] = zero
	old, oldConn := lifecycleTestCreate(t, s, h, 7)
	for i := 0; i < 2; i++ {
		if err := lifecycleTestDissociate(s, 7); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-old.ctx.Done():
	default:
		t.Fatal("dissociation did not cancel the session")
	}
	live, _ := lifecycleTestCreate(t, s, h, 7)
	// A handler may close long after dissociation removed its table entry.
	oldConn.Close()
	s.udpAccess.RLock()
	defer s.udpAccess.RUnlock()
	if s.udpConnMap[0] != zero || s.udpConnMap[7] != live || len(s.udpConnMap) != 2 {
		t.Fatal("repeated dissociation or late Close removed another session")
	}
}

func TestUDPSessionLifecycleDissociateReplacement(t *testing.T) {
	s, h := lifecycleTestSession(t)
	s.connDone, s.authDone = make(chan struct{}), make(chan struct{})
	close(s.authDone)
	old, _ := lifecycleTestCreate(t, s, h, 7)
	canceled, release := make(chan struct{}), make(chan struct{})
	cancel := old.cancel
	old.cancel = func(err error) {
		cancel(err)
		close(canceled)
		<-release
	}
	done := make(chan error, 1)
	go func() { done <- lifecycleTestDissociate(s, 7) }()
	<-canceled
	// The old connection is canceled, but dissociation has not returned.
	// Its pending removal must not erase a replacement installed now.
	live, _ := lifecycleTestCreate(t, s, h, 7)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	old.cancel = cancel
	s.udpAccess.RLock()
	defer s.udpAccess.RUnlock()
	if s.udpConnMap[7] != live {
		t.Fatal("in-flight dissociation removed the replacement session")
	}
}
