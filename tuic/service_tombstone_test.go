package tuic

import (
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

func tombstoneTestSession(t *testing.T) (*serverSession[string], *lifecycleTestHandler, *time.Time) {
	t.Helper()
	s, h := lifecycleTestSession(t)
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	s.connDone, s.authDone = make(chan struct{}), make(chan struct{})
	close(s.authDone)
	return s, h, &now
}

func tombstoneTestDrop(t *testing.T, s *serverSession[string], h *lifecycleTestHandler, id uint16) {
	t.Helper()
	message := lifecycleTestMessage(id)
	data := message.data
	s.handleUDPMessage(message, false)
	// A dropped message is returned to the pool, clearing its fields.
	if message.referenced {
		t.Fatal("dropped message was not released")
	}
	data.Release()
	s.udpAccess.RLock()
	_, exists := s.udpConnMap[id]
	s.udpAccess.RUnlock()
	if exists {
		t.Fatal("dropped packet created a session")
	}
	select {
	case <-h.connections:
		t.Fatal("dropped packet started a handler")
	default:
	}
}

func TestTUICTombstoneBlocksRecreate(t *testing.T) {
	s, h, now := tombstoneTestSession(t)
	_, conn := lifecycleTestCreate(t, s, h, 7)
	conn.Close()
	conn.Close()
	if len(s.tombstones) != 1 || s.tombstones[0].id != 7 || !s.tombstones[0].until.Equal(now.Add(30*time.Second)) {
		t.Fatalf("tombstones after Close = %v", s.tombstones)
	}
	tombstoneTestDrop(t, s, h, 7)

	t.Run("stale callback preserves live session", func(t *testing.T) {
		s, h, _ := tombstoneTestSession(t)
		_, conn := lifecycleTestCreate(t, s, h, 8)
		replacement := newUDPPacketConn(s.ctx, nil, false, true, func() {}, nil)
		t.Cleanup(func() { replacement.Close() })
		s.udpConnMap[8] = replacement
		conn.Close()
		if s.udpConnMap[8] != replacement || len(s.tombstones) != 0 {
			t.Fatal("stale callback removed or tombstoned a live replacement")
		}
	})
}

func TestTUICTombstoneDissociate(t *testing.T) {
	s, h, _ := tombstoneTestSession(t)
	_, conn := lifecycleTestCreate(t, s, h, 7)
	for i := 0; i < 2; i++ {
		if err := lifecycleTestDissociate(s, 7); err != nil {
			t.Fatal(err)
		}
	}
	// Closing the handler after dissociation must not record the ID again.
	conn.Close()
	if len(s.tombstones) != 1 || s.tombstones[0].id != 7 {
		t.Fatalf("tombstones after dissociation and Close = %v", s.tombstones)
	}
	tombstoneTestDrop(t, s, h, 7)
}

func TestTUICTombstoneExpires(t *testing.T) {
	for _, elapsed := range []time.Duration{30 * time.Second, 31 * time.Second} {
		t.Run(elapsed.String(), func(t *testing.T) {
			s, h, now := tombstoneTestSession(t)
			old, conn := lifecycleTestCreate(t, s, h, 7)
			conn.Close()
			*now = now.Add(29 * time.Second)
			tombstoneTestDrop(t, s, h, 7)
			*now = now.Add(elapsed - 29*time.Second)
			live, _ := lifecycleTestCreate(t, s, h, 7)
			if live == old || len(s.tombstones) != 0 {
				t.Fatal("expired tombstone prevented recreation or was not pruned")
			}
		})
	}
}

func TestTUICTombstoneBound(t *testing.T) {
	s, h, now := tombstoneTestSession(t)
	for id := uint16(0); id < 257; id++ {
		_, conn := lifecycleTestCreate(t, s, h, id)
		conn.Close()
		*now = now.Add(time.Millisecond)
	}
	if len(s.tombstones) != 256 {
		t.Fatalf("tombstones = %d; want 256", len(s.tombstones))
	}
	for i, tombstone := range s.tombstones {
		if tombstone.id != uint16(i+1) {
			t.Fatalf("tombstone %d = %d; want %d", i, tombstone.id, i+1)
		}
	}
	tombstoneTestDrop(t, s, h, 256)
	lifecycleTestCreate(t, s, h, 0)
}

func tombstoneTestFill(s *serverSession[string]) {
	for id := uint16(0); len(s.udpConnMap) < 4096; id++ {
		if s.udpConnMap[id] == nil {
			// The cap only needs live contexts for these unrelated sessions.
			s.udpConnMap[id] = &udpPacketConn{ctx: s.ctx}
		}
	}
}

func TestTUICSessionCap(t *testing.T) {
	s, h, _ := tombstoneTestSession(t)
	_, conn := lifecycleTestCreate(t, s, h, 0)
	tombstoneTestFill(s)
	tombstoneTestDrop(t, s, h, 4096)
	if len(s.udpConnMap) != 4096 {
		t.Fatalf("sessions = %d; want 4096", len(s.udpConnMap))
	}
	conn.Close()
	lifecycleTestCreate(t, s, h, 4096)
	if len(s.udpConnMap) != 4096 {
		t.Fatalf("sessions after accepting replacement = %d; want 4096", len(s.udpConnMap))
	}
}

func TestTUICLiveSessionUnaffected(t *testing.T) {
	s, h, _ := tombstoneTestSession(t)
	raw, conn := lifecycleTestCreate(t, s, h, 0)
	tombstoneTestFill(s)
	s.handleUDPMessage(lifecycleTestMessage(0), false)
	buffer := buf.New()
	defer buffer.Release()
	if _, err := conn.ReadPacket(buffer); err != nil || string(buffer.Bytes()) != "packet" {
		t.Fatalf("live session packet = %q, %v", buffer.Bytes(), err)
	}
	if s.udpConnMap[0] != raw || len(s.udpConnMap) != 4096 {
		t.Fatal("packet replaced live session or changed session count")
	}
	select {
	case <-h.connections:
		t.Fatal("live session packet started another handler")
	default:
	}
}

func TestTUICTombstoneConcurrent(t *testing.T) {
	s, h, _ := tombstoneTestSession(t)
	const batch = 128
	for round := 0; round < 4; round++ {
		conns := make([]*udpPacketConn, batch)
		for i := range conns {
			conns[i], _ = lifecycleTestCreate(t, s, h, uint16(round*batch+i))
		}
		var wg sync.WaitGroup
		for i, conn := range conns {
			wg.Add(1)
			go func(id uint16, conn *udpPacketConn) {
				defer wg.Done()
				if id%2 == 0 {
					conn.Close()
				} else {
					if err := lifecycleTestDissociate(s, id); err != nil {
						t.Error(err)
					}
					conn.Close()
				}
				// At most 128 newer removals occur in this batch, so this
				// tombstone cannot have been evicted when its packet arrives.
				message := lifecycleTestMessage(id)
				data := message.data
				s.handleUDPMessage(message, false)
				data.Release()
				s.udpAccess.RLock()
				if len(s.tombstones) > 256 {
					t.Error("tombstone bound exceeded")
				}
				s.udpAccess.RUnlock()
			}(uint16(round*batch+i), conn)
		}
		wg.Wait()
		s.udpAccess.RLock()
		want := 256
		if round == 0 {
			want = batch
		}
		if len(s.udpConnMap) != 0 || len(s.tombstones) != want {
			t.Errorf("sessions = %d, tombstones = %d; want 0, %d", len(s.udpConnMap), len(s.tombstones), want)
		}
		seen := make(map[uint16]bool)
		for _, tombstone := range s.tombstones {
			if seen[tombstone.id] {
				t.Errorf("duplicate tombstone for %d", tombstone.id)
			}
			seen[tombstone.id] = true
		}
		s.udpAccess.RUnlock()
		select {
		case <-h.connections:
			t.Fatal("late concurrent packet started a handler")
		default:
		}
	}
}
