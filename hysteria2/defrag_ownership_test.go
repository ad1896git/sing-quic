package hysteria2

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

func defragOwnershipMessage(t *testing.T, packetID uint16, total, id uint8, payload string) *udpMessage {
	t.Helper()
	m := allocMessage()
	m.sessionID = 7
	m.packetID = packetID
	m.fragmentTotal = total
	m.fragmentID = id
	m.destination = "example.org:53"
	m.data = buf.NewSize(len(payload))
	copy(m.data.Extend(len(payload)), payload)
	return m
}

func defragOwnershipClear(t *testing.T, d *udpDefragger) {
	t.Helper()
	d.access.Lock()
	defer d.access.Unlock()
	for _, item := range d.packetMap {
		d.remove(item)
	}
}

func defragOwnershipWait(t *testing.T, wg *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("defragger workers did not finish within 10 seconds")
	}
}

func defragOwnershipCheck(t *testing.T, m *udpMessage, payload string) {
	t.Helper()
	defer m.releaseMessage()
	if string(m.data.Bytes()) != payload || m.sessionID != 7 || m.destination != "example.org:53" {
		t.Errorf("packet %d: unexpected payload or metadata: %q", m.packetID, m.data.Bytes())
	}
}

func TestDefragOwnershipConcurrent(t *testing.T) {
	const packets, fragments, workers = 256, 4, 8
	d := newUDPDefragger(nil)
	defer defragOwnershipClear(t, d)
	var jobs [workers][]*udpMessage
	var buffers []*buf.Buffer
	for packet := 0; packet < packets; packet++ {
		for fragment := 0; fragment < fragments; fragment++ {
			m := defragOwnershipMessage(t, uint16(packet), fragments, uint8(fragment), fmt.Sprintf("%d/%d;", packet, fragment))
			buffers = append(buffers, m.data)
			worker := (packet + fragment) % workers
			jobs[worker] = append(jobs[worker], m)
		}
	}
	results := make(chan *udpMessage, packets)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, job := range jobs {
		wg.Add(1)
		go func(messages []*udpMessage) {
			defer wg.Done()
			<-start
			for _, m := range messages {
				if got := d.feed(m); got != nil {
					results <- got
				}
			}
		}(job)
	}
	close(start)
	defragOwnershipWait(t, &wg)
	close(results)
	seen := make(map[uint16]int)
	for m := range results {
		packet := m.packetID
		seen[packet]++
		defragOwnershipCheck(t, m, fmt.Sprintf("%d/0;%d/1;%d/2;%d/3;", packet, packet, packet, packet))
	}
	for packet := 0; packet < packets; packet++ {
		if seen[uint16(packet)] != 1 {
			t.Errorf("packet %d completed %d times, want once", packet, seen[uint16(packet)])
		}
	}
	for i, buffer := range buffers {
		if buffer.Len() != 0 {
			t.Errorf("completed fragment %d buffer was not released", i)
		}
	}
	d.access.Lock()
	defer d.access.Unlock()
	for key, item := range d.packetMap {
		if item.count != 0 || len(item.messages) != 0 {
			t.Errorf("packet %d retained completed fragments", key)
		}
	}
}

func TestDefragOwnershipDuplicateAndInvalid(t *testing.T) {
	d := newUDPDefragger(nil)
	defer defragOwnershipClear(t, d)
	first := defragOwnershipMessage(t, 1, 3, 0, "first")
	firstBuffer := first.data
	if got := d.feed(first); got != nil {
		got.releaseMessage()
		t.Fatal("incomplete packet delivered")
	}
	for _, id := range []uint8{0, 3, 255} {
		m := defragOwnershipMessage(t, 1, 3, id, "discard")
		buffer := m.data
		if got := d.feed(m); got != nil {
			got.releaseMessage()
			t.Fatal("duplicate or invalid fragment delivered")
		}
		if buffer.Len() != 0 {
			t.Fatal("discarded fragment buffer was not released")
		}
		d.access.Lock()
		item, ok := d.packetMap[1]
		unchanged := ok && item.count == 1 && len(item.messages) == 3 && item.messages[0] == first
		d.access.Unlock()
		if !unchanged {
			t.Fatal("discarded fragment changed stored reassembly")
		}
	}
	if got := d.feed(defragOwnershipMessage(t, 1, 3, 2, "third")); got != nil {
		got.releaseMessage()
		t.Fatal("incomplete packet delivered after discarded fragments")
	}
	got := d.feed(defragOwnershipMessage(t, 1, 3, 1, "second"))
	if got == nil {
		t.Fatal("remaining fragments did not complete packet")
	}
	defragOwnershipCheck(t, got, "firstsecondthird")
	if firstBuffer.Len() != 0 {
		t.Fatal("stored fragment buffer was not released on completion")
	}

	// A changed total drops the old fragments and keeps the triggering fragment.
	old := defragOwnershipMessage(t, 2, 3, 0, "old")
	oldBuffer := old.data
	d.feed(old)
	replacement := defragOwnershipMessage(t, 2, 2, 1, "new-second")
	replacementBuffer := replacement.data
	if got := d.feed(replacement); got != nil {
		got.releaseMessage()
		t.Fatal("reset delivered incomplete packet")
	}
	if oldBuffer.Len() != 0 || replacementBuffer.Len() == 0 {
		t.Fatal("reset did not release old fragments and retain the new fragment")
	}
	got = d.feed(defragOwnershipMessage(t, 2, 2, 0, "new-first"))
	if got == nil {
		t.Fatal("reset packet did not complete")
	}
	defragOwnershipCheck(t, got, "new-firstnew-second")
	if replacementBuffer.Len() != 0 {
		t.Fatal("reset fragment buffer was not released on completion")
	}
}

func TestDefragOwnershipEviction(t *testing.T) {
	const packets, fragments, workers = 128, 4, 8
	d := newUDPDefragger(nil)
	defer defragOwnershipClear(t, d)
	var buffers []*buf.Buffer
	for packet := 0; packet < packets; packet++ {
		m := defragOwnershipMessage(t, uint16(packet), fragments, 0, "x")
		buffers = append(buffers, m.data)
		d.feed(m)
	}
	// Force removal without waiting for expiry.
	defragOwnershipClear(t, d)
	for i, buffer := range buffers {
		if buffer.Len() != 0 {
			t.Fatalf("evicted fragment %d buffer was not released", i)
		}
	}
	// Keep every packet incomplete before starting the removal workers.
	for packet := 0; packet < packets; packet++ {
		m := defragOwnershipMessage(t, uint16(packet), fragments, 0, "x")
		buffers = append(buffers, m.data)
		d.feed(m)
	}
	var jobs [workers][]*udpMessage
	for packet := 0; packet < packets; packet++ {
		for fragment := 1; fragment < fragments; fragment++ {
			m := defragOwnershipMessage(t, uint16(packet), fragments, uint8(fragment), "x")
			buffers = append(buffers, m.data)
			worker := (packet + fragment) % workers
			jobs[worker] = append(jobs[worker], m)
		}
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, job := range jobs {
		wg.Add(1)
		go func(messages []*udpMessage) {
			defer wg.Done()
			<-start
			for _, m := range messages {
				if got := d.feed(m); got != nil {
					defragOwnershipCheck(t, got, "xxxx")
				}
			}
		}(job)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < packets; i++ {
			d.access.Lock()
			if item := d.packetMap[uint16(i)]; item != nil {
				d.remove(item)
			}
			d.access.Unlock()
		}
	}()
	close(start)
	defragOwnershipWait(t, &wg)
	defragOwnershipClear(t, d)
	for i, buffer := range buffers {
		if buffer.Len() != 0 {
			t.Errorf("fragment %d buffer survived completion and eviction", i)
		}
	}
}
