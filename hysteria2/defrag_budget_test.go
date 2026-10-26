package hysteria2

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func defragBudgetTest(t *testing.T, budget *defragBudget) (*udpDefragger, *time.Time) {
	t.Helper()
	d := newUDPDefragger(budget)
	now := time.Unix(100, 123456789)
	d.now = func() time.Time { return now }
	t.Cleanup(d.close)
	return d, &now
}

func defragBudgetCheck(t *testing.T, b *defragBudget, items, bytes int) {
	t.Helper()
	b.access.Lock()
	defer b.access.Unlock()
	if b.items != items || b.bytes != bytes {
		t.Fatalf("budget = (%d, %d), want (%d, %d)", b.items, b.bytes, items, bytes)
	}
}

func defragBudgetFeed(t *testing.T, d *udpDefragger, packet uint16, total, id uint8, size int, complete bool) {
	t.Helper()
	m := defragOwnershipMessage(t, packet, total, id, strings.Repeat("x", size))
	got := d.feed(m)
	if (got != nil) != complete {
		if got != nil {
			got.releaseMessage()
		}
		t.Fatalf("packet %d completion = %v, want %v", packet, got != nil, complete)
	}
	if got != nil {
		got.releaseMessage()
	}
}

func TestDefragBudgetSessionItems(t *testing.T) {
	d, _ := defragBudgetTest(t, nil)
	for i := 0; i < 256; i++ {
		defragBudgetFeed(t, d, uint16(i), 2, 0, 1, false)
	}
	incoming := defragOwnershipMessage(t, 256, 2, 0, "x")
	buffer := incoming.data
	d.feed(incoming)
	if buffer.Len() != 0 || len(d.packetMap) != 256 {
		t.Fatal("item limit did not drop incoming fragment")
	}
	defragBudgetCheck(t, d.budget, 256, 256)
	for i := 0; i < 256; i++ {
		defragBudgetFeed(t, d, uint16(i), 2, 1, 1, true)
	}
	defragBudgetCheck(t, d.budget, 0, 0)
}

func TestDefragBudgetSessionBytes(t *testing.T) {
	d, _ := defragBudgetTest(t, nil)
	for i := 0; i < 32; i++ {
		defragBudgetFeed(t, d, uint16(i), 2, 0, 32768, false)
	}
	defragBudgetCheck(t, d.budget, 32, 1<<20)
	incoming := defragOwnershipMessage(t, 100, 2, 0, "x")
	buffer := incoming.data
	d.feed(incoming)
	if buffer.Len() != 0 || len(d.packetMap) != 32 {
		t.Fatal("byte limit did not drop incoming fragment")
	}
	// A denied fragment on an existing item must preserve that item too.
	incoming = defragOwnershipMessage(t, 0, 2, 1, "x")
	buffer = incoming.data
	d.feed(incoming)
	if buffer.Len() != 0 || d.packetMap[0].bytes != 32768 || d.packetMap[0].count != 1 {
		t.Fatal("byte rejection changed an existing item")
	}
	defragBudgetCheck(t, d.budget, 32, 1<<20)
	// A zero-length final fragment can complete at the exact byte budget.
	defragBudgetFeed(t, d, 0, 2, 1, 0, true)
	defragBudgetFeed(t, d, 100, 2, 0, 32768, false)
	defragBudgetCheck(t, d.budget, 32, 1<<20)
	d.close()
	defragBudgetCheck(t, d.budget, 0, 0)
}

func TestDefragBudgetMultiSession(t *testing.T) {
	// Explicit limits keep this test small while exercising the shared counters.
	for _, limits := range []struct{ items, bytes int }{{3, 100}, {10, 3}} {
		b := newDefragBudget(limits.items, limits.bytes)
		a, _ := defragBudgetTest(t, b)
		d, _ := defragBudgetTest(t, b)
		defragBudgetFeed(t, a, 1, 2, 0, 1, false)
		defragBudgetFeed(t, a, 2, 2, 0, 1, false)
		defragBudgetFeed(t, d, 1, 2, 0, 1, false)
		incoming := defragOwnershipMessage(t, 2, 2, 0, "x")
		buffer := incoming.data
		d.feed(incoming)
		if buffer.Len() != 0 || len(d.packetMap) != 1 {
			t.Fatal("connection limit did not drop incoming fragment")
		}
		defragBudgetCheck(t, b, 3, 3)
		incoming = defragOwnershipMessage(t, 1, 2, 1, "xxxx")
		buffer = incoming.data
		// In the item-limit case there is room for bytes, so this completes.
		// In the byte-limit case the existing item must survive rejection.
		got := d.feed(incoming)
		if limits.items == 3 {
			if got == nil {
				t.Fatal("existing item could not complete at the item limit")
			}
			got.releaseMessage()
			defragBudgetFeed(t, d, 1, 2, 0, 1, false)
		} else if got != nil || buffer.Len() != 0 || d.packetMap[1].bytes != 1 {
			if got != nil {
				got.releaseMessage()
			}
			t.Fatal("connection rejection changed existing item")
		}
		defragBudgetCheck(t, b, 3, 3)
		a.close()
		defragBudgetFeed(t, d, 2, 2, 0, 1, false)
		defragBudgetCheck(t, b, 2, 2)
		d.close()
		defragBudgetCheck(t, b, 0, 0)
	}
}

func TestDefragBudgetMessageLimit(t *testing.T) {
	d, _ := defragBudgetTest(t, nil)
	first := defragOwnershipMessage(t, 1, 3, 0, strings.Repeat("x", 32768))
	firstBuffer := first.data
	d.feed(first)
	incoming := defragOwnershipMessage(t, 1, 3, 1, strings.Repeat("x", 32768))
	buffer := incoming.data
	d.feed(incoming)
	if firstBuffer.Len() != 0 || buffer.Len() != 0 || len(d.packetMap) != 0 {
		t.Fatal("oversized message was retained")
	}
	defragBudgetCheck(t, d.budget, 0, 0)
	defragBudgetFeed(t, d, 2, 2, 0, 32768, false)
	defragBudgetFeed(t, d, 2, 2, 1, 32767, true)
	defragBudgetCheck(t, d.budget, 0, 0)
	defragBudgetFeed(t, d, 3, 2, 0, 65536, false)
	defragBudgetCheck(t, d.budget, 0, 0)
}

func TestDefragExpiry(t *testing.T) {
	d, now := defragBudgetTest(t, nil)
	first := defragOwnershipMessage(t, 1, 2, 0, "old")
	buffer := first.data
	d.feed(first)
	*now = now.Add(10*time.Second - time.Nanosecond)
	defragBudgetFeed(t, d, 2, 2, 0, 1, false)
	defragBudgetCheck(t, d.budget, 2, 4)
	*now = now.Add(time.Nanosecond)
	// A late last fragment starts a new item at the exact old deadline.
	defragBudgetFeed(t, d, 1, 2, 1, 1, false)
	if buffer.Len() != 0 {
		t.Fatal("expired fragment retained")
	}
	if !d.packetMap[1].deadline.Equal(now.Add(10 * time.Second)) {
		t.Fatal("late fragment did not get a fresh deadline")
	}
	defragBudgetCheck(t, d.budget, 2, 2)
	defragBudgetFeed(t, d, 1, 2, 0, 1, true)
	*now = now.Add(11 * time.Second)
	// Invalid input must sweep too.
	defragBudgetFeed(t, d, 3, 2, 2, 1, false)
	defragBudgetCheck(t, d.budget, 0, 0)
}

func TestDefragExpiryNotExtended(t *testing.T) {
	d, now := defragBudgetTest(t, nil)
	first := defragOwnershipMessage(t, 1, 4, 0, "x")
	buffer := first.data
	d.feed(first)
	deadline := d.packetMap[1].deadline
	*now = now.Add(9 * time.Second)
	duplicate := defragOwnershipMessage(t, 1, 4, 0, "duplicate")
	duplicateBuffer := duplicate.data
	d.feed(duplicate)
	defragBudgetFeed(t, d, 1, 4, 1, 1, false)
	if duplicateBuffer.Len() != 0 || !d.packetMap[1].deadline.Equal(deadline) {
		t.Fatal("fragment refreshed deadline or duplicate retained")
	}
	*now = now.Add(time.Second)
	defragBudgetFeed(t, d, 2, 2, 2, 1, false)
	if buffer.Len() != 0 {
		t.Fatal("first fragment survived hard lifetime")
	}
	defragBudgetCheck(t, d.budget, 0, 0)
}

func TestDefragBudgetReplacement(t *testing.T) {
	b := newDefragBudget(1, 4)
	d, now := defragBudgetTest(t, b)
	old := defragOwnershipMessage(t, 1, 3, 0, "old")
	buffer := old.data
	d.feed(old)
	*now = now.Add(9 * time.Second)
	defragBudgetFeed(t, d, 1, 2, 1, 4, false)
	if buffer.Len() != 0 || !d.packetMap[1].deadline.Equal(now.Add(10*time.Second)) {
		t.Fatal("replacement did not release old item or reset deadline")
	}
	defragBudgetCheck(t, b, 1, 4)
	defragBudgetFeed(t, d, 1, 3, 0, 5, false)
	if len(d.packetMap) != 0 {
		t.Fatal("over-budget replacement retained")
	}
	defragBudgetCheck(t, b, 0, 0)
}

func TestDefragBudgetCloseReleases(t *testing.T) {
	b := newDefragBudget(defragConnectionItems, defragConnectionBytes)
	c := newUDPPacketConn(context.Background(), nil, func() {}, b)
	other := newUDPPacketConn(context.Background(), nil, func() {}, b)
	t.Cleanup(func() { other.Close() })
	defragBudgetFeed(t, other.defragger, 2, 2, 0, 1, false)
	d := c.defragger
	first := defragOwnershipMessage(t, 1, 2, 0, "x")
	buffer := first.data
	d.feed(first)
	defragBudgetCheck(t, b, 2, 2)
	c.Close()
	c.Close()
	if buffer.Len() != 0 {
		t.Fatal("close retained fragment")
	}
	defragBudgetCheck(t, b, 1, 1)
	other.Close()
	defragBudgetCheck(t, b, 0, 0)
	incoming := defragOwnershipMessage(t, 2, 2, 0, "x")
	incomingBuffer := incoming.data
	d.feed(incoming)
	if incomingBuffer.Len() != 0 {
		t.Fatal("closed defragger retained late fragment")
	}
	defragBudgetCheck(t, b, 0, 0)
}

func TestDefragBudgetConcurrent(t *testing.T) {
	b := newDefragBudget(defragConnectionItems, defragConnectionBytes)
	var ds [2]*udpDefragger
	var clocks [2]*time.Time
	for i := range ds {
		ds[i], clocks[i] = defragBudgetTest(t, b)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			d := ds[worker%2]
			for i := 0; i < 32; i++ {
				packet := uint16(worker*32 + i)
				defragBudgetFeed(t, d, packet, 3, 0, 1, false)
				defragBudgetFeed(t, d, packet, 3, 1, 1, false)
				if i%2 == 0 {
					defragBudgetFeed(t, d, packet, 3, 2, 1, true)
				}
			}
		}(worker)
	}
	wg.Wait()
	defragBudgetCheck(t, b, 128, 256)
	for i, d := range ds {
		*clocks[i] = clocks[i].Add(10 * time.Second)
		defragBudgetFeed(t, d, 1000, 2, 2, 1, false)
	}
	defragBudgetCheck(t, b, 0, 0)
}

// Only tests override the production ten-second timer lifetime.
func defragBudgetWithLifetime(items, bytes int, lifetime time.Duration) *defragBudget {
	b := newDefragBudget(items, bytes)
	b.lifetime = lifetime
	return b
}

func TestDefragBudgetIdleSessionExpires(t *testing.T) {
	b := defragBudgetWithLifetime(2, 100, 50*time.Millisecond)
	a, _ := defragBudgetTest(t, b)
	other, _ := defragBudgetTest(t, b)
	defragBudgetFeed(t, a, 1, 2, 0, 1, false)
	defragBudgetFeed(t, a, 2, 2, 0, 1, false)
	defragBudgetFeed(t, other, 1, 2, 0, 1, false)
	if len(other.packetMap) != 0 {
		t.Fatal("connection budget was not full")
	}
	// The fixed feed clock never advances, and A receives no more traffic.
	// Retry B through a channel until A's real timers return capacity.
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case <-ticker.C:
			defragBudgetFeed(t, other, 1, 2, 0, 1, false)
			other.access.Lock()
			accepted := other.packetMap[1] != nil
			other.access.Unlock()
			if accepted {
				return
			}
		case <-timeout:
			t.Fatal("idle session did not return connection capacity")
		}
	}
}

func TestDefragBudgetTimerAfterRemoveIsNoop(t *testing.T) {
	for _, complete := range []bool{true, false} {
		d, _ := defragBudgetTest(t, nil)
		defragBudgetFeed(t, d, 1, 2, 0, 1, false)
		old := d.packetMap[1]
		timer := old.timer
		if timer == nil {
			t.Fatal("item has no expiry timer")
		}
		if complete {
			defragBudgetFeed(t, d, 1, 2, 1, 1, true)
			defragBudgetFeed(t, d, 1, 3, 0, 1, false)
		} else {
			// A changed fragment count evicts the old item with the same ID.
			defragBudgetFeed(t, d, 1, 3, 0, 1, false)
		}
		if old.timer != nil || timer.Stop() {
			t.Fatal("remove did not stop and detach the timer")
		}
		current := d.packetMap[1]
		d.expire(old) // Run the exact callback body after removal and ID reuse.
		if d.packetMap[1] != current || len(d.packetMap) != 1 || d.queue.Len() != 1 || d.bytes != 1 || current.count != 1 {
			t.Fatal("stale timer changed the replacement item")
		}
		defragBudgetCheck(t, d.budget, 1, 1)
	}
}

func TestDefragBudgetTimerCloseRace(t *testing.T) {
	for round := 0; round < 8; round++ {
		b := defragBudgetWithLifetime(256, 1024, 50*time.Millisecond)
		d, _ := defragBudgetTest(t, b)
		var items []*packetItem
		var timers []*time.Timer
		for i := 0; i < 128; i++ {
			defragBudgetFeed(t, d, uint16(i), 2, 0, 1, false)
			d.access.Lock()
			if item := d.packetMap[uint16(i)]; item != nil {
				items = append(items, item)
				timers = append(timers, item.timer)
			}
			d.access.Unlock()
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			d.close()
		}()
		for _, item := range items {
			wg.Add(1)
			go func(item *packetItem) {
				defer wg.Done()
				<-start
				d.expire(item)
			}(item)
		}
		close(start)
		wg.Wait()
		for i, item := range items {
			if item.timer != nil || timers[i] == nil || timers[i].Stop() {
				t.Fatal("close or expiry left an active timer")
			}
			d.expire(item) // A callback arriving after close must also be inert.
		}
		d.access.Lock()
		empty := len(d.packetMap) == 0 && d.queue.Len() == 0 && d.bytes == 0
		d.access.Unlock()
		if !empty {
			t.Fatal("close/timer race retained items")
		}
		defragBudgetCheck(t, b, 0, 0)
	}
}
