package tuic

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// These tests replace the allocator to count releases and overwrite returned
// storage immediately. They must not run in parallel.
type waitReadPacketAllocator struct {
	buf.Allocator
	releases map[*byte]int
}

func (a *waitReadPacketAllocator) Put(data []byte) error {
	a.releases[&data[0]]++
	for i := range data {
		data[i] = 0xdd
	}
	return a.Allocator.Put(data)
}

func trackWaitReadPacketReleases(t *testing.T) *waitReadPacketAllocator {
	t.Helper()
	original := buf.DefaultAllocator
	allocator := &waitReadPacketAllocator{Allocator: original, releases: make(map[*byte]int)}
	buf.DefaultAllocator = allocator
	t.Cleanup(func() { buf.DefaultAllocator = original })
	return allocator
}

func queueWaitReadPacket(t *testing.T, payload []byte, options N.ReadWaitOptions) (*udpPacketConn, *udpMessage, *buf.Buffer, *byte) {
	t.Helper()
	data := buf.NewSize(len(payload) + 1)
	if _, err := data.Write(payload); err != nil {
		t.Fatal(err)
	}
	storage := &data.FreeBytes()[0]
	if len(payload) > 0 {
		storage = &data.Bytes()[0]
	}
	message := allocMessage()
	message.destination = M.Socksaddr{Fqdn: "example.org", Port: 443}
	message.data = data
	conn := &udpPacketConn{ctx: context.Background(), data: make(chan *udpMessage, 1)}
	conn.InitializeReadWaiter(options)
	conn.data <- message
	return conn, message, data, storage
}

func TestWaitReadPacketHeadroom(t *testing.T) {
	for _, payload := range [][]byte{nil, {0, 1, 2, 0xff, 'h', 'i'}} {
		name := "payload"
		if len(payload) == 0 {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			allocator := trackWaitReadPacketReleases(t)
			options := N.ReadWaitOptions{FrontHeadroom: 8, RearHeadroom: 4, MTU: 64}
			conn, message, source, storage := queueWaitReadPacket(t, payload, options)
			destination := message.destination
			buffer, gotDestination, err := conn.WaitReadPacket()
			if err != nil {
				t.Fatal(err)
			}
			defer buffer.Release()
			if buffer == source || !bytes.Equal(buffer.Bytes(), payload) {
				t.Fatalf("copied payload = %x, want %x in a new buffer", buffer.Bytes(), payload)
			}
			if gotDestination != destination {
				t.Fatalf("destination = %v, want %v", gotDestination, destination)
			}
			if buffer.Start() != options.FrontHeadroom || buffer.FreeLen() != options.MTU-len(payload)+options.RearHeadroom {
				t.Fatalf("unexpected headroom: start=%d free=%d", buffer.Start(), buffer.FreeLen())
			}
			if allocator.releases[storage] != 1 || source.RawCap() != 0 || message.referenced || message.data != nil {
				t.Fatalf("message not released exactly once: releases=%d message=%+v", allocator.releases[storage], message)
			}
		})
	}
}

func TestWaitReadPacketCopyFailure(t *testing.T) {
	allocator := trackWaitReadPacketReleases(t)
	options := N.ReadWaitOptions{FrontHeadroom: buf.UDPBufferSize}
	conn, message, source, storage := queueWaitReadPacket(t, []byte("payload"), options)
	destination := message.destination
	buffer, gotDestination, err := conn.WaitReadPacket()
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("error = %v, want %v", err, io.ErrShortBuffer)
	}
	if gotDestination != destination {
		t.Fatalf("destination = %v, want %v", gotDestination, destination)
	}
	if allocator.releases[storage] != 1 || source.RawCap() != 0 || message.referenced || message.data != nil {
		t.Fatalf("message not released exactly once: releases=%d message=%+v", allocator.releases[storage], message)
	}
	if buffer == nil || buffer.RawCap() != 0 {
		t.Fatal("failed copy buffer was not released")
	}
	if len(allocator.releases) != 2 {
		t.Fatalf("released %d buffers, want source and failed copy", len(allocator.releases))
	}
	for _, count := range allocator.releases {
		if count != 1 {
			t.Fatalf("buffer released %d times, want 1", count)
		}
	}
}

func TestWaitReadPacketNoHeadroom(t *testing.T) {
	allocator := trackWaitReadPacketReleases(t)
	payload := []byte("payload")
	conn, message, source, storage := queueWaitReadPacket(t, payload, N.ReadWaitOptions{})
	destination := message.destination
	buffer, gotDestination, err := conn.WaitReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if buffer != source || !bytes.Equal(buffer.Bytes(), payload) || gotDestination != destination {
		t.Fatal("payload buffer and destination were not transferred unchanged")
	}
	if allocator.releases[storage] != 0 || message.referenced || message.data != nil {
		t.Fatal("message release did not preserve payload ownership")
	}
	buffer.Release()
	if allocator.releases[storage] != 1 {
		t.Fatalf("caller released buffer %d times, want 1", allocator.releases[storage])
	}
}
