package tuic

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// Hold every writer's first datagram until all writers have read the initial
// MTU. Returning the size error together exercises concurrent retry updates,
// while subsequent writes exercise reads against those updates.
type concurrentMTUQUIC struct {
	quic.Connection
	ctx     context.Context
	arrived chan struct{}
	release chan struct{}
	limit   int
}

func (c *concurrentMTUQUIC) SendDatagram(data []byte) error {
	if len(data) > c.limit {
		select {
		case c.arrived <- struct{}{}:
		case <-c.ctx.Done():
			return c.ctx.Err()
		}
		select {
		case <-c.release:
		case <-c.ctx.Done():
			return c.ctx.Err()
		}
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(c.limit)}
	}
	return nil
}

func TestConcurrentUDPMTU(t *testing.T) {
	const writers = 8
	destination := M.ParseSocksaddr("example.org:53")
	for _, isServer := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		sender := &concurrentMTUQUIC{
			ctx: ctx, arrived: make(chan struct{}, writers),
			release: make(chan struct{}), limit: 128,
		}
		conn := newUDPPacketConn(ctx, sender, false, isServer, func() {}, nil)
		var workers sync.WaitGroup
		errors := make(chan error, writers)
		for writer := 0; writer < writers; writer++ {
			workers.Add(1)
			go func(packet bool) {
				defer workers.Done()
				payload := bytes.Repeat([]byte("x"), 256)
				for i := 0; i < 32; i++ {
					if packet {
						if err := conn.WritePacket(buf.As(payload), destination); err != nil {
							errors <- err
							return
						}
					} else if n, err := conn.WriteTo(payload, destination); err != nil || n != len(payload) {
						errors <- fmt.Errorf("WriteTo: n=%d err=%v", n, err)
						return
					}
				}
			}(writer%2 == 0)
		}
		for i := 0; i < writers; i++ {
			select {
			case <-sender.arrived:
			case <-ctx.Done():
				cancel()
				workers.Wait()
				conn.defragger.close()
				t.Fatal("writers did not reach the MTU retry barrier")
			}
		}
		close(sender.release)
		workers.Wait()
		cancel()
		conn.defragger.close()
		close(errors)
		for err := range errors {
			t.Errorf("server=%t: %v", isServer, err)
		}
		// Workers have joined, so this read needs no lock.
		if conn.udpMTU != sender.limit-3 {
			t.Errorf("server=%t: MTU=%d, want %d", isServer, conn.udpMTU, sender.limit-3)
		}
	}
}
