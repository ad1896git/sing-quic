package hysteria2

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/sagernet/sing-quic/internal/testquic"
)

// Unlike the error-injection fixtures, this peer enforces its advertised limit
// on every datagram. Exercise both public packet write APIs through real QUIC,
// then decode and reassemble with the protocol's actual receive path.
func TestLowDatagramRoundTrip(t *testing.T) {
	for _, limit := range []int64{0, 64} {
		for _, packet := range []bool{false, true} {
			for _, size := range []int{0, 1, 31, 32, 33, 255, 256, 4096} {
				t.Run(fmt.Sprintf("frame=%d/packet=%t/size=%d", limit, packet, size), func(t *testing.T) {
					testquic.CheckKnownFailure(t, limit, size)
					ctx, client, server := testquic.Pair(t, limit)
					sender := &udpPacketConn{ctx: context.Background(), quicConn: client, udpMTU: 1197}
					receiver := newUDPPacketConn(ctx, server, func() {}, nil)
					// Stop and join the reader before releasing defragger state,
					// including on an early write/assertion failure.
					ctx, cancel := context.WithCancel(ctx)
					done := make(chan struct{})
					t.Cleanup(func() {
						cancel()
						<-done
						receiver.defragger.close()
					})
					payload := bytes.Repeat([]byte{0, 0xff, 0x42, 0x80}, (size+3)/4)[:size]
					// Receive concurrently so the QUIC datagram queue cannot drop a burst.
					received := make(chan error, 1)
					go func() {
						defer close(done)
						for {
							wire, err := server.ReceiveDatagram(ctx)
							if err != nil {
								received <- err
								return
							}

							message := allocMessage()
							if err := decodeUDPMessage(message, wire); err != nil {
								message.release()
								received <- err
								return
							}
							receiver.inputPacket(message)
							select {
							case got := <-receiver.data:
								valid := bytes.Equal(got.data.Bytes(), payload) && got.destination == "example.org:53"
								got.releaseMessage()
								if !valid {
									received <- fmt.Errorf("payload or destination changed")
									return
								}
								received <- nil
								return
							default:
							}
						}
					}()
					n, err := fragmentBoundsWrite(sender, packet, payload)
					if err != nil || n != size {
						t.Fatalf("write n=%d err=%v", n, err)
					}
					select {
					case err := <-received:
						if err != nil {
							t.Fatal(err)
						}
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				})
			}
		}
	}
}
