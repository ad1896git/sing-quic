package hysteria

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// The existing packet_fragment_bounds_test.go owns the base MTU, count, retry,
// and wire-vector test names. These subtests add the missing boundary cases.
func TestFragmentBoundsMTULimits(t *testing.T) {
	header := fragmentBoundsMessage(nil).headerSize()
	for _, limit := range []int{math.MinInt, -1, 0, header - 1, header, header + 1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			message := fragmentBoundsMessage([]byte("x"))
			fragments, err := fragUDPMessage(message, limit)
			if limit <= header {
				if err == nil || err.Error() != "UDP payload MTU must be positive" || fragments != nil {
					t.Fatalf("fragments=%v error=%v", fragments, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer releaseMessages(fragments)
			if len(fragments) != 1 || !bytes.Equal(fragments[0].data.Bytes(), []byte("x")) {
				t.Fatalf("expected one one-byte fragment: %v", fragments)
			}
		})
	}
}

func TestFragmentBoundsCountError(t *testing.T) {
	t.Run("256-error-text", func(t *testing.T) {
		message := fragmentBoundsMessage(make([]byte, 256))
		fragments, err := fragUDPMessage(message, message.headerSize()+1)
		if err == nil || err.Error() != "UDP message requires more than 255 fragments" || fragments != nil {
			t.Fatalf("fragments=%v error=%v", fragments, err)
		}
	})
}

type fragmentBoundsFailureQUIC struct {
	quic.Connection
	calls   int
	failAt  int
	err     error
	packets [][]byte
}

func (c *fragmentBoundsFailureQUIC) SendDatagram(data []byte) error {
	c.calls++
	if c.calls == c.failAt {
		return c.err
	}
	c.packets = append(c.packets, append([]byte(nil), data...))
	return nil
}

func TestFragmentBoundsRetryLimits(t *testing.T) {
	header := fragmentBoundsMessage(nil).headerSize()
	for _, packet := range []bool{false, true} {
		for _, initialMTU := range []int{1200, header + 4} {
			for _, limit := range []int64{math.MinInt64, 0, 1, 3, int64(header + 2), int64(header + 3), int64(header + 6), math.MaxInt64} {
				t.Run(fmt.Sprintf("packet=%t/mtu=%d/limit=%d", packet, initialMTU, limit), func(t *testing.T) {
					sender := &fragmentBoundsFailureQUIC{failAt: 1, err: &quic.DatagramTooLargeError{MaxDatagramPayloadSize: limit}}
					c := &udpPacketConn{ctx: context.Background(), quicConn: sender, udpMTU: initialMTU}
					data := []byte("abcdefg")
					n, err := fragmentBoundsWrite(c, packet, data)
					valid := limit > int64(header+3) && limit-3 <= int64(math.MaxInt)
					if !valid {
						if err == nil || err.Error() != "UDP payload MTU must be positive" || n != 0 || sender.calls != 1 || len(sender.packets) != 0 {
							t.Fatalf("n=%d err=%v calls=%d packets=%d", n, err, sender.calls, len(sender.packets))
						}

						return
					}
					if err != nil || n != len(data) {
						t.Fatalf("n=%d err=%v", n, err)
					}
					var joined []byte
					for _, wire := range sender.packets {
						var decoded udpMessage
						if err := decodeUDPMessage(&decoded, wire); err != nil {
							t.Fatal(err)
						}
						joined = append(joined, decoded.data.Bytes()...)
					}
					if !bytes.Equal(joined, data) {
						t.Fatalf("payload changed: %x", joined)
					}
					if limit == int64(header+6) && len(sender.packets) != 3 {
						t.Fatalf("got %d fragments", len(sender.packets))
					}
				})
			}
		}
	}
}

func TestFragmentBoundsReleasesOnError(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("fragment=%d", failAt), func(t *testing.T) {
			message := fragmentBoundsMessage([]byte("abcdefg"))
			fragments, err := fragUDPMessage(message, message.headerSize()+3)
			if err != nil {
				t.Fatal(err)
			}
			for i, fragment := range fragments {
				if !fragment.referenced {
					t.Fatalf("fragment %d lost its pool reference", i)
				}
			}
			failure := errors.New("send failed")
			sender := &fragmentBoundsFailureQUIC{failAt: failAt, err: failure}
			c := &udpPacketConn{quicConn: sender}
			if err := c.writePackets(fragments); !errors.Is(err, failure) {
				t.Fatalf("error=%v", err)
			}
			if sender.calls != failAt {
				t.Fatalf("calls=%d", sender.calls)
			}
			// release clears referenced and all fields before returning the object to
			// the pool. A second release must be a no-op, preventing a second pool Put.
			for i, fragment := range fragments {
				if *fragment != (udpMessage{}) {
					t.Fatalf("fragment %d was not released: %+v", i, fragment)
				}
				fragment.release()
				if *fragment != (udpMessage{}) {
					t.Fatalf("fragment %d changed on second release", i)
				}
			}
			if !bytes.Equal(message.data.Bytes(), []byte("abcdefg")) {
				t.Fatal("caller payload changed")
			}
		})
	}
	t.Run("singleton-remains-owned-by-caller", func(t *testing.T) {
		message := fragmentBoundsMessage([]byte("x"))
		message.referenced = true
		defer message.release()
		failure := errors.New("send failed")
		sender := &fragmentBoundsFailureQUIC{failAt: 1, err: failure}
		c := &udpPacketConn{quicConn: sender}
		if err := c.writeFragmented(message, message.headerSize()+1); !errors.Is(err, failure) {
			t.Fatalf("error=%v", err)
		}
		if !message.referenced || !bytes.Equal(message.data.Bytes(), []byte("x")) {
			t.Fatal("caller message was released")
		}
	})
	t.Run("owned-buffer-on-write-error", func(t *testing.T) {
		sender := &fragmentBoundsFailureQUIC{failAt: 1, err: errors.New("send failed")}
		c := &udpPacketConn{ctx: context.Background(), quicConn: sender, udpMTU: fragmentBoundsMessage(nil).headerSize() + 3}
		buffer := buf.NewSize(7)
		_, _ = buffer.Write([]byte("abcdefg"))
		if err := c.WritePacket(buffer, M.ParseSocksaddr("example.org:53")); err == nil {
			t.Fatal("expected send failure")
		}
	})
}

func TestFragmentBoundsHostLength(t *testing.T) {
	for _, length := range []int{math.MaxUint16, math.MaxUint16 + 1} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			message := fragmentBoundsMessage([]byte("x"))
			message.host = strings.Repeat("x", length)
			fragments, err := fragUDPMessage(message, message.headerSize()+1)
			sender := &fragmentBoundsFailureQUIC{}
			c := &udpPacketConn{quicConn: sender}
			if length > math.MaxUint16 {
				if err == nil || fragments != nil {
					t.Fatalf("fragments=%v error=%v", fragments, err)
				}
				if err := c.writePacket(message); err == nil || sender.calls != 0 {
					t.Fatalf("error=%v calls=%d", err, sender.calls)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer releaseMessages(fragments)
			packed := message.pack()
			defer packed.Release()
			var decoded udpMessage
			if err := decodeUDPMessage(&decoded, packed.Bytes()); err != nil {
				t.Fatal(err)
			}
			if decoded.host != message.host {
				t.Fatal("host was truncated")
			}
		})
	}
}

func TestFragmentBoundsPayloadLimit(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(fmt.Sprintf("packet=%t", packet), func(t *testing.T) {
			sender := &fragmentBoundsFailureQUIC{}
			c := &udpPacketConn{ctx: context.Background(), quicConn: sender, udpMTU: 1}
			n, err := fragmentBoundsWrite(c, packet, make([]byte, 65536))
			var tooLarge *quic.DatagramTooLargeError
			if n != 0 || !errors.As(err, &tooLarge) || tooLarge.MaxDatagramPayloadSize != 65535 || sender.calls != 0 {
				t.Fatalf("n=%d error=%v calls=%d", n, err, sender.calls)
			}
		})
	}
}
