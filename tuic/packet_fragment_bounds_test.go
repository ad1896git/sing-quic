package tuic

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func fragmentBoundsMessage(data []byte) *udpMessage {
	return &udpMessage{sessionID: 0x1234, packetID: 0x5678, fragmentTotal: 1, destination: M.ParseSocksaddr("example.org:53"), data: buf.As(data)}
}

func TestFragmentBoundsMTU(t *testing.T) {
	header := fragmentBoundsMessage(nil).headerSize()
	for _, payloadMTU := range []int{-1, 0, 1, header, header + 1} {
		for _, data := range [][]byte{nil, bytes.Repeat([]byte("x"), 2*(header+1)+1)} {
			t.Run(fmt.Sprintf("payload=%d/length=%d", payloadMTU, len(data)), func(t *testing.T) {
				message := fragmentBoundsMessage(data)
				fragments, err := fragUDPMessage(message, header+payloadMTU)
				if payloadMTU <= 0 {
					if err == nil || fragments != nil {
						t.Fatalf("invalid MTU: fragments=%v error=%v", fragments, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer releaseMessages(fragments)
				var joined []byte
				for _, fragment := range fragments {
					if fragment.data.Len() > payloadMTU {
						t.Fatal("fragment exceeds payload MTU")
					}
					joined = append(joined, fragment.data.Bytes()...)
				}
				if !bytes.Equal(joined, data) {
					t.Fatalf("payload changed: %x", joined)
				}
			})
		}
	}
	// Also reject negative/zero packet limits, including subtraction overflow.
	for _, limit := range []int{-int(^uint(0)>>1) - 1, -1, 0, header - 1, header} {
		fragments, err := fragUDPMessage(fragmentBoundsMessage([]byte("x")), limit)
		if err == nil || fragments != nil {
			t.Fatalf("packet limit %d: fragments=%v error=%v", limit, fragments, err)
		}
	}
}

func TestFragmentBoundsCount(t *testing.T) {
	for _, count := range []int{255, 256} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			message := fragmentBoundsMessage(bytes.Repeat([]byte("x"), count))
			fragments, err := fragUDPMessage(message, message.headerSize()+1)
			if count == 256 {
				if err == nil || fragments != nil {
					t.Fatalf("overflow: fragments=%v error=%v", fragments, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer releaseMessages(fragments)
			if len(fragments) != count {
				t.Fatalf("got %d fragments", len(fragments))
			}
			for i, fragment := range fragments {
				if fragment.fragmentID != uint8(i) || fragment.fragmentTotal != 255 || !bytes.Equal(fragment.data.Bytes(), []byte("x")) {
					t.Fatalf("invalid fragment %d: %+v", i, fragment)
				}
			}
		})
	}
}

func TestFragmentBoundsWire(t *testing.T) {
	// Captured by running the unmodified splitter and packer at parent 4eb6bdd.
	tests := []struct {
		payloadMTU int
		want       []string
	}{
		{2, []string{"05021234567804000002000b6578616d706c652e6f726700356162", "05021234567804010002ff6364", "05021234567804020002ff6566", "05021234567804030001ff67"}},
		{4, []string{"05021234567802000004000b6578616d706c652e6f7267003561626364", "05021234567802010003ff656667"}},
		{20, []string{"05021234567801000007000b6578616d706c652e6f7267003561626364656667"}},
	}
	for _, test := range tests {
		t.Run(fmt.Sprint(test.payloadMTU), func(t *testing.T) {
			message := fragmentBoundsMessage([]byte("abcdefg"))
			fragments, err := fragUDPMessage(message, message.headerSize()+test.payloadMTU)
			if err != nil {
				t.Fatal(err)
			}
			defer releaseMessages(fragments)
			if len(fragments) != len(test.want) {
				t.Fatalf("got %d fragments", len(fragments))
			}
			for i, fragment := range fragments {
				packed := fragment.pack()
				got := hex.EncodeToString(packed.Bytes())
				packed.Release()
				if got != test.want[i] {
					t.Fatalf("fragment %d: got %s, want %s", i, got, test.want[i])
				}
			}
		})
	}
}

type fragmentBoundsQUIC struct {
	quic.Connection
	calls       int
	rejectLimit int
	packets     [][]byte
}

func (c *fragmentBoundsQUIC) SendDatagram(data []byte) error {
	c.calls++
	if c.rejectLimit != 0 && c.calls == 1 {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(c.rejectLimit)}
	}
	c.packets = append(c.packets, append([]byte(nil), data...))
	return nil
}

func fragmentBoundsWrite(c *udpPacketConn, packet bool, data []byte) (int, error) {
	destination := M.ParseSocksaddr("example.org:53")
	if packet {
		err := c.WritePacket(buf.As(data), destination)
		if err != nil {
			return 0, err
		}
		return len(data), nil
	}
	return c.WriteTo(data, destination)
}

func TestFragmentBoundsRetry(t *testing.T) {
	header := fragmentBoundsMessage(nil).headerSize()
	for _, packet := range []bool{false, true} {
		// Exercise both an initial single datagram and an initial fragmented write.
		for _, initialMTU := range []int{1200, header + 4} {
			t.Run(fmt.Sprintf("packet=%t/mtu=%d", packet, initialMTU), func(t *testing.T) {
				sender := &fragmentBoundsQUIC{rejectLimit: header + 3 + 3}
				c := &udpPacketConn{ctx: context.Background(), quicConn: sender, udpMTU: initialMTU}
				data := []byte("abcdefg")
				n, err := fragmentBoundsWrite(c, packet, data)
				if err != nil || n != len(data) {
					t.Fatalf("write: n=%d error=%v", n, err)
				}
				if sender.calls != 4 || len(sender.packets) != 3 {
					t.Fatalf("calls=%d packets=%d", sender.calls, len(sender.packets))
				}
				var joined []byte
				for i, wire := range sender.packets {
					var message udpMessage
					if err := decodeUDPMessage(&message, wire[2:]); err != nil {
						t.Fatal(err)
					}
					if message.fragmentID != uint8(i) || message.fragmentTotal != 3 {
						t.Fatalf("invalid retry fragment: %+v", message)
					}
					joined = append(joined, message.data.Bytes()...)
				}
				if !bytes.Equal(joined, data) {
					t.Fatalf("retry payload changed: %x", joined)
				}
			})
		}
	}
}

func TestFragmentBoundsWriteErrors(t *testing.T) {
	header := fragmentBoundsMessage(nil).headerSize()
	for _, packet := range []bool{false, true} {
		for _, retry := range []bool{false, true} {
			for _, test := range []struct {
				name          string
				limit, length int
			}{
				{"negative", header - 1, 1}, {"zero", header, 1}, {"empty", header, 0}, {"count", header + 1, 256},
			} {
				t.Run(fmt.Sprintf("packet=%t/retry=%t/%s", packet, retry, test.name), func(t *testing.T) {
					sender := &fragmentBoundsQUIC{}
					c := &udpPacketConn{ctx: context.Background(), quicConn: sender, udpMTU: test.limit}
					wantCalls := 0
					if retry {
						c.udpMTU = 1200
						sender.rejectLimit = test.limit + 3
						wantCalls = 1
					}
					n, err := fragmentBoundsWrite(c, packet, bytes.Repeat([]byte("x"), test.length))
					if err == nil || n != 0 || sender.calls != wantCalls || len(sender.packets) != 0 {
						t.Fatalf("n=%d error=%v calls=%d packets=%d", n, err, sender.calls, len(sender.packets))
					}
				})
			}
		}
	}
}
