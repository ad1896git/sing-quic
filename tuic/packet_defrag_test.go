package tuic

import (
	"bytes"
	"context"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func defragLengthMessage(packetID uint16, total, id uint8, data []byte) *udpMessage {
	message := allocMessage()
	message.sessionID = 7
	message.packetID = packetID
	message.fragmentTotal = total
	message.fragmentID = id
	message.destination = M.ParseSocksaddr("127.0.0.1:53")
	message.data = buf.NewSize(len(data))
	copy(message.data.Extend(len(data)), data)
	return message
}

func TestDefragLengthBoundaries(t *testing.T) {
	for _, test := range []struct {
		name   string
		first  int
		second int
		accept bool
	}{
		{"Exactly65535", 32768, 32767, true},
		{"Exactly65536", 32768, 32768, false},
		{"Two40000", 40000, 40000, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := newUDPDefragger(nil)
			defer d.close()
			firstData := bytes.Repeat([]byte{1}, test.first)
			secondData := bytes.Repeat([]byte{2}, test.second)
			first := defragLengthMessage(1, 2, 0, firstData)
			second := defragLengthMessage(1, 2, 1, secondData)
			buffers := []*buf.Buffer{first.data, second.data}
			if got := d.feed(first); got != nil {
				got.releaseMessage()
				t.Fatal("incomplete packet delivered")
			}
			got := d.feed(second)
			if got != nil {
				defer got.releaseMessage()
			}
			if (got != nil) != test.accept {
				t.Fatalf("accepted = %v, want %v", got != nil, test.accept)
			}
			if got != nil {
				if !bytes.Equal(got.data.Bytes(), append(firstData, secondData...)) {
					t.Fatal("reassembled payload differs")
				}
				if got.sessionID != 7 || got.packetID != 1 || got.destination != M.ParseSocksaddr("127.0.0.1:53") {
					t.Fatal("reassembled metadata differs")
				}
			}
			for i, buffer := range buffers {
				if buffer.Len() != 0 {
					t.Errorf("fragment %d buffer was not released", i)
				}
			}
			if len(d.packetMap) != 0 {
				t.Fatal("completed reassembly retained fragments")
			}
		})
	}
}

func TestDefragLengthOutOfOrderAndDuplicate(t *testing.T) {
	d := newUDPDefragger(nil)
	defer d.close()
	if got := d.feed(defragLengthMessage(1, 3, 2, []byte("third"))); got != nil {
		got.releaseMessage()
		t.Fatal("incomplete packet delivered")
	}
	duplicate := defragLengthMessage(1, 3, 2, []byte("ignored"))
	duplicateBuffer := duplicate.data
	if got := d.feed(duplicate); got != nil {
		got.releaseMessage()
		t.Fatal("duplicate completed packet")
	}
	if duplicateBuffer.Len() != 0 {
		t.Fatal("duplicate buffer was not released")
	}
	if got := d.feed(defragLengthMessage(1, 3, 0, []byte("first"))); got != nil {
		got.releaseMessage()
		t.Fatal("incomplete packet delivered after duplicate")
	}
	got := d.feed(defragLengthMessage(1, 3, 1, []byte("second")))
	if got == nil {
		t.Fatal("complete packet rejected")
	}
	defer got.releaseMessage()
	if string(got.data.Bytes()) != "firstsecondthird" {
		t.Fatalf("unexpected payload %q", got.data.Bytes())
	}
}

func TestDefragLengthZeroFragments(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"AllZero", nil},
		{"Mixed", []byte("payload")},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := newUDPDefragger(nil)
			defer d.close()
			d.feed(defragLengthMessage(1, 3, 0, nil))
			d.feed(defragLengthMessage(1, 3, 1, test.data))
			got := d.feed(defragLengthMessage(1, 3, 2, nil))
			if got != nil {
				defer got.releaseMessage()
			}
			if len(test.data) == 0 {
				if got != nil {
					t.Fatal("all-zero reassembly should be dropped")
				}
			} else if got == nil || !bytes.Equal(got.data.Bytes(), test.data) {
				t.Fatal("mixed zero/nonzero reassembly differs")
			}
		})
	}
	message := defragLengthMessage(2, 1, 0, nil)
	got := newUDPDefragger(nil).feed(message)
	if got != message {
		t.Fatal("unfragmented empty packet should pass through")
	}
	got.releaseMessage()
}

func TestDefragLengthSessionAfterRejection(t *testing.T) {
	conn := newUDPPacketConn(context.Background(), nil, false, true, nil, nil)
	defer conn.defragger.close()
	conn.inputPacket(defragLengthMessage(1, 2, 0, make([]byte, 40000)))
	conn.inputPacket(defragLengthMessage(1, 2, 1, make([]byte, 40000)))
	if len(conn.data) != 0 {
		t.Fatal("oversized packet delivered")
	}
	// Verify that a rejected packet ID can be reused.
	conn.inputPacket(defragLengthMessage(1, 2, 0, []byte("normal")))
	conn.inputPacket(defragLengthMessage(1, 2, 1, []byte(" packet")))
	conn.inputPacket(defragLengthMessage(2, 1, 0, []byte("next")))
	for _, want := range []string{"normal packet", "next"} {
		select {
		case got := <-conn.data:
			payload := string(got.data.Bytes())
			sessionID := got.sessionID
			got.releaseMessage()
			if payload != want || sessionID != 7 {
				t.Fatalf("delivered session %d payload %q, want session 7 payload %q", sessionID, payload, want)
			}
		default:
			t.Fatalf("packet %q was not delivered", want)
		}
	}
}
