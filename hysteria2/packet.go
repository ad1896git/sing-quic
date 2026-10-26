package hysteria2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/quicvarint"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/cache"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var udpMessagePool = sync.Pool{
	New: func() interface{} {
		return new(udpMessage)
	},
}

func allocMessage() *udpMessage {
	message := udpMessagePool.Get().(*udpMessage)
	message.referenced = true
	return message
}

func releaseMessages(messages []*udpMessage) {
	for _, message := range messages {
		if message != nil {
			message.release()
		}
	}
}

type udpMessage struct {
	sessionID     uint32
	packetID      uint16
	fragmentID    uint8
	fragmentTotal uint8
	destination   string
	data          *buf.Buffer
	referenced    bool
}

func (m *udpMessage) release() {
	if !m.referenced {
		return
	}
	*m = udpMessage{}
	udpMessagePool.Put(m)
}

func (m *udpMessage) releaseMessage() {
	m.data.Release()
	m.release()
}

func (m *udpMessage) pack() *buf.Buffer {
	buffer := buf.NewSize(m.headerSize() + m.data.Len())
	common.Must(
		binary.Write(buffer, binary.BigEndian, m.sessionID),
		binary.Write(buffer, binary.BigEndian, m.packetID),
		binary.Write(buffer, binary.BigEndian, m.fragmentID),
		binary.Write(buffer, binary.BigEndian, m.fragmentTotal),
		protocol.WriteVString(buffer, m.destination),
		common.Error(buffer.Write(m.data.Bytes())),
	)
	return buffer
}

func (m *udpMessage) headerSize() int {
	return 8 + int(quicvarint.Len(uint64(len(m.destination)))) + len(m.destination)
}

func fragUDPMessage(message *udpMessage, maxPacketSize int) ([]*udpMessage, error) {
	// Check before subtraction so even a negative packet limit cannot overflow.
	if maxPacketSize <= message.headerSize() {
		return nil, errors.New("UDP payload MTU must be positive")
	}
	udpMTU := maxPacketSize - message.headerSize()
	if message.data.Len() <= udpMTU {
		return []*udpMessage{message}, nil
	}
	// Subtract first to avoid overflow when rounding up the fragment count.
	fragmentTotal := 1 + (message.data.Len()-1)/udpMTU
	if fragmentTotal > math.MaxUint8 {
		return nil, errors.New("UDP message requires more than 255 fragments")
	}
	fragments := make([]*udpMessage, 0, fragmentTotal)
	originPacket := message.data.Bytes()
	for remaining := len(originPacket); remaining > 0; remaining -= udpMTU {
		fragment := allocMessage()
		*fragment = *message
		if remaining > udpMTU {
			fragment.data = buf.As(originPacket[:udpMTU])
			originPacket = originPacket[udpMTU:]
		} else {
			fragment.data = buf.As(originPacket)
			originPacket = nil
		}
		fragments = append(fragments, fragment)
	}
	for index, fragment := range fragments {
		fragment.fragmentID = uint8(index)
		fragment.fragmentTotal = uint8(fragmentTotal)
		/*if index > 0 {
			fragment.destination = ""
			// not work in hysteria
		}*/
	}
	return fragments, nil
}

type udpPacketConn struct {
	ctx             context.Context
	cancel          common.ContextCancelCauseFunc
	sessionID       uint32
	quicConn        quic.Connection
	data            chan *udpMessage
	udpMTU          int
	packetId        atomic.Uint32
	closeOnce       sync.Once
	defragger       *udpDefragger
	onDestroy       func()
	readWaitOptions N.ReadWaitOptions
}

func newUDPPacketConn(ctx context.Context, quicConn quic.Connection, onDestroy func()) *udpPacketConn {
	ctx, cancel := common.ContextWithCancelCause(ctx)
	return &udpPacketConn{
		ctx:       ctx,
		cancel:    cancel,
		quicConn:  quicConn,
		data:      make(chan *udpMessage, 64),
		udpMTU:    1200 - 3,
		defragger: newUDPDefragger(),
		onDestroy: onDestroy,
	}
}

func (c *udpPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		_, err = buffer.ReadOnceFrom(p.data)
		destination = M.ParseSocksaddr(p.destination)
		p.releaseMessage()
		return
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	}
}

func (c *udpPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case pkt := <-c.data:
		n = copy(p, pkt.data.Bytes())
		destination := M.ParseSocksaddr(pkt.destination)
		if destination.IsFqdn() {
			addr = destination
		} else {
			addr = destination.UDPAddr()
		}
		pkt.releaseMessage()
		return n, addr, nil
	case <-c.ctx.Done():
		return 0, nil, io.ErrClosedPipe
	}
}

func (c *udpPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	select {
	case <-c.ctx.Done():
		return net.ErrClosed
	default:
	}
	if buffer.Len() > protocol.MaxUDPSize {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: protocol.MaxUDPSize}
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	*message = udpMessage{
		sessionID:     c.sessionID,
		packetID:      packetId,
		fragmentTotal: 1,
		destination:   destination.String(),
		data:          buffer,
	}
	defer message.releaseMessage()
	var err error
	if c.udpMTU <= message.headerSize() || buffer.Len() > c.udpMTU-message.headerSize() {
		err = c.writeFragmented(message, c.udpMTU)
	} else {
		err = c.writePacket(message)
	}
	if err == nil {
		return nil
	}
	var tooLargeErr *quic.DatagramTooLargeError
	if !errors.As(err, &tooLargeErr) {
		return err
	}
	return c.writeFragmented(message, int(tooLargeErr.MaxDatagramPayloadSize)-3)
}

func (c *udpPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	default:
	}
	if len(p) > protocol.MaxUDPSize {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: protocol.MaxUDPSize}
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	*message = udpMessage{
		sessionID:     c.sessionID,
		packetID:      packetId,
		fragmentTotal: 1,
		destination:   addr.String(),
		data:          buf.As(p),
	}
	if c.udpMTU <= message.headerSize() || len(p) > c.udpMTU-message.headerSize() {
		err = c.writeFragmented(message, c.udpMTU)
		if err == nil {
			return len(p), nil
		}
	} else {
		err = c.writePacket(message)
	}
	if err == nil {
		return len(p), nil
	}
	var tooLargeErr *quic.DatagramTooLargeError
	if !errors.As(err, &tooLargeErr) {
		return
	}
	err = c.writeFragmented(message, int(tooLargeErr.MaxDatagramPayloadSize)-3)
	if err == nil {
		return len(p), nil
	}
	return
}

func (c *udpPacketConn) inputPacket(message *udpMessage) {
	if message.fragmentTotal <= 1 {
		select {
		case c.data <- message:
		default:
		}
	} else {
		newMessage := c.defragger.feed(message)
		if newMessage != nil {
			select {
			case c.data <- newMessage:
			default:
			}
		}
	}
}

func (c *udpPacketConn) writeFragmented(message *udpMessage, maxPacketSize int) error {
	fragments, err := fragUDPMessage(message, maxPacketSize)
	if err != nil {
		return err
	}
	return c.writePackets(fragments)
}

func (c *udpPacketConn) writePackets(messages []*udpMessage) error {
	defer releaseMessages(messages)
	for _, message := range messages {
		err := c.writePacket(message)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *udpPacketConn) writePacket(message *udpMessage) error {
	buffer := message.pack()
	defer buffer.Release()
	return c.quicConn.SendDatagram(buffer.Bytes())
}

func (c *udpPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeWithError(os.ErrClosed)
		c.onDestroy()
	})
	return nil
}

func (c *udpPacketConn) closeWithError(err error) {
	c.cancel(err)
}

func (c *udpPacketConn) LocalAddr() net.Addr {
	return c.quicConn.LocalAddr()
}

func (c *udpPacketConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *udpPacketConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *udpPacketConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *udpPacketConn) ReaderMTU() int {
	return protocol.MaxUDPSize
}

func (c *udpPacketConn) WriterMTU() int {
	return protocol.MaxUDPSize
}

type udpDefragger struct {
	// access protects all cache operations and receive-side fragment ownership.
	access    sync.Mutex
	packetMap *cache.LruCache[uint16, *packetItem]
}

func newUDPDefragger() *udpDefragger {
	return &udpDefragger{
		packetMap: cache.New(
			cache.WithAge[uint16, *packetItem](10),
			cache.WithUpdateAgeOnGet[uint16, *packetItem](),
			cache.WithEvict[uint16, *packetItem](func(key uint16, value *packetItem) {
				// sing v0.4.1 evicts synchronously during cache operations; it has no janitor.
				// feed holds udpDefragger.access before taking the cache lock.
				// Do not lock here: the callback already runs under both locks.
				value.releaseMessages()
			}),
		),
	}
}

type packetItem struct {
	messages []*udpMessage
	count    uint8
}

// releaseMessages releases owned receive buffers. The defragger mutex must be held.
func (p *packetItem) releaseMessages() {
	for _, message := range p.messages {
		if message != nil {
			message.releaseMessage()
		}
	}
	p.messages = nil
	p.count = 0
}

func (d *udpDefragger) feed(m *udpMessage) *udpMessage {
	d.access.Lock()
	defer d.access.Unlock()
	if m.fragmentTotal <= 1 {
		return m
	}
	if m.fragmentID >= m.fragmentTotal {
		m.releaseMessage()
		return nil
	}
	item, _ := d.packetMap.LoadOrStore(m.packetID, newPacketItem)
	if int(m.fragmentTotal) != len(item.messages) {
		item.releaseMessages()
		item.messages = make([]*udpMessage, m.fragmentTotal)
		item.count = 1
		item.messages[m.fragmentID] = m
		return nil
	}
	if item.messages[m.fragmentID] != nil {
		m.releaseMessage()
		return nil
	}
	item.messages[m.fragmentID] = m
	item.count++
	if int(item.count) != len(item.messages) {
		return nil
	}
	defer item.releaseMessages()
	newMessage := allocMessage()
	newMessage.sessionID = m.sessionID
	newMessage.packetID = m.packetID
	newMessage.destination = item.messages[0].destination
	var finalLength int
	for _, message := range item.messages {
		finalLength += message.data.Len()
	}
	if finalLength > 0 {
		newMessage.data = buf.NewSize(finalLength)
		for _, message := range item.messages {
			newMessage.data.Write(message.data.Bytes())
		}
		return newMessage
	}
	newMessage.release()
	return nil
}

func newPacketItem() *packetItem {
	return new(packetItem)
}

func decodeUDPMessage(message *udpMessage, data []byte) error {
	reader := bytes.NewReader(data)
	err := binary.Read(reader, binary.BigEndian, &message.sessionID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.packetID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentTotal)
	if err != nil {
		return err
	}
	message.destination, err = protocol.ReadVString(reader)
	if err != nil {
		return err
	}
	message.data = buf.As(data[len(data)-reader.Len():])
	return nil
}
