package hysteria

import (
	"bytes"
	"container/list"
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
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
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
	host          string
	port          uint16
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
		binary.Write(buffer, binary.BigEndian, uint16(len(m.host))),
		common.Error(buffer.WriteString(m.host)),
		binary.Write(buffer, binary.BigEndian, m.port),
		binary.Write(buffer, binary.BigEndian, m.packetID),
		binary.Write(buffer, binary.BigEndian, m.fragmentID),
		binary.Write(buffer, binary.BigEndian, m.fragmentTotal),
		binary.Write(buffer, binary.BigEndian, uint16(m.data.Len())),
		common.Error(buffer.Write(m.data.Bytes())),
	)
	return buffer
}

func (m *udpMessage) headerSize() int {
	return 14 + len(m.host)
}

func fragUDPMessage(message *udpMessage, maxPacketSize int) ([]*udpMessage, error) {
	if len(message.host) > math.MaxUint16 {
		return nil, errors.New("UDP host length exceeds 65535 bytes")
	}
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
		fragment.referenced = true
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

func newUDPPacketConn(ctx context.Context, quicConn quic.Connection, onDestroy func(), budget *defragBudget) *udpPacketConn {
	ctx, cancel := common.ContextWithCancelCause(ctx)
	return &udpPacketConn{
		ctx:       ctx,
		cancel:    cancel,
		quicConn:  quicConn,
		data:      make(chan *udpMessage, 64),
		udpMTU:    1200 - 3,
		defragger: newUDPDefragger(budget),
		onDestroy: onDestroy,
	}
}

func (c *udpPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		_, err = buffer.ReadOnceFrom(p.data)
		destination = M.ParseSocksaddrHostPort(p.host, p.port)
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
		destination := M.ParseSocksaddrHostPort(pkt.host, pkt.port)
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
	if buffer.Len() > 0xffff {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 0xffff}
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	*message = udpMessage{
		sessionID:     c.sessionID,
		packetID:      packetId,
		fragmentTotal: 1,
		host:          destination.AddrString(),
		port:          destination.Port,
		data:          buffer,
		referenced:    true,
	}
	defer message.release()
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
	return c.retryFragmented(message, tooLargeErr.MaxDatagramPayloadSize)
}

func (c *udpPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	default:
	}
	if len(p) > 0xffff {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 0xffff}
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	destination := M.SocksaddrFromNet(addr)
	*message = udpMessage{
		sessionID:     c.sessionID,
		packetID:      packetId,
		fragmentTotal: 1,
		host:          destination.AddrString(),
		port:          destination.Port,
		data:          buf.As(p),
		referenced:    true,
	}
	defer message.release()
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
	err = c.retryFragmented(message, tooLargeErr.MaxDatagramPayloadSize)
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

func (c *udpPacketConn) retryFragmented(message *udpMessage, maxDatagramPayloadSize int64) error {
	// Validate before subtraction and conversion to int, including on 32-bit hosts.
	if maxDatagramPayloadSize <= 3 || maxDatagramPayloadSize-3 <= int64(message.headerSize()) || maxDatagramPayloadSize-3 > int64(math.MaxInt) {
		return errors.New("UDP payload MTU must be positive")
	}
	maxPacketSize := int(maxDatagramPayloadSize - 3)
	return c.writeFragmented(message, maxPacketSize)
}

func (c *udpPacketConn) writeFragmented(message *udpMessage, maxPacketSize int) error {
	fragments, err := fragUDPMessage(message, maxPacketSize)
	if err != nil {
		return err
	}
	// The caller owns the original message, including across retries.
	if len(fragments) == 1 && fragments[0] == message {
		return c.writePacket(message)
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
	if len(message.host) > math.MaxUint16 {
		return errors.New("UDP host length exceeds 65535 bytes")
	}
	buffer := message.pack()
	defer buffer.Release()
	return c.quicConn.SendDatagram(buffer.Bytes())
}

func (c *udpPacketConn) Close() error {
	c.closeWithError(os.ErrClosed)
	return nil
}

func (c *udpPacketConn) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.cancel(err)
		c.defragger.close()
		c.onDestroy()
	})
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

const (
	defragSessionItems    = 256
	defragSessionBytes    = 1 << 20
	defragConnectionItems = 4096
	defragConnectionBytes = 8 << 20
	defragMessageBytes    = 65535
)

// defragBudget is shared by every UDP session on one QUIC connection.
// Lock ordering is udpDefragger.access followed by defragBudget.access.
type defragBudget struct {
	access             sync.Mutex
	items, bytes       int
	maxItems, maxBytes int
	lifetime           time.Duration // Immutable after construction; tests may shorten it.
}

func newDefragBudget(maxItems, maxBytes int) *defragBudget {
	return &defragBudget{maxItems: maxItems, maxBytes: maxBytes, lifetime: 10 * time.Second}
}

func (b *defragBudget) reserve(items, bytes int) bool {
	b.access.Lock()
	defer b.access.Unlock()
	if b.items+items > b.maxItems || b.bytes+bytes > b.maxBytes {
		return false
	}
	b.items += items
	b.bytes += bytes
	return true
}

func (b *defragBudget) release(items, bytes int) {
	b.access.Lock()
	defer b.access.Unlock()
	b.items -= items
	b.bytes -= bytes
}

type udpDefragger struct {
	// access protects all state and receive-side fragment ownership.
	access    sync.Mutex
	packetMap map[uint16]*packetItem
	queue     list.List
	bytes     int
	budget    *defragBudget
	now       func() time.Time
	closed    bool
}

func newUDPDefragger(budget *defragBudget) *udpDefragger {
	if budget == nil {
		budget = newDefragBudget(defragConnectionItems, defragConnectionBytes)
	}
	return &udpDefragger{packetMap: make(map[uint16]*packetItem), budget: budget, now: time.Now}
}

type packetItem struct {
	packetID uint16
	messages []*udpMessage
	count    uint8
	deadline time.Time
	timer    *time.Timer
	bytes    int
	element  *list.Element
}

// remove returns the item's reservations exactly once. access must be held.
func (d *udpDefragger) remove(item *packetItem) {
	if item.timer != nil {
		item.timer.Stop()
		item.timer = nil
	}
	delete(d.packetMap, item.packetID)
	d.queue.Remove(item.element)
	d.bytes -= item.bytes
	d.budget.release(1, item.bytes)
	item.bytes = 0
	for _, message := range item.messages {
		if message != nil {
			message.releaseMessage()
		}
	}
	item.messages = nil
	item.count = 0
}

func (d *udpDefragger) close() {
	d.access.Lock()
	defer d.access.Unlock()
	d.closed = true
	for d.queue.Len() > 0 {
		d.remove(d.queue.Front().Value.(*packetItem))
	}
}

// expire also handles callbacks already running when remove stops the timer.
func (d *udpDefragger) expire(item *packetItem) {
	d.access.Lock()
	defer d.access.Unlock()
	if !d.closed && d.packetMap[item.packetID] == item {
		d.remove(item)
	}
}

func (d *udpDefragger) feed(m *udpMessage) *udpMessage {
	var created *packetItem
	d.access.Lock()
	defer func() {
		d.access.Unlock()
		if created == nil {
			return
		}
		// AfterFunc must run without either lock held. Removal or even expiry
		// may win the race to install the timer, so recheck under access.
		timer := time.AfterFunc(d.budget.lifetime, func() { d.expire(created) })
		d.access.Lock()
		if !d.closed && d.packetMap[created.packetID] == created {
			created.timer = timer
		} else {
			timer.Stop()
		}
		d.access.Unlock()
	}()
	now := d.now()
	for front := d.queue.Front(); front != nil; front = d.queue.Front() {
		item := front.Value.(*packetItem)
		if now.Before(item.deadline) {
			break
		}
		d.remove(item)
	}
	if d.closed {
		m.releaseMessage()
		return nil
	}
	if m.fragmentTotal <= 1 {
		return m
	}
	if m.fragmentID >= m.fragmentTotal {
		m.releaseMessage()
		return nil
	}
	item := d.packetMap[m.packetID]
	if item != nil && int(m.fragmentTotal) != len(item.messages) {
		d.remove(item)
		item = nil
	}
	if item != nil && item.messages[m.fragmentID] != nil {
		m.releaseMessage()
		return nil
	}
	size := m.data.Len()
	if size > defragMessageBytes || (item != nil && item.bytes+size > defragMessageBytes) {
		if item != nil {
			d.remove(item)
		}
		m.releaseMessage()
		return nil
	}
	newItems := 0
	if item == nil {
		newItems = 1
	}
	if len(d.packetMap)+newItems > defragSessionItems || d.bytes+size > defragSessionBytes || !d.budget.reserve(newItems, size) {
		m.releaseMessage()
		return nil
	}
	if item == nil {
		item = &packetItem{packetID: m.packetID, messages: make([]*udpMessage, m.fragmentTotal), deadline: now.Add(10 * time.Second)}
		item.element = d.queue.PushBack(item)
		d.packetMap[m.packetID] = item
		created = item
	}
	d.bytes += size
	item.bytes += size
	item.messages[m.fragmentID] = m
	item.count++
	if int(item.count) != len(item.messages) {
		return nil
	}
	defer d.remove(item)
	newMessage := allocMessage()
	newMessage.sessionID = m.sessionID
	newMessage.packetID = m.packetID
	newMessage.host = item.messages[0].host
	newMessage.port = item.messages[0].port
	if item.bytes > 0 {
		newMessage.data = buf.NewSize(item.bytes)
		for _, message := range item.messages {
			newMessage.data.Write(message.data.Bytes())
		}
		return newMessage
	}
	newMessage.release()
	return nil
}

func decodeUDPMessage(message *udpMessage, data []byte) error {
	reader := bytes.NewReader(data)
	err := binary.Read(reader, binary.BigEndian, &message.sessionID)
	if err != nil {
		return err
	}
	var hostLen uint16
	err = binary.Read(reader, binary.BigEndian, &hostLen)
	if err != nil {
		return err
	}
	hostBytes := make([]byte, hostLen)
	_, err = io.ReadFull(reader, hostBytes)
	if err != nil {
		return err
	}
	message.host = string(hostBytes)
	err = binary.Read(reader, binary.BigEndian, &message.port)
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
	var dataLen uint16
	err = binary.Read(reader, binary.BigEndian, &dataLen)
	if err != nil {
		return err
	}
	if reader.Len() != int(dataLen) {
		return E.New("invalid data length")
	}
	message.data = buf.As(data[len(data)-reader.Len():])
	return nil
}
