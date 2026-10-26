package tuic

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
	sessionID     uint16
	packetID      uint16
	fragmentTotal uint8
	fragmentID    uint8
	destination   M.Socksaddr
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
		buffer.WriteByte(Version),
		buffer.WriteByte(CommandPacket),
		binary.Write(buffer, binary.BigEndian, m.sessionID),
		binary.Write(buffer, binary.BigEndian, m.packetID),
		binary.Write(buffer, binary.BigEndian, m.fragmentTotal),
		binary.Write(buffer, binary.BigEndian, m.fragmentID),
		binary.Write(buffer, binary.BigEndian, uint16(m.data.Len())),
		AddressSerializer.WriteAddrPort(buffer, m.destination),
		common.Error(buffer.Write(m.data.Bytes())),
	)
	return buffer
}

func (m *udpMessage) headerSize() int {
	return 10 + AddressSerializer.AddrPortLen(m.destination)
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
		if index > 0 {
			fragment.destination = M.Socksaddr{}
		}
	}
	return fragments, nil
}

var (
	_ N.NetPacketConn    = (*udpPacketConn)(nil)
	_ N.PacketReadWaiter = (*udpPacketConn)(nil)
)

type udpPacketConn struct {
	ctx             context.Context
	cancel          common.ContextCancelCauseFunc
	sessionID       uint16
	quicConn        quic.Connection
	data            chan *udpMessage
	udpStream       bool
	udpMTU          int
	packetId        atomic.Uint32
	closeOnce       sync.Once
	isServer        bool
	defragger       *udpDefragger
	onDestroy       func()
	readWaitOptions N.ReadWaitOptions
}

func newUDPPacketConn(ctx context.Context, quicConn quic.Connection, udpStream bool, isServer bool, onDestroy func(), budget *defragBudget) *udpPacketConn {
	ctx, cancel := common.ContextWithCancelCause(ctx)
	return &udpPacketConn{
		ctx:       ctx,
		cancel:    cancel,
		quicConn:  quicConn,
		data:      make(chan *udpMessage, 64),
		udpStream: udpStream,
		isServer:  isServer,
		defragger: newUDPDefragger(budget),
		onDestroy: onDestroy,
		udpMTU:    1200 - 3,
	}
}

func (c *udpPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		_, err = buffer.ReadOnceFrom(p.data)
		destination = p.destination
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
		if pkt.destination.IsFqdn() {
			addr = pkt.destination
		} else {
			addr = pkt.destination.UDPAddr()
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
	if !destination.IsValid() {
		return E.New("invalid destination address")
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	*message = udpMessage{
		sessionID:     c.sessionID,
		packetID:      packetId,
		fragmentTotal: 1,
		destination:   destination,
		data:          buffer,
		referenced:    true,
	}
	defer message.release()
	var err error
	if !c.udpStream && (c.udpMTU <= message.headerSize() || buffer.Len() > c.udpMTU-message.headerSize()) {
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
	destination := M.SocksaddrFromNet(addr)
	if !destination.IsValid() {
		return 0, E.New("invalid destination address")
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	*message = udpMessage{
		sessionID:     c.sessionID,
		packetID:      packetId,
		fragmentTotal: 1,
		destination:   destination,
		data:          buf.As(p),
		referenced:    true,
	}
	defer message.release()
	if !c.udpStream && (c.udpMTU <= message.headerSize() || len(p) > c.udpMTU-message.headerSize()) {
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
	c.udpMTU = maxPacketSize
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
	if !c.udpStream {
		buffer := message.pack()
		err := c.quicConn.SendDatagram(buffer.Bytes())
		buffer.Release()
		if err != nil {
			return err
		}
	} else {
		stream, err := c.quicConn.OpenUniStream()
		if err != nil {
			return err
		}
		buffer := message.pack()
		_, err = stream.Write(buffer.Bytes())
		buffer.Release()
		stream.Close()
		if err != nil {
			return err
		}
	}
	return nil
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
	c.defragger.close()
	if !c.isServer {
		buffer := buf.NewSize(4)
		defer buffer.Release()
		buffer.WriteByte(Version)
		buffer.WriteByte(CommandDissociate)
		binary.Write(buffer, binary.BigEndian, c.sessionID)
		sendStream, openErr := c.quicConn.OpenUniStream()
		if openErr != nil {
			return
		}
		defer sendStream.Close()
		sendStream.Write(buffer.Bytes())
	}
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
	if item.bytes == 0 {
		return nil
	}
	newMessage := allocMessage()
	*newMessage = *item.messages[0]
	newMessage.data = buf.NewSize(item.bytes)
	for _, message := range item.messages {
		n, err := newMessage.data.Write(message.data.Bytes())
		if err != nil || n != message.data.Len() {
			newMessage.releaseMessage()
			return nil
		}
	}
	return newMessage
}

func readUDPMessage(message *udpMessage, reader io.Reader) error {
	err := binary.Read(reader, binary.BigEndian, &message.sessionID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.packetID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentTotal)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentID)
	if err != nil {
		return err
	}
	var dataLength uint16
	err = binary.Read(reader, binary.BigEndian, &dataLength)
	if err != nil {
		return err
	}
	message.destination, err = AddressSerializer.ReadAddrPort(reader)
	if err != nil {
		return err
	}
	message.data = buf.NewSize(int(dataLength))
	_, err = message.data.ReadFullFrom(reader, message.data.FreeLen())
	if err != nil {
		return err
	}
	return nil
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
	err = binary.Read(reader, binary.BigEndian, &message.fragmentTotal)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentID)
	if err != nil {
		return err
	}
	var dataLength uint16
	err = binary.Read(reader, binary.BigEndian, &dataLength)
	if err != nil {
		return err
	}
	message.destination, err = AddressSerializer.ReadAddrPort(reader)
	if err != nil {
		return err
	}
	if reader.Len() != int(dataLength) {
		return io.ErrUnexpectedEOF
	}
	message.data = buf.As(data[len(data)-reader.Len():])
	return nil
}
