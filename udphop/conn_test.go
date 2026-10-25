package udphop

import (
	"errors"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func hopGoroutines() int {
	stack := make([]byte, 1<<20)
	n := runtime.Stack(stack, true)
	return strings.Count(string(stack[:n]), "github.com/sagernet/sing-quic/udphop.(*udpHopPacketConn).hopLoop(") +
		strings.Count(string(stack[:n]), "github.com/sagernet/sing-quic/udphop.(*udpHopPacketConn).recvLoop(")
}

func waitHopGoroutines(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if hopGoroutines() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("hop goroutines = %d, want %d", hopGoroutines(), want)
}

func TestCloseStopsHopGoroutines(t *testing.T) {
	baseline := hopGoroutines()
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	pc, err := NewUDPHopPacketConn("127.0.0.1", strconv.Itoa(server.LocalAddr().(*net.UDPAddr).Port), 5*time.Second, func() (net.PacketConn, error) {
		return net.ListenPacket("udp", "127.0.0.1:0")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	waitHopGoroutines(t, baseline+2)
	// Rotate without waiting for the minimum five-second hop interval.
	pc.(*udpHopPacketConn).hop()
	waitHopGoroutines(t, baseline+3)
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	waitHopGoroutines(t, baseline)
	if _, _, err := pc.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom after Close = %v, want net.ErrClosed", err)
	}
}

type timeoutPacketConn struct {
	net.PacketConn
	read chan struct{}
}

func (c *timeoutPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	close(c.read)
	return 0, nil, &net.DNSError{IsTimeout: true}
}

func TestCloseUnblocksTimeoutWithFullQueue(t *testing.T) {
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	pc := &udpHopPacketConn{
		currentConn: socket,
		recvQueue:   make(chan *udpPacket, 1),
		closeChan:   make(chan struct{}),
		bufPool: sync.Pool{New: func() interface{} {
			buf := make([]byte, udpBufferSize)
			return &buf
		}},
	}
	pc.recvQueue <- &udpPacket{}
	reader := &timeoutPacketConn{read: make(chan struct{})}
	done := make(chan struct{})
	go func() { pc.recvLoop(reader); close(done) }()
	select {
	case <-reader.read:
	case <-time.After(time.Second):
		t.Fatal("receive loop did not start")
	}
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("receive loop blocked on full queue after Close")
	}
}
