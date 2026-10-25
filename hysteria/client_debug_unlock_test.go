//go:build debug

package hysteria

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	M "github.com/sagernet/sing/common/metadata"
)

type duplicateSessionQUIC struct {
	quic.Connection
	ctx     context.Context
	streams []*duplicateSessionStream
	next    int
}

func (q *duplicateSessionQUIC) Context() context.Context { return q.ctx }

func (q *duplicateSessionQUIC) OpenStream() (quic.Stream, error) {
	if q.next == len(q.streams) {
		return nil, io.EOF
	}
	stream := q.streams[q.next]
	q.next++
	return stream, nil
}

type duplicateSessionStream struct {
	quic.Stream
	response *bytes.Reader
	readDone chan struct{}
	once     sync.Once
	closed   atomic.Bool
}

func (s *duplicateSessionStream) Read(p []byte) (int, error) {
	if s.response.Len() > 0 {
		return s.response.Read(p)
	}
	// Keep the session registered until the client cancels its hold stream.
	<-s.readDone
	return 0, net.ErrClosed
}

func (s *duplicateSessionStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *duplicateSessionStream) Close() error {
	s.closed.Store(true)
	return nil
}
func (s *duplicateSessionStream) CancelRead(quic.StreamErrorCode) {
	s.once.Do(func() { close(s.readDone) })
}

func TestDuplicateUDPSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := &duplicateSessionQUIC{ctx: ctx}
	for _, id := range []uint32{1, 1, 2} {
		response := make([]byte, 7)
		response[0] = 1
		binary.BigEndian.PutUint32(response[1:5], id)
		stream := &duplicateSessionStream{response: bytes.NewReader(response), readDone: make(chan struct{})}
		q.streams = append(q.streams, stream)
		defer stream.CancelRead(0)
	}
	conn := &clientQUICConnection{
		quicConn:   q,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*udpPacketConn),
	}
	client := &Client{ctx: ctx, conn: conn}
	listen := func() (net.PacketConn, error) {
		t.Helper()
		type result struct {
			conn net.PacketConn
			err  error
		}
		done := make(chan result, 1)
		go func() {
			packetConn, err := client.ListenPacket(ctx, M.Socksaddr{})
			done <- result{packetConn, err}
		}()
		select {
		case r := <-done:
			return r.conn, r.err
		case <-time.After(5 * time.Second):
			t.Fatal("ListenPacket blocked: udpAccess was not released")
			return nil, nil
		}
	}

	first, err := listen()
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := listen()
	if duplicate != nil || err == nil || !strings.Contains(err.Error(), "udp session id duplicated") {
		t.Fatalf("duplicate session = (%v, %v), want nil connection and duplicate-ID error", duplicate, err)
	}
	// A new session on this same connection must still acquire udpAccess.
	third, err := listen()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	defer third.Close()
	if !q.streams[1].closed.Load() {
		t.Error("duplicate session's stream write side was not closed")
	}
	select {
	case <-q.streams[1].readDone:
	default:
		t.Error("duplicate session's stream read side was not canceled")
	}
	conn.udpAccess.RLock()
	defer conn.udpAccess.RUnlock()
	if len(conn.udpConnMap) != 2 || conn.udpConnMap[1] != first || conn.udpConnMap[2] != third {
		t.Error("duplicate rejection did not preserve the original session and register the following session")
	}
}
