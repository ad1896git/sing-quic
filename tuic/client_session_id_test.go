package tuic

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/sagernet/quic-go"
)

type sessionIDQUIC struct {
	quic.Connection
}

func (sessionIDQUIC) Context() context.Context { return context.Background() }
func (sessionIDQUIC) OpenUniStream() (quic.SendStream, error) {
	return nil, errors.New("test connection has no streams")
}

func newSessionIDClient() (*Client, *clientQUICConnection) {
	conn := &clientQUICConnection{
		quicConn:   sessionIDQUIC{},
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint16]*udpPacketConn),
	}
	return &Client{conn: conn}, conn
}

func listenSessionID(t *testing.T, client *Client) *udpPacketConn {
	t.Helper()
	packetConn, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })
	return packetConn.(*udpPacketConn)
}

func fillSessionIDs(conn *clientQUICConnection) {
	for id := 0; id < 1<<16; id++ {
		conn.udpConnMap[uint16(id)] = &udpPacketConn{sessionID: uint16(id)}
	}
}

func TestUDPSessionIDWrap(t *testing.T) {
	client, conn := newSessionIDClient()
	live := listenSessionID(t, client)
	if live.sessionID != 0 {
		t.Fatalf("initial session ID = %d, want 0", live.sessionID)
	}
	conn.udpSessionID = math.MaxUint16
	last := listenSessionID(t, client)
	if last.sessionID != math.MaxUint16 {
		t.Fatalf("session ID = %d, want %d", last.sessionID, math.MaxUint16)
	}
	next := listenSessionID(t, client)
	if conn.udpConnMap[0] != live {
		t.Fatal("wrap allocation overwrote live session 0")
	}
	if next.sessionID != 1 || conn.udpConnMap[1] != next || len(conn.udpConnMap) != 3 {
		t.Fatalf("wrap allocation ID = %d, map size = %d; want ID 1 and 3 sessions", next.sessionID, len(conn.udpConnMap))
	}
}

func TestUDPSessionIDExhaustion(t *testing.T) {
	client, conn := newSessionIDClient()
	fillSessionIDs(conn)
	live := conn.udpConnMap[0]
	packetConn, err := client.ListenPacket(context.Background())
	if packetConn != nil || err == nil || err.Error() != "UDP session ID space exhausted" {
		t.Fatalf("ListenPacket = (%v, %v), want nil and exhaustion error", packetConn, err)
	}
	if len(conn.udpConnMap) != 1<<16 || conn.udpConnMap[0] != live {
		t.Fatal("exhaustion changed the live session map")
	}
}

func TestUDPSessionIDReuseFreed(t *testing.T) {
	client, conn := newSessionIDClient()
	fillSessionIDs(conn)
	if packetConn, err := client.ListenPacket(context.Background()); packetConn != nil || err == nil {
		t.Fatalf("full map allocation = (%v, %v), want exhaustion", packetConn, err)
	}
	const freedID = 12345
	delete(conn.udpConnMap, freedID)
	packetConn := listenSessionID(t, client)
	if packetConn.sessionID != freedID || conn.udpConnMap[freedID] != packetConn || len(conn.udpConnMap) != 1<<16 {
		t.Fatalf("reused ID = %d, map size = %d; want ID %d and full map", packetConn.sessionID, len(conn.udpConnMap), freedID)
	}
	if err := packetConn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, exists := conn.udpConnMap[freedID]; exists {
		t.Fatal("closing current session did not free its ID")
	}
}

func TestUDPSessionIDOldClose(t *testing.T) {
	client, conn := newSessionIDClient()
	old := listenSessionID(t, client)
	// Simulate retirement without Close, then reuse while its owner still holds
	// the old object. Its delayed destroy callback must preserve the replacement.
	delete(conn.udpConnMap, old.sessionID)
	conn.udpSessionID = old.sessionID
	replacement := listenSessionID(t, client)
	if replacement.sessionID != old.sessionID {
		t.Fatal("test did not reuse the old ID")
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if conn.udpConnMap[replacement.sessionID] != replacement {
		t.Fatal("old session close deleted the replacement")
	}
}

func TestUDPSessionIDConcurrent(t *testing.T) {
	client, conn := newSessionIDClient()
	live := listenSessionID(t, client)
	conn.udpSessionID = math.MaxUint16 - 4
	const workers, perWorker = 8, 128
	created := make(chan *udpPacketConn, workers*perWorker)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < perWorker; i++ {
				packetConn, err := client.ListenPacket(context.Background())
				if err != nil {
					t.Error(err)
					return
				}
				created <- packetConn.(*udpPacketConn)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(created)
	seen := map[uint16]bool{live.sessionID: true}
	for packetConn := range created {
		packetConn := packetConn
		t.Cleanup(func() { _ = packetConn.Close() })
		if seen[packetConn.sessionID] {
			t.Errorf("duplicate session ID %d", packetConn.sessionID)
		}
		seen[packetConn.sessionID] = true
		if conn.udpConnMap[packetConn.sessionID] != packetConn {
			t.Errorf("session %d was overwritten", packetConn.sessionID)
		}
	}
	if len(conn.udpConnMap) != workers*perWorker+1 || conn.udpConnMap[0] != live {
		t.Fatalf("map size = %d, want %d with original session 0 intact", len(conn.udpConnMap), workers*perWorker+1)
	}
}
