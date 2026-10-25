package tuic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

func TestStreamBudgetStressUDPBurst(t *testing.T) {
	if os.Getenv("NKR_STRESS_STREAMS") != "1" {
		t.Skip("set NKR_STRESS_STREAMS=1 to measure UDP stream burst loss")
	}
	const packets, concurrency, bursts = 1000, 200, 5
	const drain, lateArrivalGrace = time.Second, 2 * time.Second
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	serverErrors := &streamStressErrors{Logger: logger.NOP()}
	traffic := &streamStressTraffic{
		sent: make([]bool, packets*bursts), forwarded: make([]bool, packets*bursts), received: make([]bool, packets*bursts),
	}
	destination, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	serverSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverSocket.Close()
	service, err := NewService[string](ServiceOptions{
		Context: ctx, Logger: serverErrors,
		TLSConfig:  streamStressTLS{config: streamBudgetTLS(t)},
		UDPTimeout: 120 * time.Second,
		Handler:    &streamStressHandler{errors: serverErrors, ctx: ctx, traffic: traffic},
	})
	if err != nil {
		t.Fatal(err)
	}
	service.UpdateUsers([]string{"stress"}, [][16]byte{{1}}, []string{"stress-password"})
	if err = service.Start(serverSocket); err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	client, err := NewClient(ClientOptions{
		Context: ctx, Dialer: streamStressDialer{},
		ServerAddress: M.SocksaddrFromNet(serverSocket.LocalAddr()),
		TLSConfig: streamStressTLS{config: &tls.Config{
			InsecureSkipVerify: true, // Ephemeral certificate on loopback only.
			NextProtos:         []string{"stream-budget-test"},
		}},
		UUID: [16]byte{1}, Password: "stress-password",
		UDPStream: true, // Exercise packet.go's non-blocking stream relay, not datagrams.
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(net.ErrClosed)
	packetConn, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	// Suppress only teardown diagnostics; errors during the measurement are retained.
	defer serverErrors.stop()

	warmed := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		var payload [2048]byte
		warm := false
		for {
			n, _, readErr := destination.ReadFromUDP(payload[:])
			if readErr != nil {
				if ctx.Err() == nil && !errors.Is(readErr, net.ErrClosed) {
					serverErrors.record(readErr)
				}
				return
			}
			if n != 64 {
				serverErrors.record(fmt.Errorf("destination received %d bytes, want 64", n))
				continue
			}
			sequence := binary.BigEndian.Uint64(payload[:8])
			if sequence == ^uint64(0) {
				if !warm {
					close(warmed)
					warm = true
				}
			} else if sequence < uint64(len(traffic.received)) {
				traffic.mu.Lock()
				traffic.received[sequence] = true
				traffic.mu.Unlock()
			}
		}
	}()
	defer func() { destination.Close(); <-readerDone }()
	// Initialize authentication and the UDP association before concurrent traffic.
	var warmup [64]byte
	binary.BigEndian.PutUint64(warmup[:8], ^uint64(0))
	if _, err = packetConn.WriteTo(warmup[:], destination.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-warmed:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	udpConn := packetConn.(*udpPacketConn)
	opens := &streamStressOpens{Connection: udpConn.quicConn}
	udpConn.quicConn = opens // Instrument only packet opens, after the warmup.
	type result struct {
		sent, failed, writeErrors int
		first                     string
		sendTime                  time.Duration
		receivedAtDrain           int
	}
	results := make([]result, bursts)
	for burst := 0; burst < bursts; burst++ {
		opens.failed, opens.first = 0, ""
		var mu sync.Mutex
		var workers sync.WaitGroup
		start := make(chan struct{})
		for worker := 0; worker < concurrency; worker++ {
			workers.Add(1)
			go func(worker int) {
				defer workers.Done()
				<-start
				for index := worker; index < packets; index += concurrency {
					var payload [64]byte
					binary.BigEndian.PutUint64(payload[:8], uint64(burst*packets+index))
					_, writeErr := packetConn.WriteTo(payload[:], destination.LocalAddr())
					mu.Lock()
					if writeErr == nil {
						results[burst].sent++
						traffic.mu.Lock()
						traffic.sent[burst*packets+index] = true
						traffic.mu.Unlock()
					} else {
						results[burst].writeErrors++
					}
					mu.Unlock()
				}
			}(worker)
		}
		sendStarted := time.Now()
		close(start)
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		results[burst].sendTime = time.Since(sendStarted)
		results[burst].failed, results[burst].first = opens.failed, opens.first
		// Fixed drain window also allows stream credit to replenish between bursts.
		streamStressWait(t, ctx, drain)
		traffic.mu.Lock()
		for _, present := range traffic.received[burst*packets : (burst+1)*packets] {
			if present {
				results[burst].receivedAtDrain++
			}
		}
		traffic.mu.Unlock()
	}
	// Count arrivals after each burst's drain, including a final grace period for
	// burst five. Use exactly the same windows for both limit configurations.
	streamStressWait(t, ctx, lateArrivalGrace)
	traffic.mu.Lock()
	for burst, result := range results {
		received, forwarded, beforeRelayMissing, afterRelayMissing, postSendMissing := 0, 0, 0, 0, 0
		for sequence := burst * packets; sequence < (burst+1)*packets; sequence++ {
			if traffic.received[sequence] {
				received++
			}
			if traffic.forwarded[sequence] {
				forwarded++
				if !traffic.received[sequence] {
					afterRelayMissing++
				}
			}
			if traffic.sent[sequence] && !traffic.received[sequence] {
				postSendMissing++
				if !traffic.forwarded[sequence] {
					beforeRelayMissing++
				}
			}
		}
		t.Logf("burst=%d attempted=%d sent=%d open_errors=%d first_open_error=%q write_errors=%d received=%d loss=%.2f%% loss_basis=attempted open_failure_loss=%.2f%% post_send_missing=%d post_send_loss=%.2f%% non_open_write_errors=%d forwarded=%d before_relay_missing=%d after_relay_missing=%d received_at_drain=%d late_arrivals=%d send_time=%s",
			burst+1, packets, result.sent, result.failed, result.first, result.writeErrors, received,
			100*float64(packets-received)/packets, 100*float64(result.failed)/packets,
			postSendMissing, 100*float64(postSendMissing)/packets, result.writeErrors-result.failed,
			forwarded, beforeRelayMissing, afterRelayMissing, result.receivedAtDrain, received-result.receivedAtDrain, result.sendTime)
	}
	traffic.mu.Unlock()
	t.Logf("limit=%d bursts=%d concurrency=%d payload_bytes=64 total_time=%s (includes warmup, drain_per_burst=%s and final_grace=%s)",
		service.quicConfig.MaxIncomingUniStreams, bursts, concurrency, time.Since(started), drain, lateArrivalGrace)
	serverErrors.mu.Lock()
	defer serverErrors.mu.Unlock()
	for _, serverErr := range serverErrors.errors {
		t.Errorf("server-side error: %v", serverErr)
	}
}

func streamStressWait(t *testing.T, ctx context.Context, duration time.Duration) {
	t.Helper()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

// Track each sequence at the successful client write, successful relay UDP
// write, and destination read. UDP WriteTo success alone does not imply arrival.
type streamStressTraffic struct {
	mu                        sync.Mutex
	sent, forwarded, received []bool
}

type streamStressTLS struct {
	aTLS.ServerConfig
	config *tls.Config
}

func (c streamStressTLS) Config() (*tls.Config, error) { return c.config, nil }

type streamStressDialer struct{ N.Dialer }

func (streamStressDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address.String())
}

type streamStressOpens struct {
	quic.Connection
	mu     sync.Mutex
	failed int
	first  string
}

func (c *streamStressOpens) OpenUniStream() (quic.SendStream, error) {
	stream, err := c.Connection.OpenUniStream()
	if err != nil {
		c.mu.Lock()
		c.failed++
		if c.first == "" {
			c.first = err.Error()
		}
		c.mu.Unlock()
	}
	return stream, err
}

type streamStressErrors struct {
	logger.Logger
	mu      sync.Mutex
	errors  []error
	stopped bool
}

func (l *streamStressErrors) record(err error) {
	var limitErr *quic.StreamLimitReachedError
	if errors.As(err, &limitErr) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.stopped {
		l.errors = append(l.errors, err)
	}
}

func (l *streamStressErrors) Error(args ...any) {
	for _, arg := range args {
		if err, ok := arg.(error); ok {
			l.record(err)
			return
		}
	}
	l.record(fmt.Errorf("%s", fmt.Sprint(args...)))
}

func (l *streamStressErrors) stop() {
	l.mu.Lock()
	l.stopped = true
	l.mu.Unlock()
}

type streamStressHandler struct {
	errors  *streamStressErrors
	ctx     context.Context
	traffic *streamStressTraffic
}

func (h *streamStressHandler) NewConnection(_ context.Context, conn net.Conn, _ M.Metadata) error {
	defer conn.Close()
	h.errors.record(errors.New("unexpected TCP connection"))
	return nil
}

func (h *streamStressHandler) NewPacketConnection(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
	defer conn.Close()
	forward, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		h.errors.record(err)
		return err
	}
	defer forward.Close()
	buffer := buf.NewSize(2048)
	defer buffer.Release()
	for {
		buffer.Reset()
		address, readErr := conn.ReadPacket(buffer)
		if readErr != nil {
			if h.ctx.Err() == nil {
				h.errors.record(readErr)
			}
			return readErr
		}
		if _, err = forward.WriteTo(buffer.Bytes(), address.UDPAddr()); err != nil {
			h.errors.record(err)
			return err
		}
		if buffer.Len() == 64 {
			sequence := binary.BigEndian.Uint64(buffer.Bytes()[:8])
			if sequence < uint64(len(h.traffic.forwarded)) {
				h.traffic.mu.Lock()
				h.traffic.forwarded[sequence] = true
				h.traffic.mu.Unlock()
			}
		}
	}
}
