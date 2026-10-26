package hysteria

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	hyCC "github.com/sagernet/sing-quic/hysteria/congestion"
	hop "github.com/sagernet/sing-quic/udphop"
	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ClientOptions struct {
	Context       context.Context
	Dialer        N.Dialer
	Logger        logger.Logger
	BrutalDebug   bool
	ServerAddress M.Socksaddr
	SendBPS       uint64
	ReceiveBPS    uint64
	XPlusPassword string
	Password      string
	TLSConfig     aTLS.Config
	UDPDisabled   bool

	HopPorts    string
	HopInterval int

	// Legacy options

	ConnReceiveWindow   uint64
	StreamReceiveWindow uint64
	DisableMTUDiscovery bool
}

type Client struct {
	ctx           context.Context
	dialer        N.Dialer
	logger        logger.Logger
	brutalDebug   bool
	serverAddr    M.Socksaddr
	sendBPS       uint64
	receiveBPS    uint64
	xplusPassword string
	password      string
	tlsConfig     aTLS.Config
	quicConfig    *quic.Config
	udpDisabled   bool
	hopPorts      string
	hopInterval   time.Duration

	connAccess sync.RWMutex
	conn       *clientQUICConnection // guarded by connAccess
}

func NewClient(options ClientOptions) (*Client, error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     DefaultConnReceiveWindow,
		MaxIdleTimeout:                 DefaultMaxIdleTimeout,
		KeepAlivePeriod:                DefaultKeepAlivePeriod,
	}
	if options.StreamReceiveWindow != 0 {
		quicConfig.InitialStreamReceiveWindow = options.StreamReceiveWindow
		quicConfig.MaxStreamReceiveWindow = options.StreamReceiveWindow
	}
	if options.ConnReceiveWindow != 0 {
		quicConfig.InitialConnectionReceiveWindow = options.ConnReceiveWindow
		quicConfig.MaxConnectionReceiveWindow = options.ConnReceiveWindow
	}
	if options.DisableMTUDiscovery {
		quicConfig.DisablePathMTUDiscovery = true
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{DefaultALPN})
	}
	if options.SendBPS == 0 {
		return nil, E.New("missing upload speed")
	} else if options.SendBPS < MinSpeedBPS {
		return nil, E.New("invalid upload speed")
	}
	if options.ReceiveBPS == 0 {
		return nil, E.New("missing download speed")
	} else if options.ReceiveBPS < MinSpeedBPS {
		return nil, E.New("invalid download speed")
	}
	if options.HopInterval < 5 {
		options.HopInterval = 5
	}
	return &Client{
		ctx:           options.Context,
		dialer:        options.Dialer,
		logger:        options.Logger,
		brutalDebug:   options.BrutalDebug,
		serverAddr:    options.ServerAddress,
		sendBPS:       options.SendBPS,
		receiveBPS:    options.ReceiveBPS,
		xplusPassword: options.XPlusPassword,
		password:      options.Password,
		tlsConfig:     options.TLSConfig,
		quicConfig:    quicConfig,
		udpDisabled:   options.UDPDisabled,
		hopPorts:      options.HopPorts,
		hopInterval:   time.Duration(options.HopInterval) * time.Second,
	}, nil
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	for {
		c.connAccess.RLock()
		conn := c.conn
		active := conn != nil && conn.active()
		c.connAccess.RUnlock()
		if active {
			return conn, nil
		}
		// Finalise the stale connection without extending the publication lock.
		if conn != nil {
			conn.closeWithError(context.Cause(conn.quicConn.Context()))
		}
		c.connAccess.Lock()
		if c.conn != conn {
			c.connAccess.Unlock()
			continue
		}
		newConn, err := c.offerNew(ctx)
		if err != nil {
			c.connAccess.Unlock()
			return nil, err
		}
		// Publish only after initialization, while excluding CloseWithError.
		c.conn = newConn
		c.connAccess.Unlock()
		return newConn, nil
	}
}

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	ctx, cancel := context.WithTimeout(ctx, ProtocolTimeout)
	defer cancel()
	// Client shutdown also cancels setup, without giving the request ownership
	// of the established connection's lifetime.
	go func() {
		select {
		case <-c.ctx.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	udpConn, err := c.dialer.DialContext(ctx, "udp", c.serverAddr)
	if err != nil {
		return nil, err
	}
	rawConn := io.Closer(udpConn)
	var packetConn net.PacketConn
	var quicConn quic.Connection
	initialized := false
	defer func() {
		if !initialized {
			if quicConn != nil {
				_ = quicConn.CloseWithError(0, "")
			}
			if packetConn != nil {
				_ = packetConn.Close()
			}
			if rawConn != nil {
				_ = rawConn.Close()
			}
		}
	}()
	if c.hopPorts != "" {
		packetConn, err = hop.NewUDPHopPacketConn(c.serverAddr.AddrString(), c.hopPorts, c.hopInterval, func() (net.PacketConn, error) {
			return c.dialer.ListenPacket(c.ctx, c.serverAddr)
		})
		if err != nil {
			return nil, fmt.Errorf("hop.NewUDPHopPacketConn: %w", err)
		}
	} else {
		packetConn = bufio.NewUnbindPacketConn(udpConn)
		// The packet connection owns udpConn on the non-hop path.
		rawConn = nil
	}
	if c.xplusPassword != "" {
		packetConn = NewXPlusPacketConn(packetConn, []byte(c.xplusPassword), c.hopPorts != "")
	}
	quicConn, err = qtls.Dial(ctx, packetConn, udpConn.RemoteAddr(), c.tlsConfig, c.quicConfig)
	if err != nil {
		return nil, err
	}
	stop := watchHandshake(ctx, cancel, quicConn)
	defer stop()
	controlStream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	err = WriteClientHello(controlStream, ClientHello{
		SendBPS: c.sendBPS,
		RecvBPS: c.receiveBPS,
		Auth:    c.password,
	})
	if err != nil {
		return nil, err
	}
	serverHello, err := ReadServerHello(controlStream)
	if err != nil {
		return nil, err
	}
	if !serverHello.OK {
		return nil, E.New("remote error: ", serverHello.Message)
	}
	stop()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	quicConn.SetCongestionControl(hyCC.NewBrutalSender(uint64(math.Min(float64(serverHello.RecvBPS), float64(c.sendBPS))), c.brutalDebug, c.logger))
	conn := &clientQUICConnection{
		quicConn:    quicConn,
		rawConn:     rawConn,
		packetConn:  packetConn,
		connDone:    make(chan struct{}),
		udpDisabled: !quicConn.ConnectionState().SupportsDatagrams,
		udpConnMap:  make(map[uint32]*udpPacketConn),

		defragBudget: newDefragBudget(defragConnectionItems, defragConnectionBytes),
	}
	if !c.udpDisabled {
		go c.loopMessages(conn)
	}
	initialized = true
	go func() {
		select {
		case <-quicConn.Context().Done():
			conn.closeWithError(context.Cause(quicConn.Context()))
		case <-c.ctx.Done():
			conn.closeWithError(context.Cause(c.ctx))
		}
	}()
	return conn, nil
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &clientConn{
		Stream:      stream,
		destination: destination,
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if c.udpDisabled {
		return nil, os.ErrInvalid
	}
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	if conn.udpDisabled {
		return nil, E.New("UDP disabled by server")
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	buffer := WriteClientRequest(ClientRequest{
		UDP:  true,
		Host: destination.AddrString(),
		Port: destination.Port,
	}, nil)
	_, err = stream.Write(buffer.Bytes())
	buffer.Release()
	if err != nil {
		stream.Close()
		return nil, err
	}
	response, err := ReadServerResponse(stream)
	if err != nil {
		stream.Close()
		return nil, err
	}
	if !response.OK {
		stream.Close()
		return nil, E.New("remote error: ", response.Message)
	}
	conn.udpAccess.Lock()
	if debug.Enabled {
		if _, connExists := conn.udpConnMap[response.UDPSessionID]; connExists {
			conn.udpAccess.Unlock()
			stream.CancelRead(0)
			stream.Close()
			return nil, E.New("udp session id duplicated")
		}
	}
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, func() {
		stream.CancelRead(0)
		stream.Close()
		conn.udpAccess.Lock()
		delete(conn.udpConnMap, response.UDPSessionID)
		conn.udpAccess.Unlock()
	}, conn.defragBudget)
	conn.udpConnMap[response.UDPSessionID] = clientPacketConn
	conn.udpAccess.Unlock()
	clientPacketConn.sessionID = response.UDPSessionID
	go func() {
		holdBuffer := make([]byte, 1024)
		for {
			_, hErr := stream.Read(holdBuffer)
			if hErr != nil {
				break
			}
		}
		clientPacketConn.closeWithError(E.Cause(net.ErrClosed, "hold stream closed"))
	}()
	return clientPacketConn, nil
}

func (c *Client) CloseWithError(err error) error {
	// Wait for any in-flight creation and close it before allowing reconnect.
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	conn := c.conn
	if conn != nil {
		conn.closeWithError(err)
	}
	return nil
}

type clientQUICConnection struct {
	quicConn    quic.Connection
	rawConn     io.Closer
	packetConn  net.PacketConn
	closeOnce   sync.Once
	connDone    chan struct{}
	connErr     error
	udpDisabled bool
	udpAccess   sync.RWMutex
	udpConnMap  map[uint32]*udpPacketConn

	defragBudget *defragBudget
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	default:
	}
	select {
	case <-c.connDone:
		return false
	default:
	}
	return true
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.connErr = err
		close(c.connDone)
		_ = c.quicConn.CloseWithError(0, "")
		if c.packetConn != nil {
			_ = c.packetConn.Close()
		}
		if c.rawConn != nil {
			_ = c.rawConn.Close()
		}
	})
}

type clientConn struct {
	quic.Stream
	destination    M.Socksaddr
	requestWritten bool
	responseRead   bool
}

func (c *clientConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *clientConn) Read(p []byte) (n int, err error) {
	if c.responseRead {
		n, err = c.Stream.Read(p)
		return n, baderror.WrapQUIC(err)
	}
	response, err := ReadServerResponse(c.Stream)
	if err != nil {
		return 0, baderror.WrapQUIC(err)
	}
	if !response.OK {
		err = E.New("remote error: ", response.Message)
		return
	}
	c.responseRead = true
	n, err = c.Stream.Read(p)
	return n, baderror.WrapQUIC(err)
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if !c.requestWritten {
		buffer := WriteClientRequest(ClientRequest{
			UDP:  false,
			Host: c.destination.AddrString(),
			Port: c.destination.Port,
		}, p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return
		}
		c.requestWritten = true
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, baderror.WrapQUIC(err)
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}
