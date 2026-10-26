package hysteria

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	hyCC "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

const defaultMaxIncomingStreams = 1024

type ServiceOptions struct {
	Context       context.Context
	Logger        logger.Logger
	BrutalDebug   bool
	SendBPS       uint64
	ReceiveBPS    uint64
	XPlusPassword string
	TLSConfig     aTLS.ServerConfig
	UDPDisabled   bool
	UDPTimeout    time.Duration
	Handler       ServerHandler

	// Legacy options

	ConnReceiveWindow   uint64
	StreamReceiveWindow uint64
	MaxIncomingStreams  int64
	DisableMTUDiscovery bool
}

type ServerHandler interface {
	N.TCPConnectionHandler
	N.UDPConnectionHandler
}

// userSnapshot is immutable after publication.
type userSnapshot[U comparable] struct {
	userMap map[string]U
}

type Service[U comparable] struct {
	ctx            context.Context
	logger         logger.Logger
	brutalDebug    bool
	sendBPS        uint64
	receiveBPS     uint64
	xplusPassword  string
	tlsConfig      aTLS.ServerConfig
	quicConfig     *quic.Config
	users          atomic.Pointer[userSnapshot[U]]
	sessionsAccess sync.Mutex
	sessions       map[*serverSession[U]]struct{}
	udpDisabled    bool
	udpTimeout     time.Duration
	handler        ServerHandler
	quicListener   io.Closer
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                !options.UDPDisabled,
		MaxIncomingStreams:             defaultMaxIncomingStreams,
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
	if options.MaxIncomingStreams > 0 {
		quicConfig.MaxIncomingStreams = int64(options.MaxIncomingStreams)
	}
	if options.DisableMTUDiscovery {
		quicConfig.DisablePathMTUDiscovery = true
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{DefaultALPN})
	}
	if options.SendBPS == 0 {
		return nil, E.New("missing upload speed configuration")
	}
	if options.ReceiveBPS == 0 {
		return nil, E.New("missing download speed configuration")
	}
	return &Service[U]{
		ctx:           options.Context,
		logger:        options.Logger,
		brutalDebug:   options.BrutalDebug,
		sendBPS:       options.SendBPS,
		receiveBPS:    options.ReceiveBPS,
		xplusPassword: options.XPlusPassword,
		tlsConfig:     options.TLSConfig,
		quicConfig:    quicConfig,
		handler:       options.Handler,
		udpDisabled:   options.UDPDisabled,
		udpTimeout:    options.UDPTimeout,
	}, nil
}

// UpdateUsers publishes a complete user snapshot. Mismatched slice lengths are
// a no-op and leave the previous snapshot unchanged.
func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	if len(userList) != len(passwordList) {
		return
	}
	snapshot := &userSnapshot[U]{userMap: make(map[string]U, len(userList))}
	for i, user := range userList {
		snapshot.userMap[passwordList[i]] = user
	}
	s.users.Store(snapshot)
	s.revokeSessions()
}

// lookupUser uses one published snapshot for the entire authentication lookup.
func (s *Service[U]) lookupUser(password string) (U, bool) {
	snapshot := s.users.Load()
	if snapshot == nil {
		var zero U
		return zero, false
	}
	user, loaded := snapshot.userMap[password]
	return user, loaded
}

// sessionValid checks the immutable credential captured during authentication.
func (s *Service[U]) sessionValid(snapshot *userSnapshot[U], session *serverSession[U]) bool {
	if snapshot == nil {
		return false
	}
	user, loaded := snapshot.userMap[session.password]
	return loaded && user == session.authUser
}

func (s *Service[U]) registerSession(session *serverSession[U]) bool {
	s.sessionsAccess.Lock()
	select {
	case <-session.connDone:
		s.sessionsAccess.Unlock()
		return false
	default:
	}
	// Recheck under the sweep's lock: authentication may have used an old snapshot.
	valid := s.sessionValid(s.users.Load(), session)
	if valid {
		if s.sessions == nil {
			s.sessions = make(map[*serverSession[U]]struct{})
		}
		s.sessions[session] = struct{}{}
	}
	s.sessionsAccess.Unlock()
	if !valid {
		session.closeWithError(errUserRevoked)
	}
	return valid
}

func (s *Service[U]) unregisterSession(session *serverSession[U]) {
	s.sessionsAccess.Lock()
	delete(s.sessions, session)
	s.sessionsAccess.Unlock()
}

func (s *Service[U]) revokeSessions() {
	s.sessionsAccess.Lock()
	// A concurrent update may have superseded the snapshot we just published.
	snapshot := s.users.Load()
	var revoked []*serverSession[U]
	for session := range s.sessions {
		if !s.sessionValid(snapshot, session) {
			revoked = append(revoked, session)
		}
	}
	s.sessionsAccess.Unlock()
	for _, session := range revoked {
		// Claim only sessions still registered, so concurrent sweeps cannot
		// close the same session twice. QUIC callbacks run without this lock.
		s.sessionsAccess.Lock()
		_, registered := s.sessions[session]
		delete(s.sessions, session)
		s.sessionsAccess.Unlock()
		if registered {
			session.closeWithError(errUserRevoked)
		}
	}
}

var errUserRevoked = errors.New("user revoked")

func (s *Service[U]) Start(conn net.PacketConn) error {
	if s.xplusPassword != "" {
		conn = NewXPlusPacketConn(conn, []byte(s.xplusPassword), false)
	}
	listener, err := qtls.Listen(conn, s.tlsConfig, s.quicConfig)
	if err != nil {
		return err
	}
	s.quicListener = listener
	go s.loopConnections(listener)
	return nil
}

func (s *Service[U]) Close() error {
	return common.Close(
		s.quicListener,
	)
}

func (s *Service[U]) loopConnections(listener qtls.Listener) {
	for {
		connection, err := listener.Accept(s.ctx)
		if err != nil {
			if E.IsClosedOrCanceled(err) || errors.Is(err, quic.ErrServerClosed) {
				s.logger.Debug(E.Cause(err, "listener closed"))
			} else {
				s.logger.Error(E.Cause(err, "listener closed"))
			}
			return
		}
		session := &serverSession[U]{
			Service:    s,
			ctx:        s.ctx,
			quicConn:   connection,
			source:     M.SocksaddrFromNet(connection.RemoteAddr()),
			connDone:   make(chan struct{}),
			udpConnMap: make(map[uint32]*udpPacketConn),

			defragBudget: newDefragBudget(defragConnectionItems, defragConnectionBytes),
		}
		go session.handleConnection()
	}
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx          context.Context
	quicConn     quic.Connection
	source       M.Socksaddr
	connAccess   sync.Mutex
	connDone     chan struct{}
	connErr      error
	authUser     U
	password     string
	udpAccess    sync.RWMutex
	udpConnMap   map[uint32]*udpPacketConn
	udpSessionID uint32

	defragBudget *defragBudget
}

func (s *serverSession[U]) handleConnection() {
	s.handleConnectionTimeout(ProtocolTimeout)
}

// The timeout argument lets tests exercise the production handshake with a short budget.
func (s *serverSession[U]) handleConnectionTimeout(timeout time.Duration) {
	defer s.closeWithError(net.ErrClosed)
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()
	stop := watchHandshake(ctx, cancel, s.quicConn)
	defer stop()
	controlStream, err := s.quicConn.AcceptStream(ctx)
	if err != nil {
		s.closeWithError0(ErrorCodeProtocolError, err)
		return
	}
	deadline, _ := ctx.Deadline()
	if err = controlStream.SetDeadline(deadline); err != nil {
		s.closeWithError0(ErrorCodeProtocolError, err)
		return
	}
	clientHello, err := ReadClientHello(controlStream)
	if err != nil {
		s.closeWithError0(ErrorCodeProtocolError, E.Cause(err, "read client hello"))
		return
	}
	user, loaded := s.lookupUser(clientHello.Auth)
	if !loaded {
		WriteServerHello(controlStream, ServerHello{
			OK:      false,
			Message: "Wrong password",
		})
		s.closeWithError0(ErrorCodeAuthError, E.New("authentication failed"))
		return
	}
	err = WriteServerHello(controlStream, ServerHello{
		OK:      true,
		SendBPS: s.sendBPS,
		RecvBPS: s.receiveBPS,
	})
	if err != nil {
		s.closeWithError(err)
		return
	}
	stop()
	if err = ctx.Err(); err != nil {
		s.closeWithError0(ErrorCodeProtocolError, err)
		return
	}
	if err = controlStream.SetDeadline(time.Time{}); err != nil {
		s.closeWithError0(ErrorCodeProtocolError, err)
		return
	}
	cancel()
	s.authUser = user
	s.password = clientHello.Auth
	if !s.registerSession(s) {
		return
	}
	s.quicConn.SetCongestionControl(hyCC.NewBrutalSender(uint64(math.Min(float64(s.sendBPS), float64(clientHello.RecvBPS))), s.brutalDebug, s.logger))
	if !s.udpDisabled {
		go s.loopMessages()
	}
	s.loopStreams()
}

func (s *serverSession[U]) loopStreams() {
	for {
		stream, err := s.quicConn.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		go func() {
			err = s.handleStream(stream)
			if err != nil {
				stream.CancelRead(0)
				stream.Close()
				s.logger.Error(E.Cause(err, "handle stream request"))
			}
		}()
	}
}

func (s *serverSession[U]) handleStream(stream quic.Stream) error {
	request, err := ReadClientRequest(stream)
	if err != nil {
		return E.New("read TCP request")
	}
	ctx := auth.ContextWithUser(s.ctx, s.authUser)
	if !request.UDP {
		_ = s.handler.NewConnection(ctx, &serverConn{Stream: stream}, M.Metadata{
			Source:      s.source,
			Destination: M.ParseSocksaddrHostPort(request.Host, request.Port),
		})
	} else {
		if s.udpDisabled {
			return WriteServerResponse(stream, ServerResponse{
				OK:      false,
				Message: "UDP disabled by server",
			})
		}
		var sessionID uint32
		udpConn := newUDPPacketConn(ctx, s.quicConn, func() {
			stream.CancelRead(0)
			stream.Close()
			s.udpAccess.Lock()
			delete(s.udpConnMap, sessionID)
			s.udpAccess.Unlock()
		}, s.defragBudget)
		s.udpAccess.Lock()
		s.udpSessionID++
		sessionID = s.udpSessionID
		udpConn.sessionID = sessionID
		s.udpConnMap[sessionID] = udpConn
		s.udpAccess.Unlock()
		err = WriteServerResponse(stream, ServerResponse{
			OK:           true,
			UDPSessionID: sessionID,
		})
		if err != nil {
			udpConn.closeWithError(E.Cause(err, "write server response"))
			return err
		}
		newCtx, newConn := canceler.NewPacketConn(udpConn.ctx, udpConn, s.udpTimeout)
		go s.handler.NewPacketConnection(newCtx, newConn, M.Metadata{
			Source:      s.source,
			Destination: M.ParseSocksaddrHostPort(request.Host, request.Port),
		})
		holdBuffer := make([]byte, 1024)
		for {
			_, hErr := stream.Read(holdBuffer)
			if hErr != nil {
				break
			}
		}
		udpConn.closeWithError(E.Cause(net.ErrClosed, "hold stream closed"))
	}
	return nil
}

func (s *serverSession[U]) closeWithError(err error) {
	s.closeWithError0(ErrorCodeGeneric, err)
}

func (s *serverSession[U]) closeWithError0(errorCode int, err error) {
	defer s.unregisterSession(s)
	s.connAccess.Lock()
	select {
	case <-s.connDone:
		s.connAccess.Unlock()
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	s.connAccess.Unlock()
	if errors.Is(err, errUserRevoked) {
		_ = s.quicConn.CloseWithError(1, "user revoked")
		return
	}
	if E.IsClosedOrCanceled(err) {
		s.logger.Debug(E.Cause(err, "connection failed"))
	} else {
		s.logger.Error(E.Cause(err, "connection failed"))
	}
	switch errorCode {
	case ErrorCodeProtocolError:
		_ = s.quicConn.CloseWithError(quic.ApplicationErrorCode(errorCode), "protocol error")
	case ErrorCodeAuthError:
		_ = s.quicConn.CloseWithError(quic.ApplicationErrorCode(errorCode), "auth error")
	default:
		_ = s.quicConn.CloseWithError(quic.ApplicationErrorCode(errorCode), "")
	}
}

type serverConn struct {
	quic.Stream
	responseWritten bool
}

func (c *serverConn) HandshakeFailure(err error) error {
	if c.responseWritten {
		return os.ErrClosed
	}
	c.responseWritten = true
	return WriteServerResponse(c.Stream, ServerResponse{
		OK:      false,
		Message: err.Error(),
	})
}

func (c *serverConn) HandshakeSuccess() error {
	if c.responseWritten {
		return nil
	}
	c.responseWritten = true
	return WriteServerResponse(c.Stream, ServerResponse{
		OK: true,
	})
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, baderror.WrapQUIC(err)
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	if !c.responseWritten {
		c.responseWritten = true
		err = WriteServerResponse(c.Stream, ServerResponse{
			OK: true,
		})
		if err != nil {
			return 0, baderror.WrapQUIC(err)
		}
	}
	n, err = c.Stream.Write(p)
	return n, baderror.WrapQUIC(err)
}

func (c *serverConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}

// watchHandshake aborts pending I/O on cancellation and stops watching before a
// successful connection is handed to its long-lived owner.
func watchHandshake(ctx context.Context, cancel context.CancelFunc, conn quic.Connection) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			_ = conn.CloseWithError(ErrorCodeProtocolError, "handshake canceled")
		case <-conn.Context().Done():
			cancel()
		case <-stop:
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(stop) })
		<-done
	}
}
