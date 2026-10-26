package hysteria2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing-quic/hysteria"
	hyCC "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/baderror"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"
)

const defaultMaxIncomingStreams = 1024

type ServiceOptions struct {
	Context               context.Context
	Logger                logger.Logger
	BrutalDebug           bool
	SendBPS               uint64
	ReceiveBPS            uint64
	IgnoreClientBandwidth bool
	SalamanderPassword    string
	TLSConfig             aTLS.ServerConfig
	UDPDisabled           bool
	UDPTimeout            time.Duration
	Handler               ServerHandler
	MasqueradeHandler     http.Handler
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
	ctx                   context.Context
	logger                logger.Logger
	brutalDebug           bool
	sendBPS               uint64
	receiveBPS            uint64
	ignoreClientBandwidth bool
	salamanderPassword    string
	tlsConfig             aTLS.ServerConfig
	quicConfig            *quic.Config
	users                 atomic.Pointer[userSnapshot[U]]
	sessionsAccess        sync.Mutex
	sessions              map[*serverSession[U]]struct{}
	udpDisabled           bool
	udpTimeout            time.Duration
	handler               ServerHandler
	masqueradeHandler     http.Handler
	quicListener          io.Closer
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                !options.UDPDisabled,
		MaxIncomingStreams:             defaultMaxIncomingStreams,
		InitialStreamReceiveWindow:     hysteria.DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         hysteria.DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: hysteria.DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     hysteria.DefaultConnReceiveWindow,
		MaxIdleTimeout:                 hysteria.DefaultMaxIdleTimeout,
		KeepAlivePeriod:                hysteria.DefaultKeepAlivePeriod,
	}
	if options.MasqueradeHandler == nil {
		options.MasqueradeHandler = http.NotFoundHandler()
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	return &Service[U]{
		ctx:                   options.Context,
		logger:                options.Logger,
		brutalDebug:           options.BrutalDebug,
		sendBPS:               options.SendBPS,
		receiveBPS:            options.ReceiveBPS,
		ignoreClientBandwidth: options.IgnoreClientBandwidth,
		salamanderPassword:    options.SalamanderPassword,
		tlsConfig:             options.TLSConfig,
		quicConfig:            quicConfig,
		udpDisabled:           options.UDPDisabled,
		udpTimeout:            options.UDPTimeout,
		handler:               options.Handler,
		masqueradeHandler:     options.MasqueradeHandler,
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
	if s.salamanderPassword != "" {
		conn = NewSalamanderConn(conn, []byte(s.salamanderPassword), false)
	}
	err := qtls.ConfigureHTTP3(s.tlsConfig)
	if err != nil {
		return err
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
		go s.handleConnection(connection)
	}
}

func (s *Service[U]) handleConnection(connection quic.Connection) {
	session := &serverSession[U]{
		Service:    s,
		ctx:        s.ctx,
		quicConn:   connection,
		source:     M.SocksaddrFromNet(connection.RemoteAddr()),
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*udpPacketConn),

		defragBudget: newDefragBudget(defragConnectionItems, defragConnectionBytes),
	}
	httpServer := http3.Server{
		Handler:        session,
		StreamHijacker: session.handleStream0,
	}
	_ = httpServer.ServeQUICConn(connection)
	session.closeWithError(net.ErrClosed)
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx        context.Context
	quicConn   quic.Connection
	source     M.Socksaddr
	connAccess sync.Mutex
	connDone   chan struct{}
	connErr    error
	// authAccess guards publication and all HTTP/TCP reads of authentication.
	// authUser is immutable after publication, before the UDP loop starts.
	authAccess    sync.Mutex
	authenticated bool
	authUser      U
	password      string
	udpAccess     sync.RWMutex
	udpConnMap    map[uint32]*udpPacketConn

	defragBudget *defragBudget
}

func (s *serverSession[U]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Host == protocol.URLHost && r.URL.Path == protocol.URLPath {
		s.authAccess.Lock()
		if s.authenticated {
			s.authAccess.Unlock()
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !s.udpDisabled,
				Rx:         s.receiveBPS,
				RxAuto:     s.ignoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			return
		}
		request := protocol.AuthRequestFromHeader(r.Header)
		user, loaded := s.lookupUser(request.Auth)
		if !loaded {
			s.authAccess.Unlock()
			s.masqueradeHandler.ServeHTTP(w, r)
			return
		}
		s.authUser = user
		s.password = request.Auth
		s.authenticated = true
		s.authAccess.Unlock()
		if !s.registerSession(s) {
			return
		}
		// Only the handler that published authentication performs session setup.
		if !s.ignoreClientBandwidth && request.Rx > 0 {
			rx := request.Rx
			if s.sendBPS > 0 && rx > s.sendBPS {
				rx = s.sendBPS
			}
			s.quicConn.SetCongestionControl(hyCC.NewBrutalSender(rx, s.brutalDebug, s.logger))
		} else {
			timeFunc := ntp.TimeFuncFromContext(s.ctx)
			if timeFunc == nil {
				timeFunc = time.Now
			}
			s.quicConn.SetCongestionControl(congestion_meta2.NewBbrSender(
				congestion_meta2.DefaultClock{TimeFunc: timeFunc},
				congestion.ByteCount(s.quicConn.Config().InitialPacketSize),
				congestion.ByteCount(congestion_meta1.InitialCongestionWindow),
			))
		}
		protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
			UDPEnabled: !s.udpDisabled,
			Rx:         s.receiveBPS,
			RxAuto:     s.ignoreClientBandwidth,
		})
		w.WriteHeader(protocol.StatusAuthOK)
		if s.ctx.Done() != nil {
			go func() {
				select {
				case <-s.ctx.Done():
					s.closeWithError(s.ctx.Err())
				case <-s.connDone:
				}
			}()
		}
		if !s.udpDisabled {
			go s.loopMessages()
		}
	} else {
		s.masqueradeHandler.ServeHTTP(w, r)
	}
}

func (s *serverSession[U]) handleStream0(frameType http3.FrameType, id quic.ConnectionTracingID, stream quic.Stream, err error) (bool, error) {
	s.authAccess.Lock()
	authenticated := s.authenticated
	s.authAccess.Unlock()
	if !authenticated || err != nil {
		return false, nil
	}
	if frameType != protocol.FrameTypeTCPRequest {
		return false, nil
	}
	go func() {
		hErr := s.handleStream(stream)
		stream.CancelRead(0)
		stream.Close()
		if hErr != nil {
			stream.CancelRead(0)
			stream.Close()
			s.logger.Error(E.Cause(hErr, "handle stream request"))
		}
	}()
	return true, nil
}

func (s *serverSession[U]) handleStream(stream quic.Stream) error {
	destinationString, err := protocol.ReadTCPRequest(stream)
	if err != nil {
		return E.New("read TCP request")
	}
	s.authAccess.Lock()
	user := s.authUser
	s.authAccess.Unlock()
	ctx := auth.ContextWithUser(s.ctx, user)
	_ = s.handler.NewConnection(ctx, &serverConn{Stream: stream}, M.Metadata{
		Source:      s.source,
		Destination: M.ParseSocksaddr(destinationString),
	})
	return nil
}

func (s *serverSession[U]) closeWithError(err error) {
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
	_ = s.quicConn.CloseWithError(0, "")
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
	buffer, writeErr := protocol.WriteTCPResponse(false, err.Error(), nil)
	if writeErr != nil {
		return writeErr
	}
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *serverConn) HandshakeSuccess() error {
	if c.responseWritten {
		return nil
	}
	c.responseWritten = true
	buffer, err := protocol.WriteTCPResponse(true, "", nil)
	if err != nil {
		return err
	}
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, baderror.WrapQUIC(err)
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	if !c.responseWritten {
		c.responseWritten = true
		buffer, err := protocol.WriteTCPResponse(true, "", p)
		if err != nil {
			return 0, baderror.WrapQUIC(err)
		}
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return 0, baderror.WrapQUIC(err)
		}
		return len(p), nil
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
