package tuic

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/gofrs/uuid/v5"
)

const (
	defaultMaxIncomingStreams = 1024
	tombstoneTTL              = 30 * time.Second
	maxTombstones             = 256
	maxUDPSessions            = 4096
)

type ServiceOptions struct {
	Context           context.Context
	Logger            logger.Logger
	TLSConfig         aTLS.ServerConfig
	CongestionControl string
	AuthTimeout       time.Duration
	ZeroRTTHandshake  bool
	Heartbeat         time.Duration
	UDPTimeout        time.Duration
	Handler           ServiceHandler
}

type ServiceHandler interface {
	N.TCPConnectionHandler
	N.UDPConnectionHandler
}

// userSnapshot is immutable after publication.
type userSnapshot[U comparable] struct {
	userMap     map[[16]byte]U
	passwordMap map[U]string
}

type Service[U comparable] struct {
	ctx               context.Context
	logger            logger.Logger
	tlsConfig         aTLS.ServerConfig
	heartbeat         time.Duration
	quicConfig        *quic.Config
	users             atomic.Pointer[userSnapshot[U]]
	sessionsAccess    sync.Mutex
	sessions          map[*serverSession[U]]struct{}
	congestionControl string
	authTimeout       time.Duration
	udpTimeout        time.Duration
	handler           ServiceHandler

	quicListener io.Closer
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	if options.AuthTimeout == 0 {
		options.AuthTimeout = 3 * time.Second
	}
	if options.Heartbeat == 0 {
		options.Heartbeat = 10 * time.Second
	}
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:         true,
		Allow0RTT:               options.ZeroRTTHandshake,
		MaxIncomingStreams:      defaultMaxIncomingStreams,
		MaxIncomingUniStreams:   defaultMaxIncomingStreams,
	}
	switch options.CongestionControl {
	case "":
		options.CongestionControl = "cubic"
	case "cubic", "new_reno", "bbr":
	default:
		return nil, E.New("unknown congestion control algorithm: ", options.CongestionControl)
	}
	return &Service[U]{
		ctx:               options.Context,
		logger:            options.Logger,
		tlsConfig:         options.TLSConfig,
		heartbeat:         options.Heartbeat,
		quicConfig:        quicConfig,
		congestionControl: options.CongestionControl,
		authTimeout:       options.AuthTimeout,
		udpTimeout:        options.UDPTimeout,
		handler:           options.Handler,
	}, nil
}

// UpdateUsers publishes a complete user snapshot. Mismatched slice lengths are
// a no-op and leave the previous snapshot unchanged.
func (s *Service[U]) UpdateUsers(userList []U, uuidList [][16]byte, passwordList []string) {
	if len(userList) != len(uuidList) || len(userList) != len(passwordList) {
		return
	}
	snapshot := &userSnapshot[U]{userMap: make(map[[16]byte]U, len(userList)), passwordMap: make(map[U]string, len(userList))}
	for index, user := range userList {
		snapshot.userMap[uuidList[index]] = user
		snapshot.passwordMap[user] = passwordList[index]
	}
	s.users.Store(snapshot)
	s.revokeSessions()
}

// sessionValid checks the immutable credential captured during authentication.
func (s *Service[U]) sessionValid(snapshot *userSnapshot[U], session *serverSession[U]) bool {
	if snapshot == nil {
		return false
	}
	user, loaded := snapshot.userMap[session.uuid]
	password, passwordLoaded := snapshot.passwordMap[session.authUser]
	return loaded && user == session.authUser && passwordLoaded && password == session.password
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
	if !s.quicConfig.Allow0RTT {
		listener, err := qtls.Listen(conn, s.tlsConfig, s.quicConfig)
		if err != nil {
			return err
		}
		s.quicListener = listener
		go func() {
			for {
				connection, hErr := listener.Accept(s.ctx)
				if hErr != nil {
					if E.IsClosedOrCanceled(hErr) || errors.Is(hErr, quic.ErrServerClosed) {
						s.logger.Debug(E.Cause(hErr, "listener closed"))
					} else {
						s.logger.Error(E.Cause(hErr, "listener closed"))
					}
					return
				}
				go s.handleConnection(connection)
			}
		}()
	} else {
		listener, err := qtls.ListenEarly(conn, s.tlsConfig, s.quicConfig)
		if err != nil {
			return err
		}
		s.quicListener = listener
		go func() {
			for {
				connection, hErr := listener.Accept(s.ctx)
				if hErr != nil {
					if E.IsClosedOrCanceled(hErr) || errors.Is(hErr, quic.ErrServerClosed) {
						s.logger.Debug(E.Cause(hErr, "listener closed"))
					} else {
						s.logger.Error(E.Cause(hErr, "listener closed"))
					}
					return
				}
				go s.handleConnection(connection)
			}
		}()
	}
	return nil
}

func (s *Service[U]) Close() error {
	return common.Close(
		s.quicListener,
	)
}

func (s *Service[U]) handleConnection(connection quic.Connection) {
	setCongestion(s.ctx, connection, s.congestionControl)
	session := &serverSession[U]{
		Service:    s,
		ctx:        s.ctx,
		quicConn:   connection,
		source:     M.SocksaddrFromNet(connection.RemoteAddr()),
		connDone:   make(chan struct{}),
		authDone:   make(chan struct{}),
		udpConnMap: make(map[uint16]*udpPacketConn),
		now:        time.Now,

		defragBudget: newDefragBudget(defragConnectionItems, defragConnectionBytes),
	}
	session.handle()
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx        context.Context
	quicConn   quic.Connection
	source     M.Socksaddr
	connAccess sync.Mutex
	connDone   chan struct{}
	connErr    error
	// authAccess serializes identity publication with authentication timeout.
	authAccess  sync.Mutex
	authExpired bool
	authDone    chan struct{}
	authUser    U
	password    string
	uuid        [16]byte
	udpAccess   sync.RWMutex
	udpConnMap  map[uint16]*udpPacketConn
	tombstones  []udpTombstone
	now         func() time.Time

	defragBudget *defragBudget
}

func (s *serverSession[U]) handle() {
	if s.ctx.Done() != nil {
		go func() {
			select {
			case <-s.ctx.Done():
				s.closeWithError(s.ctx.Err())
			case <-s.connDone:
			}
		}()
	}
	go s.loopUniStreams()
	go s.loopStreams()
	go s.loopMessages()
	go s.handleAuthTimeout()
	go s.loopHeartbeats()
}

func (s *serverSession[U]) loopUniStreams() {
	for {
		uniStream, err := s.quicConn.AcceptUniStream(s.ctx)
		if err != nil {
			return
		}
		go func() {
			err = s.handleUniStream(uniStream)
			if err != nil {
				s.closeWithError(E.Cause(err, "handle uni stream"))
			}
		}()
	}
}

func (s *serverSession[U]) handleUniStream(stream quic.ReceiveStream) error {
	defer stream.CancelRead(0)
	buffer := buf.New()
	defer buffer.Release()
	_, err := buffer.ReadAtLeastFrom(stream, 2)
	if err != nil {
		return E.Cause(err, "read request")
	}
	version := buffer.Byte(0)
	if version != Version {
		return E.New("unknown version ", buffer.Byte(0))
	}
	command := buffer.Byte(1)
	switch command {
	case CommandAuthenticate:
		select {
		case <-s.authDone:
			return E.New("authentication: multiple authentication requests")
		default:
		}
		if buffer.Len() < AuthenticateLen {
			_, err = buffer.ReadFullFrom(stream, AuthenticateLen-buffer.Len())
			if err != nil {
				return E.Cause(err, "authentication: read request")
			}
		}
		var userUUID [16]byte
		copy(userUUID[:], buffer.Range(2, 2+16))
		snapshot := s.users.Load()
		if snapshot == nil {
			return E.New("authentication: unknown user ", uuid.UUID(userUUID))
		}
		user, loaded := snapshot.userMap[userUUID]
		if !loaded {
			return E.New("authentication: unknown user ", uuid.UUID(userUUID))
		}
		password, loaded := snapshot.passwordMap[user]
		if !loaded {
			return E.New("authentication: missing password for user ", uuid.UUID(userUUID))
		}
		handshakeState := s.quicConn.ConnectionState()
		tuicToken, err := handshakeState.ExportKeyingMaterial(string(userUUID[:]), []byte(password), 32)
		if err != nil {
			return E.Cause(err, "authentication: export keying material")
		}
		if subtle.ConstantTimeCompare(tuicToken, buffer.Range(2+16, 2+16+32)) != 1 {
			return E.New("authentication: token mismatch")
		}
		s.authAccess.Lock()
		select {
		case <-s.authDone:
			s.authAccess.Unlock()
			return E.New("authentication: multiple authentication requests")
		default:
		}
		if s.authExpired {
			s.authAccess.Unlock()
			return E.New("authentication timeout")
		}
		s.authUser = user
		s.uuid = userUUID
		s.password = password
		close(s.authDone)
		s.authAccess.Unlock()
		// Token validation used one snapshot. Registration independently closes
		// revoked credentials, without changing the token-validation result.
		s.registerSession(s)
		return nil
	case CommandPacket:
		select {
		case <-s.connDone:
			return s.connErr
		case <-s.authDone:
		}
		message := allocMessage()
		err = readUDPMessage(message, io.MultiReader(bytes.NewReader(buffer.From(2)), stream))
		if err != nil {
			message.release()
			return err
		}
		s.handleUDPMessage(message, true)
		return nil
	case CommandDissociate:
		select {
		case <-s.connDone:
			return s.connErr
		case <-s.authDone:
		}
		if buffer.Len() > 4 {
			return E.New("invalid dissociate message")
		}
		var sessionID uint16
		err = binary.Read(io.MultiReader(bytes.NewReader(buffer.From(2)), stream), binary.BigEndian, &sessionID)
		if err != nil {
			return err
		}
		s.udpAccess.Lock()
		udpConn, loaded := s.udpConnMap[sessionID]
		if loaded {
			delete(s.udpConnMap, sessionID)
			s.recordTombstone(sessionID)
		}
		s.udpAccess.Unlock()
		if loaded {
			udpConn.closeWithError(E.New("remote closed"))
		}
		return nil
	default:
		return E.New("unknown command ", command)
	}
}

func (s *serverSession[U]) handleAuthTimeout() {
	select {
	case <-s.connDone:
	case <-s.authDone:
	case <-time.After(s.authTimeout):
		s.authAccess.Lock()
		select {
		case <-s.authDone:
			s.authAccess.Unlock()
			return
		default:
		}
		s.authExpired = true
		s.authAccess.Unlock()
		s.closeWithError(E.New("authentication timeout"))
	}
}

func (s *serverSession[U]) loopStreams() {
	for {
		stream, err := s.quicConn.AcceptStream(s.ctx)
		if err != nil {
			s.closeWithError(err)
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
	buffer := buf.NewSize(2 + M.MaxSocksaddrLength)
	defer buffer.Release()
	_, err := buffer.ReadAtLeastFrom(stream, 2)
	if err != nil {
		return E.Cause(err, "read request")
	}
	version, _ := buffer.ReadByte()
	if version != Version {
		return E.New("unknown version ", buffer.Byte(0))
	}
	command, _ := buffer.ReadByte()
	if command != CommandConnect {
		return E.New("unsupported stream command ", command)
	}
	destination, err := AddressSerializer.ReadAddrPort(io.MultiReader(buffer, stream))
	if err != nil {
		return E.Cause(err, "read request destination")
	}
	select {
	case <-s.connDone:
		return s.connErr
	case <-s.authDone:
	}
	var conn net.Conn = &serverConn{
		Stream:      stream,
		destination: destination,
	}
	if buffer.IsEmpty() {
		buffer.Release()
	} else {
		conn = bufio.NewCachedConn(conn, buffer)
	}
	ctx := auth.ContextWithUser(s.ctx, s.authUser)
	_ = s.handler.NewConnection(ctx, conn, M.Metadata{
		Source:      s.source,
		Destination: destination,
	})
	return nil
}

func (s *serverSession[U]) loopHeartbeats() {
	ticker := time.NewTicker(s.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-s.connDone:
			return
		case <-ticker.C:
			err := s.quicConn.SendDatagram([]byte{Version, CommandHeartbeat})
			if err != nil {
				s.closeWithError(E.Cause(err, "send heartbeat"))
			}
		}
	}
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
	destination M.Socksaddr
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, baderror.WrapQUIC(err)
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	n, err = c.Stream.Write(p)
	return n, baderror.WrapQUIC(err)
}

func (c *serverConn) LocalAddr() net.Addr {
	return c.destination
}

func (c *serverConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}
