package hysteria2

import (
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

func (s *serverSession[U]) loopMessages() {
	for {
		message, err := s.quicConn.ReceiveDatagram(s.ctx)
		if err != nil {
			s.closeWithError(E.Cause(err, "receive message"))
			return
		}
		hErr := s.handleMessage(message)
		if hErr != nil {
			s.closeWithError(E.Cause(hErr, "handle message"))
			return
		}
	}
}

func (s *serverSession[U]) handleMessage(data []byte) error {
	message := allocMessage()
	err := decodeUDPMessage(message, data)
	if err != nil {
		message.release()
		return E.Cause(err, "decode UDP message")
	}
	s.handleUDPMessage(message)
	return nil
}

func (s *serverSession[U]) handleUDPMessage(message *udpMessage) {
	sessionID := message.sessionID
	s.udpAccess.Lock()
	udpConn, loaded := s.udpConnMap[sessionID]
	created := !loaded || common.Done(udpConn.ctx)
	if created {
		// This constructor only allocates state; it cannot invoke onDestroy.
		udpConn = newUDPPacketConn(auth.ContextWithUser(s.ctx, s.authUser), s.quicConn, func() {
			s.udpAccess.Lock()
			if s.udpConnMap[sessionID] == udpConn {
				delete(s.udpConnMap, sessionID)
			}
			s.udpAccess.Unlock()
		}, s.defragBudget)
		udpConn.sessionID = sessionID
		s.udpConnMap[sessionID] = udpConn
	}
	s.udpAccess.Unlock()
	if created {
		newCtx, newConn := canceler.NewPacketConn(udpConn.ctx, udpConn, s.udpTimeout)
		go s.handler.NewPacketConnection(newCtx, newConn, M.Metadata{
			Source:      s.source,
			Destination: M.ParseSocksaddr(message.destination),
		})
	}
	udpConn.inputPacket(message)
}
