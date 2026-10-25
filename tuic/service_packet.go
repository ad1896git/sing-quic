package tuic

import (
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

func (s *serverSession[U]) loopMessages() {
	select {
	case <-s.connDone:
		return
	case <-s.authDone:
	}
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
	if len(data) < 2 {
		return E.New("invalid message")
	}
	if data[0] != Version {
		return E.New("unknown version ", data[0])
	}
	switch data[1] {
	case CommandPacket:
		message := allocMessage()
		err := decodeUDPMessage(message, data[2:])
		if err != nil {
			message.release()
			return E.Cause(err, "decode UDP message")
		}
		s.handleUDPMessage(message, false)
		return nil
	case CommandHeartbeat:
		return nil
	default:
		return E.New("unknown command ", data[0])
	}
}

func (s *serverSession[U]) handleUDPMessage(message *udpMessage, udpStream bool) {
	sessionID := message.sessionID
	s.udpAccess.Lock()
	udpConn, loaded := s.udpConnMap[sessionID]
	created := !loaded || common.Done(udpConn.ctx)
	if created {
		// This constructor only allocates state; it cannot invoke onDestroy.
		udpConn = newUDPPacketConn(auth.ContextWithUser(s.ctx, s.authUser), s.quicConn, udpStream, true, func() {
			s.udpAccess.Lock()
			if s.udpConnMap[sessionID] == udpConn {
				delete(s.udpConnMap, sessionID)
			}
			s.udpAccess.Unlock()
		})
		udpConn.sessionID = sessionID
		s.udpConnMap[sessionID] = udpConn
	}
	s.udpAccess.Unlock()
	if created {
		newCtx, newConn := canceler.NewPacketConn(udpConn.ctx, udpConn, s.udpTimeout)
		go s.handler.NewPacketConnection(newCtx, newConn, M.Metadata{
			Source:      s.source,
			Destination: message.destination,
		})
	}
	udpConn.inputPacket(message)
}
