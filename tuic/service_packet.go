package tuic

import (
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type udpTombstone struct {
	id    uint16
	until time.Time
}

// The caller holds udpAccess for all tombstone operations.
func (s *serverSession[U]) pruneTombstones() time.Time {
	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	for len(s.tombstones) > 0 && !now.Before(s.tombstones[0].until) {
		s.tombstones = s.tombstones[1:]
	}
	return now
}

func (s *serverSession[U]) recordTombstone(id uint16) {
	now := s.pruneTombstones()
	if len(s.tombstones) == maxTombstones {
		copy(s.tombstones, s.tombstones[1:])
		s.tombstones = s.tombstones[:maxTombstones-1]
	}
	s.tombstones = append(s.tombstones, udpTombstone{id: id, until: now.Add(tombstoneTTL)})
}

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
		s.pruneTombstones()
		for _, tombstone := range s.tombstones {
			if tombstone.id == sessionID {
				s.udpAccess.Unlock()
				message.release()
				return
			}
		}
		if len(s.udpConnMap) >= maxUDPSessions {
			s.udpAccess.Unlock()
			message.release()
			return
		}
		// This constructor only allocates state; it cannot invoke onDestroy.
		udpConn = newUDPPacketConn(auth.ContextWithUser(s.ctx, s.authUser), s.quicConn, udpStream, true, func() {
			s.udpAccess.Lock()
			if s.udpConnMap[sessionID] == udpConn {
				delete(s.udpConnMap, sessionID)
				s.recordTombstone(sessionID)
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
			Destination: message.destination,
		})
	}
	udpConn.inputPacket(message)
}
