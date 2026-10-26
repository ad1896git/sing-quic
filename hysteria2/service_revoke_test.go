package hysteria2

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/logger"
)

// Embedding the interface makes unexpected network operations fail immediately.
type revokeTestConn struct {
	quic.Connection
	calls atomic.Int32
	close func(quic.ApplicationErrorCode, string)
}

func (c *revokeTestConn) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	c.calls.Add(1)
	if c.close != nil {
		c.close(code, reason)
	}
	return nil
}

func revokeTestUpdate(s *Service[int], users []int, passwords []string) {
	s.UpdateUsers(users, passwords)
}

func revokeTestSession(s *Service[int], user int, password string) (*serverSession[int], *revokeTestConn) {
	c := &revokeTestConn{}
	session := &serverSession[int]{Service: s, authUser: user, password: password, connDone: make(chan struct{}), quicConn: c}
	// A synchronous close callback exercises both registry and session lock order.
	c.close = func(_ quic.ApplicationErrorCode, _ string) {
		session.closeWithError(net.ErrClosed)
		s.unregisterSession(session)
	}
	return session, c
}

func revokeTestCount(t *testing.T, s *Service[int], want int) {
	t.Helper()
	s.sessionsAccess.Lock()
	defer s.sessionsAccess.Unlock()
	if len(s.sessions) != want {
		t.Fatalf("registered sessions = %d, want %d", len(s.sessions), want)
	}
}

func TestRevokeOnRemove(t *testing.T) {
	s := &Service[int]{logger: logger.NOP()}
	revokeTestUpdate(s, []int{1, 2}, []string{"a", "b"})
	a, ac := revokeTestSession(s, 1, "a")
	b, bc := revokeTestSession(s, 2, "b")
	if !s.registerSession(a) || !s.registerSession(b) {
		t.Fatal("registration rejected")
	}
	ac.close = func(code quic.ApplicationErrorCode, reason string) {
		if code == 0 || reason != "user revoked" {
			t.Errorf("close = %d, %q", code, reason)
		}
		a.closeWithError(net.ErrClosed)
	}
	revokeTestUpdate(s, []int{2}, []string{"b"})
	if ac.calls.Load() != 1 || bc.calls.Load() != 0 {
		t.Fatal("removed user must close once; unchanged user must stay open")
	}
	revokeTestCount(t, s, 1)
	b.closeWithError(net.ErrClosed)
	revokeTestCount(t, s, 0)
}

func TestRevokeOnPasswordChange(t *testing.T) {
	s := &Service[int]{logger: logger.NOP()}
	revokeTestUpdate(s, []int{1}, []string{"old"})
	a, c := revokeTestSession(s, 1, "old")
	if !s.registerSession(a) {
		t.Fatal("registration rejected")
	}
	revokeTestUpdate(s, []int{1}, []string{"new"})
	if c.calls.Load() != 1 {
		t.Fatal("old credential was not closed once")
	}
	revokeTestCount(t, s, 0)
}

func TestNoRevokeWhenUnchanged(t *testing.T) {
	s := &Service[int]{logger: logger.NOP()}
	revokeTestUpdate(s, []int{1}, []string{"a"})
	a, c := revokeTestSession(s, 1, "a")
	if !s.registerSession(a) {
		t.Fatal("registration rejected")
	}
	revokeTestUpdate(s, []int{1}, []string{"a"})
	if c.calls.Load() != 0 {
		t.Fatal("unchanged user closed")
	}
	revokeTestCount(t, s, 1)
	a.closeWithError(net.ErrClosed)
	revokeTestCount(t, s, 0)
}

func TestRegisterAfterUpdateRejected(t *testing.T) {
	s := &Service[int]{logger: logger.NOP()}
	revokeTestUpdate(s, []int{1}, []string{"old"})
	a, c := revokeTestSession(s, 1, "old")
	revokeTestUpdate(s, []int{1}, []string{"new"})
	if s.registerSession(a) {
		t.Fatal("stale authentication registered")
	}
	if c.calls.Load() != 1 {
		t.Fatal("rejected session was not closed once")
	}
	revokeTestCount(t, s, 0)
}

func TestRevokeCredentialReassigned(t *testing.T) {
	s := &Service[int]{logger: logger.NOP()}
	revokeTestUpdate(s, []int{1}, []string{"a"})
	a, c := revokeTestSession(s, 1, "a")
	if !s.registerSession(a) {
		t.Fatal("registration rejected")
	}
	revokeTestUpdate(s, []int{2}, []string{"a"})
	if c.calls.Load() != 1 {
		t.Fatal("credential reassigned to another user stayed open")
	}
}

func TestRevokeClosedBeforeRegister(t *testing.T) {
	s := &Service[int]{logger: logger.NOP()}
	revokeTestUpdate(s, []int{1}, []string{"a"})
	a, c := revokeTestSession(s, 1, "a")
	a.closeWithError(net.ErrClosed)
	if s.registerSession(a) {
		t.Fatal("closed session registered")
	}
	revokeTestUpdate(s, nil, nil)
	if c.calls.Load() != 1 {
		t.Fatal("closed session closed twice")
	}
	revokeTestCount(t, s, 0)
}

func TestRevokeConcurrent(t *testing.T) {
	const count = 128
	s := &Service[int]{logger: logger.NOP()}
	revokeTestUpdate(s, []int{1}, []string{"a"})
	sessions := make([]*serverSession[int], count)
	conns := make([]*revokeTestConn, count)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range sessions {
		sessions[i], conns[i] = revokeTestSession(s, 1, "a")
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			<-start
			s.registerSession(sessions[i])
			if i%2 == 0 {
				sessions[i].closeWithError(net.ErrClosed)
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			<-start
			if i%2 == 0 {
				revokeTestUpdate(s, nil, nil)
			} else {
				revokeTestUpdate(s, []int{1}, []string{"a"})
			}
		}(i)
	}
	close(start)
	wg.Wait()
	revokeTestUpdate(s, nil, nil)
	for i, session := range sessions {
		session.closeWithError(net.ErrClosed)
		if got := conns[i].calls.Load(); got != 1 {
			t.Fatalf("session %d closed %d times, want 1", i, got)
		}
	}
	revokeTestCount(t, s, 0)
}
