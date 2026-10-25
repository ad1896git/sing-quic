package tuic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

// A deterministic exporter makes the token depend on both the UUID and password.
func snapshotToken(label string, password []byte, length int) ([]byte, error) {
	sum := sha256.Sum256(append([]byte(label), password...))
	return sum[:length], nil
}

func snapshotAuthenticate(service *Service[string], id [16]byte, password string) error {
	token, _ := snapshotToken(string(id[:]), []byte(password), 32)
	request := make([]byte, AuthenticateLen)
	request[0], request[1] = Version, CommandAuthenticate
	copy(request[2:18], id[:])
	copy(request[18:], token)
	session := &serverSession[string]{
		Service: service, ctx: context.Background(),
		quicConn: &authTestConn{export: snapshotToken}, connDone: make(chan struct{}), authDone: make(chan struct{}),
	}
	return session.handleUniStream(&authTestStream{Reader: bytes.NewReader(request)})
}

func TestUserSnapshotMissingPassword(t *testing.T) {
	service := &Service[string]{logger: logger.NOP()}
	service.users.Store(&userSnapshot[string]{userMap: map[[16]byte]string{{1}: "new-user"}, passwordMap: map[string]string{}})
	if err := snapshotAuthenticate(service, [16]byte{1}, ""); err == nil || !strings.Contains(err.Error(), "missing password") {
		t.Fatalf("empty-password token for missing password: %v", err)
	}
}

func TestUserSnapshotEmptyPassword(t *testing.T) {
	service := &Service[string]{}
	service.UpdateUsers([]string{"user"}, [][16]byte{{1}}, []string{""})
	if err := snapshotAuthenticate(service, [16]byte{1}, ""); err != nil {
		t.Fatal(err)
	}
}

func TestUserSnapshotDeletedUser(t *testing.T) {
	service := &Service[string]{}
	service.UpdateUsers([]string{"user"}, [][16]byte{{1}}, []string{"old"})
	if err := snapshotAuthenticate(service, [16]byte{1}, "old"); err != nil {
		t.Fatal(err)
	}
	service.UpdateUsers(nil, nil, nil)
	if err := snapshotAuthenticate(service, [16]byte{1}, "old"); err == nil || !strings.Contains(err.Error(), "unknown user") {
		t.Fatalf("deleted user: %v", err)
	}
}

func TestUserSnapshotPasswordChange(t *testing.T) {
	service := &Service[string]{}
	service.UpdateUsers([]string{"user"}, [][16]byte{{1}}, []string{"old"})
	if err := snapshotAuthenticate(service, [16]byte{1}, "old"); err != nil {
		t.Fatal(err)
	}
	previous := service.users.Load()
	service.UpdateUsers([]string{"user"}, [][16]byte{{1}}, []string{"new"})
	if previous.passwordMap["user"] != "old" {
		t.Fatal("previous snapshot mutated")
	}
	if err := snapshotAuthenticate(service, [16]byte{1}, "old"); err == nil {
		t.Fatal("old token accepted")
	}
	if err := snapshotAuthenticate(service, [16]byte{1}, "new"); err != nil {
		t.Fatal(err)
	}
}

func TestUserSnapshotLengthMismatch(t *testing.T) {
	service := &Service[string]{}
	service.UpdateUsers([]string{"user"}, [][16]byte{{1}}, []string{"password"})
	previous := service.users.Load()
	for _, lengths := range [][3]int{{0, 1, 1}, {1, 0, 1}, {1, 1, 0}, {2, 1, 1}, {1, 2, 1}, {1, 1, 2}} {
		service.UpdateUsers(make([]string, lengths[0]), make([][16]byte, lengths[1]), make([]string, lengths[2]))
		if service.users.Load() != previous {
			t.Fatalf("mismatch %v published a snapshot", lengths)
		}
		if err := snapshotAuthenticate(service, [16]byte{1}, "password"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUserSnapshotUninitialized(t *testing.T) {
	if err := snapshotAuthenticate(&Service[string]{}, [16]byte{1}, ""); err == nil {
		t.Fatal("uninitialized service accepted user")
	}
}

func TestUserSnapshotConcurrent(t *testing.T) {
	service := &Service[string]{}
	update := func(i int) {
		if i%2 == 0 {
			service.UpdateUsers([]string{"first"}, [][16]byte{{1}}, []string{"password"})
		} else {
			service.UpdateUsers([]string{"second"}, [][16]byte{{1}}, []string{"password"})
		}
	}
	update(0)
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(5)
	done.Add(5)
	go func() {
		defer done.Done()
		ready.Done()
		<-start
		for i := 0; i < 500; i++ {
			update(i)
		}
	}()
	for worker := 0; worker < 4; worker++ {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			for i := 0; i < 500; i++ {
				if err := snapshotAuthenticate(service, [16]byte{1}, "password"); err != nil {
					t.Errorf("concurrent authentication: %v", err)
					return
				}
			}
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
}

// An update while the exporter is blocked affects only subsequent attempts.
func TestUserSnapshotInFlight(t *testing.T) {
	service := &Service[string]{}
	service.UpdateUsers([]string{"user"}, [][16]byte{{1}}, []string{"old"})
	arrived, release := make(chan struct{}), make(chan struct{})
	id := [16]byte{1}
	token, _ := snapshotToken(string(id[:]), []byte("old"), 32)
	request := make([]byte, AuthenticateLen)
	request[0], request[1] = Version, CommandAuthenticate
	copy(request[2:18], id[:])
	copy(request[18:], token)
	session := &serverSession[string]{
		Service: service, ctx: context.Background(), connDone: make(chan struct{}), authDone: make(chan struct{}),
		quicConn: &authTestConn{export: func(label string, password []byte, length int) ([]byte, error) {
			close(arrived)
			<-release
			return snapshotToken(label, password, length)
		}},
	}
	done := make(chan error, 1)
	go func() { done <- session.handleUniStream(&authTestStream{Reader: bytes.NewReader(request)}) }()
	<-arrived
	service.UpdateUsers([]string{"user"}, [][16]byte{{1}}, []string{"new"})
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("in-flight snapshot changed: %v", err)
	}
	if err := snapshotAuthenticate(service, id, "old"); err == nil {
		t.Fatal("subsequent attempt accepted old token")
	}
}
