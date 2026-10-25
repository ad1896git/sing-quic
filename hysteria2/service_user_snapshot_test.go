package hysteria2

import (
	"sync"
	"testing"
)

func TestUserSnapshotDeletedUser(t *testing.T) {
	service := &Service[string]{}
	service.UpdateUsers([]string{"user"}, []string{"password"})
	if user, ok := service.lookupUser("password"); !ok || user != "user" {
		t.Fatal("known user rejected")
	}
	service.UpdateUsers(nil, nil)
	if _, ok := service.lookupUser("password"); ok {
		t.Fatal("deleted user accepted")
	}
}

func TestUserSnapshotPasswordChange(t *testing.T) {
	service := &Service[string]{}
	service.UpdateUsers([]string{"user"}, []string{"old"})
	previous := service.users.Load()
	service.UpdateUsers([]string{"user"}, []string{"new"})
	if previous.userMap["old"] != "user" {
		t.Fatal("previous snapshot mutated")
	}
	if _, ok := service.lookupUser("old"); ok {
		t.Fatal("old password accepted")
	}
	if user, ok := service.lookupUser("new"); !ok || user != "user" {
		t.Fatal("new password rejected")
	}
}

func TestUserSnapshotLengthMismatch(t *testing.T) {
	service := &Service[string]{}
	service.UpdateUsers([]string{"user"}, []string{"password"})
	previous := service.users.Load()
	for _, lengths := range [][2]int{{0, 1}, {1, 0}, {2, 1}, {1, 2}} {
		service.UpdateUsers(make([]string, lengths[0]), make([]string, lengths[1]))
		if service.users.Load() != previous {
			t.Fatalf("mismatch %v published a snapshot", lengths)
		}
		if user, ok := service.lookupUser("password"); !ok || user != "user" {
			t.Fatal("known user rejected after mismatch")
		}
	}
}

func TestUserSnapshotUninitialized(t *testing.T) {
	if _, ok := (&Service[string]{}).lookupUser(""); ok {
		t.Fatal("uninitialized service accepted user")
	}
}

func TestUserSnapshotConcurrent(t *testing.T) {
	service := &Service[string]{}
	update := func(i int) {
		if i%2 == 0 {
			service.UpdateUsers([]string{"first", "rotating"}, []string{"stable", "old"})
		} else {
			service.UpdateUsers([]string{"second", "rotating"}, []string{"stable", "new"})
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
				user, ok := service.lookupUser("stable")
				if !ok || (user != "first" && user != "second") {
					t.Errorf("concurrent authentication = %q, %v", user, ok)
					return
				}
				if _, ok := service.lookupUser("invalid"); ok {
					t.Error("invalid password accepted")
					return
				}
			}
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
}
