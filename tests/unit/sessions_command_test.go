package unit

import (
	"github.com/DataDog/pathrunner/pkg/attacker"
	"testing"
)

func TestShellSessionManagerAdd(t *testing.T) {
	manager := attacker.NewShellSessionManager()

	if manager.TotalCount() != 0 {
		t.Fatalf("expected 0 sessions, got %d", manager.TotalCount())
	}

	session := &attacker.ShellSession{}
	sessionID := manager.Add(session)

	if sessionID != 1 {
		t.Errorf("expected session ID 1, got %d", sessionID)
	}
	if session.ID != 1 {
		t.Errorf("expected session.ID to be 1, got %d", session.ID)
	}
	if manager.TotalCount() != 1 {
		t.Errorf("expected 1 session, got %d", manager.TotalCount())
	}
}

func TestShellSessionManagerAutoIncrementIDs(t *testing.T) {
	manager := attacker.NewShellSessionManager()

	session1 := &attacker.ShellSession{}
	session2 := &attacker.ShellSession{}
	session3 := &attacker.ShellSession{}

	id1 := manager.Add(session1)
	id2 := manager.Add(session2)
	id3 := manager.Add(session3)

	if id1 != 1 || id2 != 2 || id3 != 3 {
		t.Errorf("expected IDs 1, 2, 3 but got %d, %d, %d", id1, id2, id3)
	}
}

func TestShellSessionManagerGet(t *testing.T) {
	manager := attacker.NewShellSessionManager()

	session := &attacker.ShellSession{}
	sessionID := manager.Add(session)

	retrieved := manager.Get(sessionID)
	if retrieved != session {
		t.Error("Get returned wrong session")
	}

	notFound := manager.Get(999)
	if notFound != nil {
		t.Error("expected nil for nonexistent session ID")
	}
}

func TestShellSessionManagerKill(t *testing.T) {
	manager := attacker.NewShellSessionManager()

	session := &attacker.ShellSession{}
	sessionID := manager.Add(session)

	if !manager.Kill(sessionID) {
		t.Error("Kill should return true for existing session")
	}
	if manager.TotalCount() != 0 {
		t.Errorf("expected 0 sessions after kill, got %d", manager.TotalCount())
	}

	// Killing again should return false
	if manager.Kill(sessionID) {
		t.Error("Kill should return false for already-killed session")
	}
}

func TestShellSessionManagerRemove(t *testing.T) {
	manager := attacker.NewShellSessionManager()

	session := &attacker.ShellSession{}
	sessionID := manager.Add(session)

	manager.Remove(sessionID)

	if manager.Get(sessionID) != nil {
		t.Error("session should be nil after Remove")
	}
}

func TestShellSessionManagerList(t *testing.T) {
	manager := attacker.NewShellSessionManager()

	session1 := &attacker.ShellSession{}
	session2 := &attacker.ShellSession{}
	session3 := &attacker.ShellSession{}

	manager.Add(session1)
	manager.Add(session2)
	manager.Add(session3)

	sessions := manager.List()
	if len(sessions) != 3 {
		t.Fatalf("expected 3 sessions, got %d", len(sessions))
	}

	// List should return sessions sorted by ID
	for i, s := range sessions {
		expectedID := i + 1
		if s.ID != expectedID {
			t.Errorf("session at index %d has ID %d, expected %d", i, s.ID, expectedID)
		}
	}
}

func TestShellSessionManagerKillDoesNotAffectOthers(t *testing.T) {
	manager := attacker.NewShellSessionManager()

	session1 := &attacker.ShellSession{}
	session2 := &attacker.ShellSession{}
	session3 := &attacker.ShellSession{}

	id1 := manager.Add(session1)
	manager.Add(session2)
	manager.Add(session3)

	manager.Kill(id1)

	if manager.TotalCount() != 2 {
		t.Errorf("expected 2 sessions after killing one, got %d", manager.TotalCount())
	}

	// Other sessions should still be retrievable
	if manager.Get(2) == nil || manager.Get(3) == nil {
		t.Error("killing session 1 should not affect sessions 2 and 3")
	}
}

func TestShellSessionManagerIDsDoNotReset(t *testing.T) {
	manager := attacker.NewShellSessionManager()

	session1 := &attacker.ShellSession{}
	id1 := manager.Add(session1)
	manager.Kill(id1)

	session2 := &attacker.ShellSession{}
	id2 := manager.Add(session2)

	// ID should continue incrementing, not reset to 1
	if id2 != 2 {
		t.Errorf("expected ID 2 after killing session 1, got %d", id2)
	}
}
