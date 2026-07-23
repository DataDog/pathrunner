// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"os"
	"path/filepath"
	"github.com/DataDog/pathrunner/pkg/core"
	"github.com/DataDog/pathrunner/pkg/modules"
	"testing"
	"time"
)

func TestSessionManagerCreation(t *testing.T) {
	// Create temporary directory for test sessions
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	sm := core.NewSessionManager()

	if sm == nil {
		t.Fatal("Expected SessionManager instance, got nil")
	}

	current := sm.GetCurrentSession()
	if current == nil {
		t.Fatal("Expected default session to be created")
	}

	if current.Name != "default" {
		t.Errorf("Expected default session name, got '%s'", current.Name)
	}
}

func TestCreateSession(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	sm := core.NewSessionManager()

	err := sm.CreateSession("test-session")
	if err != nil {
		t.Fatalf("Expected no error creating session, got: %v", err)
	}

	// Verify session file was created
	sessionFile := filepath.Join(tempDir, ".pathrunner", "sessions", "test-session.json")
	if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
		t.Error("Expected session file to be created")
	}
}

func TestCreateDuplicateSession(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	sm := core.NewSessionManager()

	// Create first session
	err := sm.CreateSession("duplicate")
	if err != nil {
		t.Fatalf("Expected no error creating first session, got: %v", err)
	}

	// Try to create duplicate
	err = sm.CreateSession("duplicate")
	if err == nil {
		t.Error("Expected error when creating duplicate session")
	}
}

func TestCreateSessionEmptyName(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	sm := core.NewSessionManager()

	err := sm.CreateSession("")
	if err == nil {
		t.Error("Expected error when creating session with empty name")
	}
}

func TestSwitchSession(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	sm := core.NewSessionManager()

	// Create new session
	err := sm.CreateSession("session2")
	if err != nil {
		t.Fatalf("Expected no error creating session, got: %v", err)
	}

	// Switch to it
	err = sm.SwitchSession("session2")
	if err != nil {
		t.Fatalf("Expected no error switching session, got: %v", err)
	}

	current := sm.GetCurrentSession()
	if current.Name != "session2" {
		t.Errorf("Expected current session 'session2', got '%s'", current.Name)
	}
}

func TestSwitchSessionNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	sm := core.NewSessionManager()

	err := sm.SwitchSession("nonexistent")
	if err == nil {
		t.Error("Expected error when switching to non-existent session")
	}

	// Current session should remain unchanged
	current := sm.GetCurrentSession()
	if current.Name != "default" {
		t.Errorf("Expected current session to remain 'default', got '%s'", current.Name)
	}
}

func TestListSessions(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	sm := core.NewSessionManager()

	// Create multiple sessions
	_ = sm.CreateSession("session1")
	_ = sm.CreateSession("session2")
	_ = sm.CreateSession("session3")

	sessions, err := sm.ListSessions()
	if err != nil {
		t.Fatalf("Expected no error listing sessions, got: %v", err)
	}

	// Should have default + 3 created = 4 total
	if len(sessions) != 4 {
		t.Errorf("Expected 4 sessions, got %d", len(sessions))
	}

	// Verify session names
	sessionNames := make(map[string]bool)
	for _, session := range sessions {
		sessionNames[session.Name] = true
	}

	expectedNames := []string{"default", "session1", "session2", "session3"}
	for _, name := range expectedNames {
		if !sessionNames[name] {
			t.Errorf("Expected session '%s' in list", name)
		}
	}
}

func TestDeleteSession(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	sm := core.NewSessionManager()

	// Create and delete a session
	_ = sm.CreateSession("to-delete")

	err := sm.DeleteSession("to-delete")
	if err != nil {
		t.Fatalf("Expected no error deleting session, got: %v", err)
	}

	// Verify session file was deleted
	sessionFile := filepath.Join(tempDir, ".pathrunner", "sessions", "to-delete.json")
	if _, err := os.Stat(sessionFile); !os.IsNotExist(err) {
		t.Error("Expected session file to be deleted")
	}

	// Verify it's not in list
	sessions, _ := sm.ListSessions()
	for _, session := range sessions {
		if session.Name == "to-delete" {
			t.Error("Expected deleted session not to appear in list")
		}
	}
}

func TestDeleteCurrentSessionFails(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	sm := core.NewSessionManager()

	err := sm.DeleteSession("default")
	if err == nil {
		t.Error("Expected error when deleting current session")
	}
}

func TestSessionIdentityPersistence(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	sm := core.NewSessionManager()

	// Add identities to current session
	current := sm.GetCurrentSession()
	current.Identities = map[string]*modules.Identity{
		"test-identity": {
			Name:   "test-identity",
			Type:   "profile",
			Region: "us-east-1",
		},
	}
	current.CurrentIdentity = "test-identity"

	// Save session
	err := sm.SaveSession(current)
	if err != nil {
		t.Fatalf("Expected no error saving session, got: %v", err)
	}

	// Create new session manager (simulates restart)
	sm2 := core.NewSessionManager()

	// Verify identities were persisted
	loaded := sm2.GetCurrentSession()
	if len(loaded.Identities) != 1 {
		t.Errorf("Expected 1 identity, got %d", len(loaded.Identities))
	}

	if loaded.Identities["test-identity"] == nil {
		t.Error("Expected test-identity to be loaded")
	}

	if loaded.CurrentIdentity != "test-identity" {
		t.Errorf("Expected current identity 'test-identity', got '%s'", loaded.CurrentIdentity)
	}
}

func TestSessionCommandLogPersistence(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	sm := core.NewSessionManager()

	// Log some commands
	sm.LogCommand("identity list", true, "", "output1")
	sm.LogCommand("workspace create test", true, "", "output2")
	sm.LogCommand("use exploit/test", false, "error message", "")

	// Save current session
	current := sm.GetCurrentSession()
	err := sm.SaveSession(current)
	if err != nil {
		t.Fatalf("Expected no error saving session, got: %v", err)
	}

	// Create new session manager
	sm2 := core.NewSessionManager()

	// Verify command log was persisted
	loaded := sm2.GetCurrentSession()
	if len(loaded.CommandLog) != 3 {
		t.Errorf("Expected 3 command log entries, got %d", len(loaded.CommandLog))
	}

	if loaded.CommandLog[0].Command != "identity list" {
		t.Errorf("Expected first command 'identity list', got '%s'", loaded.CommandLog[0].Command)
	}

	if loaded.CommandLog[2].Success {
		t.Error("Expected third command to have failed")
	}

	if loaded.CommandLog[2].Error != "error message" {
		t.Errorf("Expected error message, got '%s'", loaded.CommandLog[2].Error)
	}
}

func TestSessionResourceTracking(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	sm := core.NewSessionManager()

	// Track a resource
	resource := modules.CreatedResource{
		Type:          "lambda:function",
		Name:          "test-function",
		ARN:           "arn:aws:lambda:us-east-1:123456789012:function:test-function",
		Region:        "us-east-1",
		CleanupMethod: "delete",
	}

	sm.TrackResource(resource)

	// Get tracked resources
	resources := sm.GetCreatedResources()
	if len(resources) != 1 {
		t.Errorf("Expected 1 tracked resource, got %d", len(resources))
	}

	if resources[0].Name != "test-function" {
		t.Errorf("Expected resource name 'test-function', got '%s'", resources[0].Name)
	}

	// Remove resource
	sm.RemoveCreatedResource("test-function")

	resources = sm.GetCreatedResources()
	if len(resources) != 0 {
		t.Errorf("Expected 0 resources after removal, got %d", len(resources))
	}
}

func TestSessionIsolation(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	sm := core.NewSessionManager()

	// Add identity to default session
	current := sm.GetCurrentSession()
	current.Identities = map[string]*modules.Identity{
		"default-identity": {
			Name:   "default-identity",
			Type:   "profile",
			Region: "us-east-1",
		},
	}
	_ = sm.SaveSession(current)

	// Create new session
	_ = sm.CreateSession("isolated")
	_ = sm.SwitchSession("isolated")

	// New session should have no identities
	isolated := sm.GetCurrentSession()
	if len(isolated.Identities) != 0 {
		t.Errorf("Expected isolated session to have 0 identities, got %d", len(isolated.Identities))
	}

	// Add identity to isolated session
	isolated.Identities = map[string]*modules.Identity{
		"isolated-identity": {
			Name:   "isolated-identity",
			Type:   "keys",
			Region: "us-west-2",
		},
	}
	_ = sm.SaveSession(isolated)

	// Switch back to default
	_ = sm.SwitchSession("default")
	defaultSession := sm.GetCurrentSession()

	// Verify default session still has its identity
	if len(defaultSession.Identities) != 1 {
		t.Errorf("Expected default session to have 1 identity, got %d", len(defaultSession.Identities))
	}

	if defaultSession.Identities["default-identity"] == nil {
		t.Error("Expected default-identity in default session")
	}

	if defaultSession.Identities["isolated-identity"] != nil {
		t.Error("Expected isolated-identity NOT to be in default session")
	}
}

func TestSessionLastAccessedUpdate(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	sm := core.NewSessionManager()

	initialTime := sm.GetCurrentSession().LastAccessed

	// Wait a bit and switch sessions
	time.Sleep(10 * time.Millisecond)

	_ = sm.CreateSession("test")
	_ = sm.SwitchSession("test")
	_ = sm.SwitchSession("default")

	newTime := sm.GetCurrentSession().LastAccessed

	if !newTime.After(initialTime) {
		t.Error("Expected LastAccessed to be updated after session switch")
	}
}
