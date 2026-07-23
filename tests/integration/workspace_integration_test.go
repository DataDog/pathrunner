// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"github.com/DataDog/pathrunner/pkg/modules"
	"strings"
	"testing"
)

// TestWorkspaceList tests listing workspaces
func TestWorkspaceList(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("workspace list")
	if err != nil {
		t.Errorf("Expected no error listing workspaces, got: %v", err)
	}
}

// TestWorkspaceCreate tests creating a workspace
func TestWorkspaceCreate(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("workspace create test-workspace")
	if err != nil {
		t.Errorf("Expected no error creating workspace, got: %v", err)
	}

	// Try to create duplicate
	err = r.ExecuteCommand("workspace create test-workspace")
	if err == nil {
		t.Error("Expected error when creating duplicate workspace")
	}

	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("Expected 'already exists' error, got: %v", err)
	}
}

// TestWorkspaceSwitch tests switching workspaces
func TestWorkspaceSwitch(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Create workspace
	_ = r.ExecuteCommand("workspace create test-ws")

	// Switch to it
	err := r.ExecuteCommand("workspace switch test-ws")
	if err != nil {
		t.Errorf("Expected no error switching workspace, got: %v", err)
	}

	// Try to switch to non-existent workspace
	err = r.ExecuteCommand("workspace switch nonexistent")
	if err == nil {
		t.Error("Expected error when switching to non-existent workspace")
	}
}

// TestWorkspaceDelete tests deleting workspaces
func TestWorkspaceDelete(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Create workspace
	_ = r.ExecuteCommand("workspace create to-delete")

	// Switch to default first (can't delete current)
	_ = r.ExecuteCommand("workspace switch default")

	// Delete it
	err := r.ExecuteCommand("workspace delete to-delete")
	if err != nil {
		t.Errorf("Expected no error deleting workspace, got: %v", err)
	}

	// Try to delete non-existent
	err = r.ExecuteCommand("workspace delete nonexistent")
	if err == nil {
		t.Error("Expected error when deleting non-existent workspace")
	}
}

// TestWorkspaceDeleteCurrent tests that current workspace cannot be deleted
func TestWorkspaceDeleteCurrent(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Try to delete current workspace (default)
	err := r.ExecuteCommand("workspace delete default")
	if err == nil {
		t.Error("Expected error when deleting current workspace")
	}

	if !strings.Contains(err.Error(), "current") && !strings.Contains(err.Error(), "default") {
		t.Errorf("Expected error about deleting current/default workspace, got: %v", err)
	}
}

// TestWorkspaceSave tests saving workspace
func TestWorkspaceSave(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("workspace save")
	if err != nil {
		t.Errorf("Expected no error saving workspace, got: %v", err)
	}
}

// TestWorkspaceHistory tests workspace history
func TestWorkspaceHistory(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("workspace history")
	if err != nil {
		t.Errorf("Expected no error showing history, got: %v", err)
	}

	// With limit
	err = r.ExecuteCommand("workspace history 10")
	if err != nil {
		t.Errorf("Expected no error showing history with limit, got: %v", err)
	}
}

// TestWorkspaceCleanup tests workspace cleanup
func TestWorkspaceCleanup(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Cleanup with no resources should not error
	err := r.ExecuteCommand("workspace cleanup")
	if err != nil {
		t.Errorf("Expected no error during cleanup, got: %v", err)
	}
}

// TestWorkspaceIsolation tests that workspaces maintain separate identities
func TestWorkspaceIsolation(t *testing.T) {
	r, sm, im, cleanup := setupTest(t)
	defer cleanup()

	// Create identity in default workspace
	identity1 := &modules.Identity{
		Name:   "default-identity",
		Type:   "profile",
		Region: "us-east-1",
	}

	identities := map[string]*modules.Identity{
		"default-identity": identity1,
	}
	im.SetIdentities(identities)
	im.SetCurrent(identity1)

	// Save current state
	currentSession := sm.GetCurrentSession()
	currentSession.Identities = identities
	currentSession.CurrentIdentity = "default-identity"
	_ = sm.SaveSession(currentSession)

	// Create and switch to new workspace
	_ = r.ExecuteCommand("workspace create isolated")
	err := r.ExecuteCommand("workspace switch isolated")
	if err != nil {
		t.Fatalf("Failed to switch workspace: %v", err)
	}

	// Verify identities were cleared
	currentIdentities := im.GetIdentities()
	if len(currentIdentities) != 0 {
		t.Errorf("Expected 0 identities in new workspace, got %d", len(currentIdentities))
	}

	if im.GetCurrent() != nil {
		t.Error("Expected no current identity in new workspace")
	}

	// Switch back to default
	err = r.ExecuteCommand("workspace switch default")
	if err != nil {
		t.Fatalf("Failed to switch back to default: %v", err)
	}

	// Verify identities were restored
	currentIdentities = im.GetIdentities()
	if len(currentIdentities) != 1 {
		t.Errorf("Expected 1 identity in default workspace, got %d", len(currentIdentities))
	}

	if currentIdentities["default-identity"] == nil {
		t.Error("Expected default-identity to be restored")
	}
}

// TestWorkspaceAliases tests workspace command aliases
func TestWorkspaceAliases(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Test "workspaces" alias
	err := r.ExecuteCommand("workspaces")
	if err != nil {
		t.Errorf("Expected 'workspaces' alias to work, got: %v", err)
	}

	err = r.ExecuteCommand("workspaces list")
	if err != nil {
		t.Errorf("Expected 'workspaces list' to work, got: %v", err)
	}
}

// TestWorkspaceCommandValidation tests command validation
func TestWorkspaceCommandValidation(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	testCases := []struct {
		name        string
		command     string
		expectError bool
	}{
		{"create without name", "workspace create", true},
		{"switch without name", "workspace switch", true},
		{"delete without name", "workspace delete", true},
		{"list", "workspace list", false},
		{"save", "workspace save", false},
		{"cleanup", "workspace cleanup", false},
		{"history", "workspace history", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.ExecuteCommand(tc.command)

			if tc.expectError && err == nil {
				t.Errorf("Expected error for command '%s'", tc.command)
			}

			if !tc.expectError && err != nil {
				t.Errorf("Expected no error for command '%s', got: %v", tc.command, err)
			}
		})
	}
}

// TestWorkspaceEndToEnd tests a complete workspace workflow
func TestWorkspaceEndToEnd(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Create multiple workspaces
	commands := []struct {
		cmd         string
		expectError bool
	}{
		{"workspace list", false},
		{"workspace create project-x", false},
		{"workspace create project-y", false},
		{"workspace switch project-x", false},
		{"workspace save", false},
		{"workspace switch project-y", false},
		{"workspace switch project-x", false},
		{"workspace delete project-y", false},
		{"workspace switch project-y", true}, // Should fail, deleted
		{"workspace switch default", false},
	}

	for _, cmd := range commands {
		err := r.ExecuteCommand(cmd.cmd)
		if cmd.expectError && err == nil {
			t.Errorf("Expected error for '%s'", cmd.cmd)
		}
		if !cmd.expectError && err != nil {
			t.Errorf("Command '%s' failed: %v", cmd.cmd, err)
		}
	}
}
