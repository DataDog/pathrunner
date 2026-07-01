package integration

import (
	"pathrunner/pkg/modules"
	"testing"
)

func TestAttackerCommandFlow(t *testing.T) {
	r, _, identityManager, cleanup := setupTest(t)
	defer cleanup()

	// Initially no attacker identity
	if identityManager.GetAttackerIdentity() != nil {
		t.Fatal("Expected no attacker identity initially")
	}

	// Show should succeed with no attacker
	if err := r.ExecuteCommand("attacker show"); err != nil {
		t.Fatalf("Expected attacker show to succeed, got: %v", err)
	}

	// Clear should succeed with no attacker
	if err := r.ExecuteCommand("attacker clear"); err != nil {
		t.Fatalf("Expected attacker clear to succeed, got: %v", err)
	}

	// Help should work
	if err := r.ExecuteCommand("attacker help"); err != nil {
		t.Fatalf("Expected attacker help to succeed, got: %v", err)
	}

	// Set help should work
	if err := r.ExecuteCommand("attacker set help"); err != nil {
		t.Fatalf("Expected attacker set help to succeed, got: %v", err)
	}
}

func TestAttackerSetValidation(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Missing source
	if err := r.ExecuteCommand("attacker set"); err == nil {
		t.Error("Expected error for attacker set with no source")
	}

	// Missing profile name
	if err := r.ExecuteCommand("attacker set profile"); err == nil {
		t.Error("Expected error for attacker set profile without name")
	}

	// Missing keys flags
	if err := r.ExecuteCommand("attacker set keys"); err == nil {
		t.Error("Expected error for attacker set keys without flags")
	}

	// Missing secret key
	if err := r.ExecuteCommand("attacker set keys --access AKIAEXAMPLE"); err == nil {
		t.Error("Expected error for attacker set keys without --secret")
	}

	// Unknown source
	if err := r.ExecuteCommand("attacker set banana"); err == nil {
		t.Error("Expected error for unknown set source")
	}
}

func TestAttackerValidateNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("attacker validate")
	if err == nil {
		t.Error("Expected error when validating with no attacker identity")
	}
}

func TestAttackerUnknownSubcommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("attacker notacommand")
	if err == nil {
		t.Error("Expected error for unknown attacker subcommand")
	}
}

func TestAttackerIdentityPersistence(t *testing.T) {
	r, _, identityManager, cleanup := setupTest(t)
	defer cleanup()

	// Manually set an attacker identity to test persistence
	attackerIdentity := &modules.Identity{
		Name:   "attacker/test-profile",
		Type:   "keys",
		Region: "us-west-2",
		AccessKeyID: "AKIAEXAMPLE1234",
		SecretKey:   "wJalrXUtnFEMI",
	}
	identityManager.SetAttackerIdentity(attackerIdentity)

	// Verify it's set
	if identityManager.GetAttackerIdentity() == nil {
		t.Fatal("Expected attacker identity to be set")
	}
	if identityManager.GetAttackerIdentity().Name != "attacker/test-profile" {
		t.Errorf("Expected attacker name 'attacker/test-profile', got '%s'", identityManager.GetAttackerIdentity().Name)
	}

	// Show should display attacker info
	if err := r.ExecuteCommand("attacker show"); err != nil {
		t.Fatalf("Expected attacker show to succeed, got: %v", err)
	}

	// Clear and verify
	if err := r.ExecuteCommand("attacker clear"); err != nil {
		t.Fatalf("Expected attacker clear to succeed, got: %v", err)
	}

	if identityManager.GetAttackerIdentity() != nil {
		t.Error("Expected attacker identity to be nil after clear")
	}
}

func TestAttackerWorkspaceIsolation(t *testing.T) {
	r, _, identityManager, cleanup := setupTest(t)
	defer cleanup()

	// Set attacker in default workspace
	attackerIdentity := &modules.Identity{
		Name:   "attacker/workspace-a",
		Type:   "keys",
		Region: "us-east-1",
		AccessKeyID: "AKIAEXAMPLEA",
		SecretKey:   "secretA",
	}
	identityManager.SetAttackerIdentity(attackerIdentity)

	// Create a new workspace and switch to it
	if err := r.ExecuteCommand("workspace create test-workspace"); err != nil {
		t.Fatalf("Failed to create workspace: %v", err)
	}

	// The new workspace should not have an attacker identity
	if identityManager.GetAttackerIdentity() != nil {
		t.Error("Expected no attacker identity in new workspace")
	}

	// Switch back to default
	if err := r.ExecuteCommand("workspace switch default"); err != nil {
		t.Fatalf("Failed to switch workspace: %v", err)
	}

	// Attacker identity should be restored from session
	restoredAttacker := identityManager.GetAttackerIdentity()
	if restoredAttacker == nil {
		t.Fatal("Expected attacker identity to be restored after workspace switch")
	}
	if restoredAttacker.Name != "attacker/workspace-a" {
		t.Errorf("Expected restored attacker name 'attacker/workspace-a', got '%s'", restoredAttacker.Name)
	}
}

func TestAttackerDefaultSubcommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Running 'attacker' alone should default to show
	if err := r.ExecuteCommand("attacker"); err != nil {
		t.Errorf("Expected attacker (default) to succeed, got: %v", err)
	}
}

func TestAttackerContextDisplay(t *testing.T) {
	r, _, identityManager, cleanup := setupTest(t)
	defer cleanup()

	// Set attacker identity
	attackerIdentity := &modules.Identity{
		Name:      "attacker/ctx-test",
		Type:      "keys",
		Region:    "eu-west-1",
		CallerARN: "arn:aws:iam::999888777666:user/attacker",
	}
	identityManager.SetAttackerIdentity(attackerIdentity)

	// Context command should succeed (attacker section will be displayed)
	if err := r.ExecuteCommand("context"); err != nil {
		t.Fatalf("Expected context to succeed, got: %v", err)
	}
}
