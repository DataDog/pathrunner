package integration

import (
	"pathrunner/pkg/modules"
	"testing"
)

func TestAttackerIdentityCommandFlow(t *testing.T) {
	r, _, identityManager, cleanup := setupTest(t)
	defer cleanup()

	// Initially no attacker identity
	if identityManager.GetAttackerIdentity() != nil {
		t.Fatal("Expected no attacker identity initially")
	}

	// Show should succeed with no attacker
	if err := r.ExecuteCommand("attacker identity show"); err != nil {
		t.Fatalf("Expected attacker identity show to succeed, got: %v", err)
	}

	// Remove should succeed with no attacker
	if err := r.ExecuteCommand("attacker identity remove"); err != nil {
		t.Fatalf("Expected attacker identity remove to succeed, got: %v", err)
	}

	// Help should work
	if err := r.ExecuteCommand("attacker help"); err != nil {
		t.Fatalf("Expected attacker help to succeed, got: %v", err)
	}

	// Identity help should work
	if err := r.ExecuteCommand("attacker identity help"); err != nil {
		t.Fatalf("Expected attacker identity help to succeed, got: %v", err)
	}

	// Identity add help should work
	if err := r.ExecuteCommand("attacker identity add help"); err != nil {
		t.Fatalf("Expected attacker identity add help to succeed, got: %v", err)
	}
}

func TestAttackerIdentityAddValidation(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Missing source
	if err := r.ExecuteCommand("attacker identity add"); err == nil {
		t.Error("Expected error for attacker identity add with no source")
	}

	// Missing profile name
	if err := r.ExecuteCommand("attacker identity add profile"); err == nil {
		t.Error("Expected error for attacker identity add profile without name")
	}

	// Missing keys flags
	if err := r.ExecuteCommand("attacker identity add keys"); err == nil {
		t.Error("Expected error for attacker identity add keys without flags")
	}

	// Missing secret key
	if err := r.ExecuteCommand("attacker identity add keys --access AKIAEXAMPLE"); err == nil {
		t.Error("Expected error for attacker identity add keys without --secret")
	}

	// Unknown source
	if err := r.ExecuteCommand("attacker identity add banana"); err == nil {
		t.Error("Expected error for unknown add source")
	}
}

func TestAttackerIdentityValidateNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("attacker identity validate")
	if err == nil {
		t.Error("Expected error when validating with no attacker identity")
	}
}

func TestAttackerIdentityUnknownSubcommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("attacker identity notacommand")
	if err == nil {
		t.Error("Expected error for unknown attacker identity subcommand")
	}
}

func TestAttackerIdentityPersistence(t *testing.T) {
	r, _, identityManager, cleanup := setupTest(t)
	defer cleanup()

	// Manually set an attacker identity to test persistence
	attackerIdentity := &modules.Identity{
		Name:        "attacker/test-profile",
		Type:        "keys",
		Region:      "us-west-2",
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
	if err := r.ExecuteCommand("attacker identity show"); err != nil {
		t.Fatalf("Expected attacker identity show to succeed, got: %v", err)
	}

	// Remove and verify
	if err := r.ExecuteCommand("attacker identity remove"); err != nil {
		t.Fatalf("Expected attacker identity remove to succeed, got: %v", err)
	}

	if identityManager.GetAttackerIdentity() != nil {
		t.Error("Expected attacker identity to be nil after remove")
	}
}

func TestAttackerIdentitySharedAcrossWorkspaces(t *testing.T) {
	r, _, identityManager, cleanup := setupTest(t)
	defer cleanup()

	// Set attacker in default workspace
	attackerIdentity := &modules.Identity{
		Name:        "attacker/shared-test",
		Type:        "keys",
		Region:      "us-east-1",
		AccessKeyID: "AKIAEXAMPLEA",
		SecretKey:   "secretA",
	}
	identityManager.SetAttackerIdentity(attackerIdentity)

	// Create a new workspace and switch to it
	if err := r.ExecuteCommand("workspace create test-workspace"); err != nil {
		t.Fatalf("Failed to create workspace: %v", err)
	}

	// The attacker identity should still be available in the new workspace
	if identityManager.GetAttackerIdentity() == nil {
		t.Fatal("Expected attacker identity to be shared across workspaces")
	}
	if identityManager.GetAttackerIdentity().Name != "attacker/shared-test" {
		t.Errorf("Expected attacker name 'attacker/shared-test', got '%s'", identityManager.GetAttackerIdentity().Name)
	}

	// Switch back to default
	if err := r.ExecuteCommand("workspace switch default"); err != nil {
		t.Fatalf("Failed to switch workspace: %v", err)
	}

	// Attacker identity should still be there
	if identityManager.GetAttackerIdentity() == nil {
		t.Fatal("Expected attacker identity to persist after workspace switch")
	}
	if identityManager.GetAttackerIdentity().Name != "attacker/shared-test" {
		t.Errorf("Expected attacker name 'attacker/shared-test', got '%s'", identityManager.GetAttackerIdentity().Name)
	}
}

func TestAttackerDefaultSubcommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Running 'attacker' alone should default to identity show
	if err := r.ExecuteCommand("attacker"); err != nil {
		t.Errorf("Expected attacker (default) to succeed, got: %v", err)
	}

	// Running 'attacker identity' alone should default to show
	if err := r.ExecuteCommand("attacker identity"); err != nil {
		t.Errorf("Expected attacker identity (default) to succeed, got: %v", err)
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

// Legacy alias tests — ensure old commands still route correctly

func TestAttackerLegacyShowAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("attacker show"); err != nil {
		t.Fatalf("Expected attacker show (legacy) to succeed, got: %v", err)
	}
}

func TestAttackerLegacyClearAlias(t *testing.T) {
	r, _, identityManager, cleanup := setupTest(t)
	defer cleanup()

	attackerIdentity := &modules.Identity{
		Name:        "attacker/legacy-test",
		Type:        "keys",
		Region:      "us-east-1",
		AccessKeyID: "AKIALEGACY",
		SecretKey:   "secretLegacy",
	}
	identityManager.SetAttackerIdentity(attackerIdentity)

	if err := r.ExecuteCommand("attacker clear"); err != nil {
		t.Fatalf("Expected attacker clear (legacy) to succeed, got: %v", err)
	}

	if identityManager.GetAttackerIdentity() != nil {
		t.Error("Expected attacker identity to be nil after legacy clear")
	}
}

func TestAttackerLegacySetValidation(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("attacker set"); err == nil {
		t.Error("Expected error for attacker set with no source")
	}

	if err := r.ExecuteCommand("attacker set profile"); err == nil {
		t.Error("Expected error for attacker set profile without name")
	}

	if err := r.ExecuteCommand("attacker set keys"); err == nil {
		t.Error("Expected error for attacker set keys without flags")
	}

	if err := r.ExecuteCommand("attacker set help"); err != nil {
		t.Fatalf("Expected attacker set help to succeed, got: %v", err)
	}
}

func TestAttackerLegacyValidateNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("attacker validate")
	if err == nil {
		t.Error("Expected error when validating with no attacker identity (legacy)")
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
