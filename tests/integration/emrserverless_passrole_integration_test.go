package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/emrserverless_passrole"
)

func TestEMRServerlessPassroleModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emrserverless-001"); err != nil {
		t.Fatalf("Failed to use emrserverless-001: %v", err)
	}
}

func TestEMRServerlessPassroleModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emrserverless-passrole"); err != nil {
		t.Fatalf("Failed to use emrserverless-passrole alias: %v", err)
	}
}

func TestEMRServerlessPassroleModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emrserverless-001"); err != nil {
		t.Fatalf("Failed to use emrserverless-001: %v", err)
	}
	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestEMRServerlessPassroleModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emrserverless-001"); err != nil {
		t.Fatalf("Failed to use emrserverless-001: %v", err)
	}
	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestEMRServerlessPassroleModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emrserverless-001"); err != nil {
		t.Fatalf("Failed to use emrserverless-001: %v", err)
	}
	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set EXECUTION_ROLE_ARN to succeed: %v", err)
	}
	if err := r.ExecuteCommand("set SCRIPT_BUCKET my-attacker-bucket"); err != nil {
		t.Fatalf("Expected set SCRIPT_BUCKET to succeed: %v", err)
	}
	if err := r.ExecuteCommand("set REGION us-west-2"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
	if err := r.ExecuteCommand("set TARGET_USER victim-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}
}

func TestEMRServerlessPassroleExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emrserverless-001"); err != nil {
		t.Fatalf("Failed to use emrserverless-001: %v", err)
	}
	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/admin"); err != nil {
		t.Fatalf("Failed to set EXECUTION_ROLE_ARN: %v", err)
	}

	// Exploit without identity should fail with identity required error.
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestEMRServerlessPassroleSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search emrserverless"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestEMRServerlessPassroleModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emrserverless-001"); err != nil {
		t.Fatalf("Failed to use emrserverless-001: %v", err)
	}
	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set EXECUTION_ROLE_ARN: %v", err)
	}
	if err := r.ExecuteCommand("unset EXECUTION_ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}

func TestEMRServerlessPassroleModuleShowInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emrserverless-001"); err != nil {
		t.Fatalf("Failed to use emrserverless-001: %v", err)
	}
	if err := r.ExecuteCommand("show info"); err != nil {
		t.Fatalf("Expected show info to succeed: %v", err)
	}
}
