package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/glue_passrole_job"
)

func TestGluePassroleJobModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by ID
	if err := r.ExecuteCommand("use glue-003"); err != nil {
		t.Fatalf("Failed to use glue-003: %v", err)
	}
}

func TestGluePassroleJobModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by alias
	if err := r.ExecuteCommand("use glue-passrole-job"); err != nil {
		t.Fatalf("Failed to use glue-passrole-job alias: %v", err)
	}
}

func TestGluePassroleJobModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-003"); err != nil {
		t.Fatalf("Failed to use glue-003: %v", err)
	}

	// Info should succeed
	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestGluePassroleJobModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-003"); err != nil {
		t.Fatalf("Failed to use glue-003: %v", err)
	}

	// Show options should succeed
	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestGluePassroleJobModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-003"); err != nil {
		t.Fatalf("Failed to use glue-003: %v", err)
	}

	// Set ROLE_ARN
	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	// Set TARGET_USER
	if err := r.ExecuteCommand("set TARGET_USER test-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}

	// Set SCRIPT_S3_URI
	if err := r.ExecuteCommand("set SCRIPT_S3_URI s3://my-bucket/script.py"); err != nil {
		t.Fatalf("Expected set SCRIPT_S3_URI to succeed: %v", err)
	}
}

func TestGluePassroleJobExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-003"); err != nil {
		t.Fatalf("Failed to use glue-003: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	// Exploit without identity should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestGluePassroleJobSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for Glue modules should include glue-003
	if err := r.ExecuteCommand("search glue"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestGluePassroleJobModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-003"); err != nil {
		t.Fatalf("Failed to use glue-003: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	// Unset should work
	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
