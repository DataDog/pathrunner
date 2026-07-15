package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/glue_passrole_job_createtrigger"
)

func TestGluePassroleJobCreateTriggerModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-004"); err != nil {
		t.Fatalf("Failed to use glue-004: %v", err)
	}
}

func TestGluePassroleJobCreateTriggerModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-passrole-job-createtrigger"); err != nil {
		t.Fatalf("Failed to use glue-passrole-job-createtrigger alias: %v", err)
	}
}

func TestGluePassroleJobCreateTriggerModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-004"); err != nil {
		t.Fatalf("Failed to use glue-004: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestGluePassroleJobCreateTriggerModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-004"); err != nil {
		t.Fatalf("Failed to use glue-004: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestGluePassroleJobCreateTriggerModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-004"); err != nil {
		t.Fatalf("Failed to use glue-004: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_USER test-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set SCRIPT_S3_URI s3://my-bucket/script.py"); err != nil {
		t.Fatalf("Expected set SCRIPT_S3_URI to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TRIGGER_NAME my-trigger"); err != nil {
		t.Fatalf("Expected set TRIGGER_NAME to succeed: %v", err)
	}
}

func TestGluePassroleJobCreateTriggerExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-004"); err != nil {
		t.Fatalf("Failed to use glue-004: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestGluePassroleJobCreateTriggerSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search glue"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestGluePassroleJobCreateTriggerModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-004"); err != nil {
		t.Fatalf("Failed to use glue-004: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
