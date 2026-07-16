package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/glue_updatejob_createtrigger"
)

func TestGlueUpdatejobCreateTriggerModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-006"); err != nil {
		t.Fatalf("Failed to use glue-006: %v", err)
	}
}

func TestGlueUpdatejobCreateTriggerModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-updatejob-createtrigger"); err != nil {
		t.Fatalf("Failed to use glue-updatejob-createtrigger alias: %v", err)
	}
}

func TestGlueUpdatejobCreateTriggerModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-006"); err != nil {
		t.Fatalf("Failed to use glue-006: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestGlueUpdatejobCreateTriggerModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-006"); err != nil {
		t.Fatalf("Failed to use glue-006: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestGlueUpdatejobCreateTriggerModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-006"); err != nil {
		t.Fatalf("Failed to use glue-006: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set JOB_NAME existing-glue-job"); err != nil {
		t.Fatalf("Expected set JOB_NAME to succeed: %v", err)
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

func TestGlueUpdatejobCreateTriggerExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-006"); err != nil {
		t.Fatalf("Failed to use glue-006: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("set JOB_NAME existing-glue-job"); err != nil {
		t.Fatalf("Failed to set JOB_NAME: %v", err)
	}

	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestGlueUpdatejobCreateTriggerSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search glue"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestGlueUpdatejobCreateTriggerModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-006"); err != nil {
		t.Fatalf("Failed to use glue-006: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
