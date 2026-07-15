package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/glue_updatejob_startjobrun"
)

func TestGlueUpdatejobStartjobrunModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-005"); err != nil {
		t.Fatalf("Failed to use glue-005: %v", err)
	}
}

func TestGlueUpdatejobStartjobrunModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-updatejob-startjobrun"); err != nil {
		t.Fatalf("Failed to use glue-updatejob-startjobrun alias: %v", err)
	}
}

func TestGlueUpdatejobStartjobrunModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-005"); err != nil {
		t.Fatalf("Failed to use glue-005: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestGlueUpdatejobStartjobrunModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-005"); err != nil {
		t.Fatalf("Failed to use glue-005: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestGlueUpdatejobStartjobrunModuleSetOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-005"); err != nil {
		t.Fatalf("Failed to use glue-005: %v", err)
	}

	if err := r.ExecuteCommand("set JOB_NAME my-existing-glue-job"); err != nil {
		t.Fatalf("Expected set JOB_NAME to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set SCRIPT_S3_URI s3://my-bucket/script.py"); err != nil {
		t.Fatalf("Expected set SCRIPT_S3_URI to succeed: %v", err)
	}
}

func TestGlueUpdatejobStartjobrunExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-005"); err != nil {
		t.Fatalf("Failed to use glue-005: %v", err)
	}

	if err := r.ExecuteCommand("set JOB_NAME my-existing-glue-job"); err != nil {
		t.Fatalf("Failed to set JOB_NAME: %v", err)
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

func TestGlueUpdatejobStartjobrunSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search glue"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestGlueUpdatejobStartjobrunModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-005"); err != nil {
		t.Fatalf("Failed to use glue-005: %v", err)
	}

	if err := r.ExecuteCommand("set JOB_NAME test-job"); err != nil {
		t.Fatalf("Failed to set JOB_NAME: %v", err)
	}

	if err := r.ExecuteCommand("unset JOB_NAME"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}

func TestGlueUpdatejobStartjobrunSearchByService(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for modules should include glue-005
	if err := r.ExecuteCommand("search existing-passrole"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}
