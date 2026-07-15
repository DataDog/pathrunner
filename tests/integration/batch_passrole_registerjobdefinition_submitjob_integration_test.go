package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/batch_passrole_registerjobdefinition_submitjob"
)

func TestBatchPassroleRegisterJobDefinitionSubmitJobModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use batch-001"); err != nil {
		t.Fatalf("Failed to use batch-001: %v", err)
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use batch-passrole"); err != nil {
		t.Fatalf("Failed to use batch-passrole alias: %v", err)
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use batch-001"); err != nil {
		t.Fatalf("Failed to use batch-001: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use batch-001"); err != nil {
		t.Fatalf("Failed to use batch-001: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobModuleSetOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use batch-001"); err != nil {
		t.Fatalf("Failed to use batch-001: %v", err)
	}

	if err := r.ExecuteCommand("set ADMIN_ROLE_ARN arn:aws:iam::123456789012:role/pl-prod-batch-001-to-admin-admin-role"); err != nil {
		t.Fatalf("Expected set ADMIN_ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/pl-prod-batch-001-to-admin-execution-role"); err != nil {
		t.Fatalf("Expected set EXECUTION_ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set JOB_QUEUE pl-prod-batch-001-to-admin-job-queue"); err != nil {
		t.Fatalf("Expected set JOB_QUEUE to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_USER pl-prod-batch-001-to-admin-starting-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use batch-001"); err != nil {
		t.Fatalf("Failed to use batch-001: %v", err)
	}

	if err := r.ExecuteCommand("set ADMIN_ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ADMIN_ROLE_ARN: %v", err)
	}
	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/exec-role"); err != nil {
		t.Fatalf("Failed to set EXECUTION_ROLE_ARN: %v", err)
	}
	if err := r.ExecuteCommand("set JOB_QUEUE my-queue"); err != nil {
		t.Fatalf("Failed to set JOB_QUEUE: %v", err)
	}
	if err := r.ExecuteCommand("set TARGET_USER some-user"); err != nil {
		t.Fatalf("Failed to set TARGET_USER: %v", err)
	}

	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search batch"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use batch-001"); err != nil {
		t.Fatalf("Failed to use batch-001: %v", err)
	}

	if err := r.ExecuteCommand("set ADMIN_ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ADMIN_ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("unset ADMIN_ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
