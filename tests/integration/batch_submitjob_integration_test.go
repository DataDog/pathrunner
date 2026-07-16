package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/batch_submitjob"
)

func TestBatchSubmitJobModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use batch-002"); err != nil {
		t.Fatalf("Failed to use batch-002: %v", err)
	}
}

func TestBatchSubmitJobModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use batch-submitjob"); err != nil {
		t.Fatalf("Failed to use batch-submitjob alias: %v", err)
	}
}

func TestBatchSubmitJobModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use batch-002"); err != nil {
		t.Fatalf("Failed to use batch-002: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestBatchSubmitJobModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use batch-002"); err != nil {
		t.Fatalf("Failed to use batch-002: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestBatchSubmitJobModuleSetOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use batch-002"); err != nil {
		t.Fatalf("Failed to use batch-002: %v", err)
	}

	if err := r.ExecuteCommand("set JOB_DEFINITION pl-prod-batch-002-admin-job-def"); err != nil {
		t.Fatalf("Expected set JOB_DEFINITION to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set JOB_QUEUE pl-prod-batch-002-job-queue"); err != nil {
		t.Fatalf("Expected set JOB_QUEUE to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_USER test-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}
}

func TestBatchSubmitJobExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use batch-002"); err != nil {
		t.Fatalf("Failed to use batch-002: %v", err)
	}

	if err := r.ExecuteCommand("set JOB_DEFINITION my-job-def"); err != nil {
		t.Fatalf("Failed to set JOB_DEFINITION: %v", err)
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

func TestBatchSubmitJobSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search batch"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestBatchSubmitJobModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use batch-002"); err != nil {
		t.Fatalf("Failed to use batch-002: %v", err)
	}

	if err := r.ExecuteCommand("set JOB_DEFINITION my-job-def"); err != nil {
		t.Fatalf("Failed to set JOB_DEFINITION: %v", err)
	}

	if err := r.ExecuteCommand("unset JOB_DEFINITION"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
