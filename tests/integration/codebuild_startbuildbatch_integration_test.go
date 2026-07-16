package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/codebuild_startbuildbatch"
	_ "github.com/DataDog/pathrunner/pkg/payloads/codebuild" // Register codebuild payloads so PAYLOAD validation works
)

func TestCodeBuildStartBuildBatchModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-003"); err != nil {
		t.Fatalf("Failed to use codebuild-003: %v", err)
	}
}

func TestCodeBuildStartBuildBatchModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-startbuildbatch"); err != nil {
		t.Fatalf("Failed to use codebuild-startbuildbatch alias: %v", err)
	}
}

func TestCodeBuildStartBuildBatchModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-003"); err != nil {
		t.Fatalf("Failed to use codebuild-003: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestCodeBuildStartBuildBatchModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-003"); err != nil {
		t.Fatalf("Failed to use codebuild-003: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestCodeBuildStartBuildBatchModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-003"); err != nil {
		t.Fatalf("Failed to use codebuild-003: %v", err)
	}

	if err := r.ExecuteCommand("set PROJECT_NAME my-privileged-project"); err != nil {
		t.Fatalf("Expected set PROJECT_NAME to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_USER test-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set PAYLOAD backdoor/attach-policy"); err != nil {
		t.Fatalf("Expected set PAYLOAD to succeed: %v", err)
	}
}

func TestCodeBuildStartBuildBatchModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-003"); err != nil {
		t.Fatalf("Failed to use codebuild-003: %v", err)
	}

	if err := r.ExecuteCommand("set PROJECT_NAME my-project"); err != nil {
		t.Fatalf("Failed to set PROJECT_NAME: %v", err)
	}

	if err := r.ExecuteCommand("unset PROJECT_NAME"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}

func TestCodeBuildStartBuildBatchExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-003"); err != nil {
		t.Fatalf("Failed to use codebuild-003: %v", err)
	}

	if err := r.ExecuteCommand("set PROJECT_NAME my-project"); err != nil {
		t.Fatalf("Failed to set PROJECT_NAME: %v", err)
	}

	if err := r.ExecuteCommand("set PAYLOAD backdoor/attach-policy"); err != nil {
		t.Fatalf("Failed to set PAYLOAD: %v", err)
	}

	// Exploit without identity should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestCodeBuildStartBuildBatchSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search codebuild"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}
