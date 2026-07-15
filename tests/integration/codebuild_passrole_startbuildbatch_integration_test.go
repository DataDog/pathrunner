package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/codebuild_passrole_startbuildbatch"
)

func TestCodeBuildPassroleStartBuildBatchModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-004"); err != nil {
		t.Fatalf("Failed to use codebuild-004: %v", err)
	}
}

func TestCodeBuildPassroleStartBuildBatchModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-passrole-startbuildbatch"); err != nil {
		t.Fatalf("Failed to use codebuild-passrole-startbuildbatch alias: %v", err)
	}
}

func TestCodeBuildPassroleStartBuildBatchModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-004"); err != nil {
		t.Fatalf("Failed to use codebuild-004: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestCodeBuildPassroleStartBuildBatchModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-004"); err != nil {
		t.Fatalf("Failed to use codebuild-004: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestCodeBuildPassroleStartBuildBatchModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-004"); err != nil {
		t.Fatalf("Failed to use codebuild-004: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_USER test-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set PROJECT_NAME my-batch-project"); err != nil {
		t.Fatalf("Expected set PROJECT_NAME to succeed: %v", err)
	}
}

func TestCodeBuildPassroleStartBuildBatchExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-004"); err != nil {
		t.Fatalf("Failed to use codebuild-004: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestCodeBuildPassroleStartBuildBatchSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search codebuild"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestCodeBuildPassroleStartBuildBatchModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-004"); err != nil {
		t.Fatalf("Failed to use codebuild-004: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
