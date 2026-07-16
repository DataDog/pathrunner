package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/ssm_startsession"
)

func TestSSMStartSessionModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by primary ID.
	if err := r.ExecuteCommand("use ssm-001"); err != nil {
		t.Fatalf("Failed to use ssm-001: %v", err)
	}
}

func TestSSMStartSessionModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by alias.
	if err := r.ExecuteCommand("use ssm-startsession"); err != nil {
		t.Fatalf("Failed to use ssm-startsession alias: %v", err)
	}
}

func TestSSMStartSessionModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-001"); err != nil {
		t.Fatalf("Failed to use ssm-001: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestSSMStartSessionModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-001"); err != nil {
		t.Fatalf("Failed to use ssm-001: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestSSMStartSessionModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-001"); err != nil {
		t.Fatalf("Failed to use ssm-001: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_ID i-0abc1234567890def"); err != nil {
		t.Fatalf("Expected set INSTANCE_ID to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_USER my-iam-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}
}

func TestSSMStartSessionExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-001"); err != nil {
		t.Fatalf("Failed to use ssm-001: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_ID i-0abc1234567890def"); err != nil {
		t.Fatalf("Failed to set INSTANCE_ID: %v", err)
	}

	// Exploit without identity should fail.
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestSSMStartSessionSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Searching by alias should find the module.
	if err := r.ExecuteCommand("search ssm-startsession"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestSSMStartSessionSearchByService(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Searching by service should include ssm-001.
	if err := r.ExecuteCommand("search ssm"); err != nil {
		t.Fatalf("Expected search by service to succeed: %v", err)
	}
}

func TestSSMStartSessionModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-001"); err != nil {
		t.Fatalf("Failed to use ssm-001: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_ID i-0abc1234567890def"); err != nil {
		t.Fatalf("Failed to set INSTANCE_ID: %v", err)
	}

	if err := r.ExecuteCommand("unset INSTANCE_ID"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
