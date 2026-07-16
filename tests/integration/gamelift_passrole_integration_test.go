package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/gamelift_passrole"
	_ "github.com/DataDog/pathrunner/pkg/payloads/gamelift"
)

func TestGameLiftPassRoleModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use gamelift-001"); err != nil {
		t.Fatalf("Failed to use gamelift-001: %v", err)
	}
}

func TestGameLiftPassRoleModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use gamelift-passrole"); err != nil {
		t.Fatalf("Failed to use gamelift-passrole alias: %v", err)
	}
}

func TestGameLiftPassRoleModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use gamelift-001"); err != nil {
		t.Fatalf("Failed to use gamelift-001: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestGameLiftPassRoleModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use gamelift-001"); err != nil {
		t.Fatalf("Failed to use gamelift-001: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestGameLiftPassRoleModuleSetOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use gamelift-001"); err != nil {
		t.Fatalf("Failed to use gamelift-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/pl-prod-gamelift-001-to-admin-admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set PAYLOAD backdoor/attach-policy"); err != nil {
		t.Fatalf("Expected set PAYLOAD to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_USER pl-prod-gamelift-001-to-admin-starting-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestGameLiftPassRoleExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use gamelift-001"); err != nil {
		t.Fatalf("Failed to use gamelift-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/AdminRole"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}
	if err := r.ExecuteCommand("set PAYLOAD backdoor/attach-policy"); err != nil {
		t.Fatalf("Failed to set PAYLOAD: %v", err)
	}
	if err := r.ExecuteCommand("set TARGET_USER some-user"); err != nil {
		t.Fatalf("Failed to set TARGET_USER: %v", err)
	}

	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestGameLiftPassRoleSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search gamelift"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestGameLiftPassRoleModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use gamelift-001"); err != nil {
		t.Fatalf("Failed to use gamelift-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/AdminRole"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}

func TestGameLiftPassRoleListPayloads(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use gamelift-001"); err != nil {
		t.Fatalf("Failed to use gamelift-001: %v", err)
	}

	if err := r.ExecuteCommand("show payloads"); err != nil {
		t.Fatalf("Expected show payloads to succeed: %v", err)
	}
}
