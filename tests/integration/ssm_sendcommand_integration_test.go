package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/ssm_sendcommand"
)

func TestSSMSendCommandModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by primary ID.
	if err := r.ExecuteCommand("use ssm-002"); err != nil {
		t.Fatalf("Failed to use ssm-002: %v", err)
	}
}

func TestSSMSendCommandModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by alias.
	if err := r.ExecuteCommand("use ssm-sendcommand"); err != nil {
		t.Fatalf("Failed to use ssm-sendcommand alias: %v", err)
	}
}

func TestSSMSendCommandModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-002"); err != nil {
		t.Fatalf("Failed to use ssm-002: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestSSMSendCommandModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-002"); err != nil {
		t.Fatalf("Failed to use ssm-002: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestSSMSendCommandModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-002"); err != nil {
		t.Fatalf("Failed to use ssm-002: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_ID i-0abc1234567890def"); err != nil {
		t.Fatalf("Expected set INSTANCE_ID to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestSSMSendCommandExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-002"); err != nil {
		t.Fatalf("Failed to use ssm-002: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_ID i-0abc1234567890def"); err != nil {
		t.Fatalf("Failed to set INSTANCE_ID: %v", err)
	}

	// Should fail with an identity-required error when no identity is set.
	err := r.ExecuteCommand("run")
	if err == nil {
		t.Fatal("Expected run to fail without identity, but it succeeded")
	}
}

func TestSSMSendCommandModuleSearch(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search by service name should surface this module.
	if err := r.ExecuteCommand("search ssm"); err != nil {
		t.Fatalf("Expected search ssm to succeed: %v", err)
	}
}

func TestSSMSendCommandModuleShowInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-002"); err != nil {
		t.Fatalf("Failed to use ssm-002: %v", err)
	}

	if err := r.ExecuteCommand("show info"); err != nil {
		t.Fatalf("Expected show info to succeed: %v", err)
	}
}
