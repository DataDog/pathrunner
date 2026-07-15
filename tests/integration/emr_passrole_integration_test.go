package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/emr_passrole"
	_ "pathrunner/pkg/payloads/emr"
)

func TestEMRPassroleModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emr-001"); err != nil {
		t.Fatalf("Failed to use emr-001: %v", err)
	}
}

func TestEMRPassroleModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emr-passrole"); err != nil {
		t.Fatalf("Failed to use emr-passrole alias: %v", err)
	}
}

func TestEMRPassroleModuleUseExploitAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use exploit/emr_passrole"); err != nil {
		t.Fatalf("Failed to use exploit/emr_passrole alias: %v", err)
	}
}

func TestEMRPassroleModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emr-001"); err != nil {
		t.Fatalf("Failed to use emr-001: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestEMRPassroleModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emr-001"); err != nil {
		t.Fatalf("Failed to use emr-001: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestEMRPassroleModuleSetOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emr-001"); err != nil {
		t.Fatalf("Failed to use emr-001: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_PROFILE pl-prod-emr-001-to-admin-admin-role"); err != nil {
		t.Fatalf("Expected set INSTANCE_PROFILE to succeed: %v", err)
	}
	if err := r.ExecuteCommand("set SERVICE_ROLE pl-prod-emr-001-to-admin-service-role"); err != nil {
		t.Fatalf("Expected set SERVICE_ROLE to succeed: %v", err)
	}
	if err := r.ExecuteCommand("set PAYLOAD backdoor/attach-policy"); err != nil {
		t.Fatalf("Expected set PAYLOAD to succeed: %v", err)
	}
	if err := r.ExecuteCommand("set TARGET_ARN arn:aws:iam::123456789012:user/test-user"); err != nil {
		t.Fatalf("Expected set TARGET_ARN to succeed: %v", err)
	}
}

func TestEMRPassroleExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emr-001"); err != nil {
		t.Fatalf("Failed to use emr-001: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_PROFILE test-profile"); err != nil {
		t.Fatalf("Failed to set INSTANCE_PROFILE: %v", err)
	}
	if err := r.ExecuteCommand("set SERVICE_ROLE test-service-role"); err != nil {
		t.Fatalf("Failed to set SERVICE_ROLE: %v", err)
	}
	if err := r.ExecuteCommand("set PAYLOAD backdoor/attach-policy"); err != nil {
		t.Fatalf("Failed to set PAYLOAD: %v", err)
	}
	if err := r.ExecuteCommand("set TARGET_ARN test-user"); err != nil {
		t.Fatalf("Failed to set TARGET_ARN: %v", err)
	}

	// Should fail with identity required error, not a panic
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Fatal("Expected error when no identity set")
	}
}

func TestEMRPassroleSearchModule(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search emr"); err != nil {
		t.Fatalf("Expected search emr to succeed: %v", err)
	}
}

func TestEMRPassroleListPayloads(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use emr-001"); err != nil {
		t.Fatalf("Failed to use emr-001: %v", err)
	}

	if err := r.ExecuteCommand("show payloads"); err != nil {
		t.Fatalf("Expected show payloads to succeed: %v", err)
	}
}
