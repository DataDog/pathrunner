package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/glue_passrole_devendpoint"
)

func TestGluePassroleDevEndpointModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by primary ID
	if err := r.ExecuteCommand("use glue-001"); err != nil {
		t.Fatalf("Failed to use glue-001: %v", err)
	}
}

func TestGluePassroleDevEndpointModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by alias
	if err := r.ExecuteCommand("use glue-passrole-devendpoint"); err != nil {
		t.Fatalf("Failed to use glue-passrole-devendpoint alias: %v", err)
	}
}

func TestGluePassroleDevEndpointModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-001"); err != nil {
		t.Fatalf("Failed to use glue-001: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestGluePassroleDevEndpointModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-001"); err != nil {
		t.Fatalf("Failed to use glue-001: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestGluePassroleDevEndpointModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-001"); err != nil {
		t.Fatalf("Failed to use glue-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set ENDPOINT_NAME my-test-endpoint"); err != nil {
		t.Fatalf("Expected set ENDPOINT_NAME to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set SSH_PUBLIC_KEY ssh-rsa-AAAAB3NzaC1yc2EAAAADAQABAAABgQC"); err != nil {
		t.Fatalf("Expected set SSH_PUBLIC_KEY to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-west-2"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestGluePassroleDevEndpointExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-001"); err != nil {
		t.Fatalf("Failed to use glue-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	// Exploit without identity should fail with an identity-required error
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestGluePassroleDevEndpointSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search glue"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestGluePassroleDevEndpointModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-001"); err != nil {
		t.Fatalf("Failed to use glue-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
