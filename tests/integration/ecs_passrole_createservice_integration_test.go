package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/ecs_passrole_createservice"
)

func TestECSPassroleCreateserviceModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by ID
	if err := r.ExecuteCommand("use ecs-003"); err != nil {
		t.Fatalf("Failed to use ecs-003: %v", err)
	}
}

func TestECSPassroleCreateserviceModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by alias
	if err := r.ExecuteCommand("use ecs-passrole-createservice"); err != nil {
		t.Fatalf("Failed to use ecs-passrole-createservice alias: %v", err)
	}
}

func TestECSPassroleCreateserviceModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-003"); err != nil {
		t.Fatalf("Failed to use ecs-003: %v", err)
	}

	// Info should succeed
	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestECSPassroleCreateserviceModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-003"); err != nil {
		t.Fatalf("Failed to use ecs-003: %v", err)
	}

	// Show options should succeed
	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestECSPassroleCreateserviceModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-003"); err != nil {
		t.Fatalf("Failed to use ecs-003: %v", err)
	}

	// Set ROLE_ARN
	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	// Set CLUSTER_ARN
	if err := r.ExecuteCommand("set CLUSTER_ARN arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster"); err != nil {
		t.Fatalf("Expected set CLUSTER_ARN to succeed: %v", err)
	}

	// Set TARGET_ARN
	if err := r.ExecuteCommand("set TARGET_ARN arn:aws:iam::123456789012:user/test-user"); err != nil {
		t.Fatalf("Expected set TARGET_ARN to succeed: %v", err)
	}
}

func TestECSPassroleCreateserviceExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-003"); err != nil {
		t.Fatalf("Failed to use ecs-003: %v", err)
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

func TestECSPassroleCreateserviceSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for ECS modules should include ecs-003
	if err := r.ExecuteCommand("search ecs"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestECSPassroleCreateserviceModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-003"); err != nil {
		t.Fatalf("Failed to use ecs-003: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	// Unset should work
	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
