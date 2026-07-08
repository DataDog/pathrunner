package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/ecs_passrole_starttask"
)

func TestEcsPassroleStarttaskModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by ID
	if err := r.ExecuteCommand("use ecs-009"); err != nil {
		t.Fatalf("Failed to use ecs-009: %v", err)
	}
}

func TestEcsPassroleStarttaskModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by alias
	if err := r.ExecuteCommand("use ecs-passrole-starttask"); err != nil {
		t.Fatalf("Failed to use ecs-passrole-starttask alias: %v", err)
	}
}

func TestEcsPassroleStarttaskModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-009"); err != nil {
		t.Fatalf("Failed to use ecs-009: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestEcsPassroleStarttaskModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-009"); err != nil {
		t.Fatalf("Failed to use ecs-009: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestEcsPassroleStarttaskModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-009"); err != nil {
		t.Fatalf("Failed to use ecs-009: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set CLUSTER_NAME my-ecs-cluster"); err != nil {
		t.Fatalf("Expected set CLUSTER_NAME to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set CONTAINER_INSTANCE_ARN arn:aws:ecs:us-east-1:123456789012:container-instance/my-cluster/abc123"); err != nil {
		t.Fatalf("Expected set CONTAINER_INSTANCE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TASK_DEFINITION my-existing-task"); err != nil {
		t.Fatalf("Expected set TASK_DEFINITION to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set CONTAINER_NAME my-container"); err != nil {
		t.Fatalf("Expected set CONTAINER_NAME to succeed: %v", err)
	}
}

func TestEcsPassroleStarttaskExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-009"); err != nil {
		t.Fatalf("Failed to use ecs-009: %v", err)
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

func TestEcsPassroleStarttaskSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for ECS modules should include ecs-009
	if err := r.ExecuteCommand("search ecs"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestEcsPassroleStarttaskModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-009"); err != nil {
		t.Fatalf("Failed to use ecs-009: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
