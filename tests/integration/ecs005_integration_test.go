package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/ecs_registertaskdefinition_runtask"
)

func TestEcs005ModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-005"); err != nil {
		t.Fatalf("Failed to use ecs-005: %v", err)
	}
}

func TestEcs005ModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-passrole-registertaskdefinition-starttask"); err != nil {
		t.Fatalf("Failed to use ecs-passrole-registertaskdefinition-starttask alias: %v", err)
	}
}

func TestEcs005ModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-005"); err != nil {
		t.Fatalf("Failed to use ecs-005: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestEcs005ModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-005"); err != nil {
		t.Fatalf("Failed to use ecs-005: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestEcs005ModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-005"); err != nil {
		t.Fatalf("Failed to use ecs-005: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set CLUSTER_NAME my-cluster"); err != nil {
		t.Fatalf("Expected set CLUSTER_NAME to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set CONTAINER_INSTANCE_ARN arn:aws:ecs:us-east-1:123456789012:container-instance/test"); err != nil {
		t.Fatalf("Expected set CONTAINER_INSTANCE_ARN to succeed: %v", err)
	}
}

func TestEcs005ExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-005"); err != nil {
		t.Fatalf("Failed to use ecs-005: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("set CLUSTER_NAME test-cluster"); err != nil {
		t.Fatalf("Failed to set CLUSTER_NAME: %v", err)
	}

	if err := r.ExecuteCommand("set CONTAINER_INSTANCE_ARN arn:aws:ecs:us-east-1:123456789012:container-instance/test"); err != nil {
		t.Fatalf("Failed to set CONTAINER_INSTANCE_ARN: %v", err)
	}

	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestEcs005Searchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search ecs"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}
