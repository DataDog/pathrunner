// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/ecs_starttask_registercontainerinstance"
)

func TestEcsStarttaskRegistercontainerinstanceModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by ID
	if err := r.ExecuteCommand("use ecs-007"); err != nil {
		t.Fatalf("Failed to use ecs-007: %v", err)
	}
}

func TestEcsStarttaskRegistercontainerinstanceModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by alias
	if err := r.ExecuteCommand("use ecs-starttask-registercontainerinstance"); err != nil {
		t.Fatalf("Failed to use ecs-starttask-registercontainerinstance alias: %v", err)
	}
}

func TestEcsStarttaskRegistercontainerinstanceModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-007"); err != nil {
		t.Fatalf("Failed to use ecs-007: %v", err)
	}

	// Info should succeed
	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestEcsStarttaskRegistercontainerinstanceModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-007"); err != nil {
		t.Fatalf("Failed to use ecs-007: %v", err)
	}

	// Show options should succeed
	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestEcsStarttaskRegistercontainerinstanceModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-007"); err != nil {
		t.Fatalf("Failed to use ecs-007: %v", err)
	}

	// Set ROLE_ARN
	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	// Set CLUSTER_NAME
	if err := r.ExecuteCommand("set CLUSTER_NAME my-ecs-cluster"); err != nil {
		t.Fatalf("Expected set CLUSTER_NAME to succeed: %v", err)
	}

	// Set CONTAINER_INSTANCE_ARN
	if err := r.ExecuteCommand("set CONTAINER_INSTANCE_ARN arn:aws:ecs:us-east-1:123456789012:container-instance/my-cluster/abc123"); err != nil {
		t.Fatalf("Expected set CONTAINER_INSTANCE_ARN to succeed: %v", err)
	}

	// Set TASK_DEFINITION
	if err := r.ExecuteCommand("set TASK_DEFINITION my-existing-task"); err != nil {
		t.Fatalf("Expected set TASK_DEFINITION to succeed: %v", err)
	}

	// Set CONTAINER_NAME
	if err := r.ExecuteCommand("set CONTAINER_NAME my-container"); err != nil {
		t.Fatalf("Expected set CONTAINER_NAME to succeed: %v", err)
	}
}

func TestEcsStarttaskRegistercontainerinstanceExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-007"); err != nil {
		t.Fatalf("Failed to use ecs-007: %v", err)
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

func TestEcsStarttaskRegistercontainerinstanceSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for ECS modules should include ecs-007
	if err := r.ExecuteCommand("search ecs"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestEcsStarttaskRegistercontainerinstanceModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-007"); err != nil {
		t.Fatalf("Failed to use ecs-007: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	// Unset should work
	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
