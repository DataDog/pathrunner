// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/ecs_executecommand"
)

func TestEcsExecutecommandModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by ID
	if err := r.ExecuteCommand("use ecs-006"); err != nil {
		t.Fatalf("Failed to use ecs-006: %v", err)
	}
}

func TestEcsExecutecommandModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by alias
	if err := r.ExecuteCommand("use ecs-executecommand"); err != nil {
		t.Fatalf("Failed to use ecs-executecommand alias: %v", err)
	}
}

func TestEcsExecutecommandModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-006"); err != nil {
		t.Fatalf("Failed to use ecs-006: %v", err)
	}

	// Info should succeed
	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestEcsExecutecommandModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-006"); err != nil {
		t.Fatalf("Failed to use ecs-006: %v", err)
	}

	// Show options should succeed
	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestEcsExecutecommandModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-006"); err != nil {
		t.Fatalf("Failed to use ecs-006: %v", err)
	}

	// Set CLUSTER_NAME
	if err := r.ExecuteCommand("set CLUSTER_NAME my-cluster"); err != nil {
		t.Fatalf("Expected set CLUSTER_NAME to succeed: %v", err)
	}

	// Set TASK_ARN
	if err := r.ExecuteCommand("set TASK_ARN arn:aws:ecs:us-east-1:123456789012:task/my-cluster/abc123"); err != nil {
		t.Fatalf("Expected set TASK_ARN to succeed: %v", err)
	}

	// Set CONTAINER_NAME
	if err := r.ExecuteCommand("set CONTAINER_NAME sleep-container"); err != nil {
		t.Fatalf("Expected set CONTAINER_NAME to succeed: %v", err)
	}
}

func TestEcsExecutecommandExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-006"); err != nil {
		t.Fatalf("Failed to use ecs-006: %v", err)
	}

	if err := r.ExecuteCommand("set CLUSTER_NAME test-cluster"); err != nil {
		t.Fatalf("Failed to set CLUSTER_NAME: %v", err)
	}

	// Exploit without identity should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestEcsExecutecommandSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for ECS modules should include ecs-006
	if err := r.ExecuteCommand("search ecs"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestEcsExecutecommandModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-006"); err != nil {
		t.Fatalf("Failed to use ecs-006: %v", err)
	}

	if err := r.ExecuteCommand("set CLUSTER_NAME my-cluster"); err != nil {
		t.Fatalf("Failed to set CLUSTER_NAME: %v", err)
	}

	// Unset should work
	if err := r.ExecuteCommand("unset CLUSTER_NAME"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
