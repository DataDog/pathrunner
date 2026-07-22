// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/ecs_passrole_runtask"
)

func TestEcsPassroleRuntaskModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by ID
	if err := r.ExecuteCommand("use ecs-008"); err != nil {
		t.Fatalf("Failed to use ecs-008: %v", err)
	}
}

func TestEcsPassroleRuntaskModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by alias
	if err := r.ExecuteCommand("use ecs-passrole-runtask"); err != nil {
		t.Fatalf("Failed to use ecs-passrole-runtask alias: %v", err)
	}
}

func TestEcsPassroleRuntaskModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-008"); err != nil {
		t.Fatalf("Failed to use ecs-008: %v", err)
	}

	// Info should succeed
	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestEcsPassroleRuntaskModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-008"); err != nil {
		t.Fatalf("Failed to use ecs-008: %v", err)
	}

	// Show options should succeed
	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestEcsPassroleRuntaskModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-008"); err != nil {
		t.Fatalf("Failed to use ecs-008: %v", err)
	}

	// Set ROLE_ARN
	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	// Set CLUSTER_NAME
	if err := r.ExecuteCommand("set CLUSTER_NAME my-cluster"); err != nil {
		t.Fatalf("Expected set CLUSTER_NAME to succeed: %v", err)
	}

	// Set TASK_DEFINITION
	if err := r.ExecuteCommand("set TASK_DEFINITION my-task-family:1"); err != nil {
		t.Fatalf("Expected set TASK_DEFINITION to succeed: %v", err)
	}

	// Set TARGET_ARN
	if err := r.ExecuteCommand("set TARGET_ARN arn:aws:iam::123456789012:user/test-user"); err != nil {
		t.Fatalf("Expected set TARGET_ARN to succeed: %v", err)
	}
}

func TestEcsPassroleRuntaskExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-008"); err != nil {
		t.Fatalf("Failed to use ecs-008: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("set CLUSTER_NAME test-cluster"); err != nil {
		t.Fatalf("Failed to set CLUSTER_NAME: %v", err)
	}

	if err := r.ExecuteCommand("set TASK_DEFINITION my-task:1"); err != nil {
		t.Fatalf("Failed to set TASK_DEFINITION: %v", err)
	}

	// Exploit without identity should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestEcsPassroleRuntaskSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for ECS modules should include ecs-008
	if err := r.ExecuteCommand("search ecs"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestEcsPassroleRuntaskModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ecs-008"); err != nil {
		t.Fatalf("Failed to use ecs-008: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	// Unset should work
	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
