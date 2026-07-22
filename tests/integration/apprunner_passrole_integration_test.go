// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/apprunner_passrole"
)

func TestAppRunnerPassroleModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by primary ID
	if err := r.ExecuteCommand("use apprunner-001"); err != nil {
		t.Fatalf("Failed to use apprunner-001: %v", err)
	}
}

func TestAppRunnerPassroleModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by alias
	if err := r.ExecuteCommand("use apprunner-passrole"); err != nil {
		t.Fatalf("Failed to use apprunner-passrole alias: %v", err)
	}
}

func TestAppRunnerPassroleModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use apprunner-001"); err != nil {
		t.Fatalf("Failed to use apprunner-001: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestAppRunnerPassroleModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use apprunner-001"); err != nil {
		t.Fatalf("Failed to use apprunner-001: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestAppRunnerPassroleModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use apprunner-001"); err != nil {
		t.Fatalf("Failed to use apprunner-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set SERVICE_NAME my-privesc-service"); err != nil {
		t.Fatalf("Expected set SERVICE_NAME to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_ARN arn:aws:iam::123456789012:user/test-user"); err != nil {
		t.Fatalf("Expected set TARGET_ARN to succeed: %v", err)
	}
}

func TestAppRunnerPassroleExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use apprunner-001"); err != nil {
		t.Fatalf("Failed to use apprunner-001: %v", err)
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

func TestAppRunnerPassroleSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for apprunner should include apprunner-001
	if err := r.ExecuteCommand("search apprunner"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestAppRunnerPassroleModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use apprunner-001"); err != nil {
		t.Fatalf("Failed to use apprunner-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
