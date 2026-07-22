// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/codebuild_passrole"
)

func TestCodeBuildPassroleModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-001"); err != nil {
		t.Fatalf("Failed to use codebuild-001: %v", err)
	}
}

func TestCodeBuildPassroleModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-passrole"); err != nil {
		t.Fatalf("Failed to use codebuild-passrole alias: %v", err)
	}
}

func TestCodeBuildPassroleModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-001"); err != nil {
		t.Fatalf("Failed to use codebuild-001: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestCodeBuildPassroleModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-001"); err != nil {
		t.Fatalf("Failed to use codebuild-001: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestCodeBuildPassroleModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-001"); err != nil {
		t.Fatalf("Failed to use codebuild-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_USER test-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set PROJECT_NAME my-test-project"); err != nil {
		t.Fatalf("Expected set PROJECT_NAME to succeed: %v", err)
	}
}

func TestCodeBuildPassroleExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-001"); err != nil {
		t.Fatalf("Failed to use codebuild-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestCodeBuildPassroleSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search codebuild"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestCodeBuildPassroleModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codebuild-001"); err != nil {
		t.Fatalf("Failed to use codebuild-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
