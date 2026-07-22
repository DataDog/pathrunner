// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/cloudformation_updatestack"
)

func TestCloudformation002ModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-002"); err != nil {
		t.Fatalf("Failed to use cloudformation-002: %v", err)
	}
}

func TestCloudformation002ModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cfn-002"); err != nil {
		t.Fatalf("Failed to use cfn-002 alias: %v", err)
	}
}

func TestCloudformation002ModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-002"); err != nil {
		t.Fatalf("Failed to use cloudformation-002: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestCloudformation002ModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-002"); err != nil {
		t.Fatalf("Failed to use cloudformation-002: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestCloudformation002ModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-002"); err != nil {
		t.Fatalf("Failed to use cloudformation-002: %v", err)
	}

	if err := r.ExecuteCommand("set STACK_NAME pl-prod-cloudformation-002-to-admin-stack"); err != nil {
		t.Fatalf("Expected set STACK_NAME to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set ESCALATED_ROLE_NAME my-escalated-role"); err != nil {
		t.Fatalf("Expected set ESCALATED_ROLE_NAME to succeed: %v", err)
	}
}

func TestCloudformation002ExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-002"); err != nil {
		t.Fatalf("Failed to use cloudformation-002: %v", err)
	}

	if err := r.ExecuteCommand("set STACK_NAME pl-prod-cloudformation-002-to-admin-stack"); err != nil {
		t.Fatalf("Failed to set STACK_NAME: %v", err)
	}

	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestCloudformation002Searchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search cloudformation"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestCloudformation002SearchByService(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search cfn"); err != nil {
		t.Fatalf("Expected search cfn to succeed: %v", err)
	}
}
