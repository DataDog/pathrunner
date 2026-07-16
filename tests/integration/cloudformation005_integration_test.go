package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/cloudformation_createchangeset_executechangeset"
)

func TestCloudformation005ModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-005"); err != nil {
		t.Fatalf("Failed to use cloudformation-005: %v", err)
	}
}

func TestCloudformation005ModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cfn-005"); err != nil {
		t.Fatalf("Failed to use cfn-005 alias: %v", err)
	}
}

func TestCloudformation005ModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-005"); err != nil {
		t.Fatalf("Failed to use cloudformation-005: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestCloudformation005ModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-005"); err != nil {
		t.Fatalf("Failed to use cloudformation-005: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestCloudformation005ModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-005"); err != nil {
		t.Fatalf("Failed to use cloudformation-005: %v", err)
	}

	if err := r.ExecuteCommand("set STACK_NAME pl-prod-cloudformation-005-to-admin-target-stack"); err != nil {
		t.Fatalf("Expected set STACK_NAME to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set ESCALATED_ROLE_NAME my-escalated-role"); err != nil {
		t.Fatalf("Expected set ESCALATED_ROLE_NAME to succeed: %v", err)
	}
}

func TestCloudformation005ExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-005"); err != nil {
		t.Fatalf("Failed to use cloudformation-005: %v", err)
	}

	if err := r.ExecuteCommand("set STACK_NAME pl-prod-cloudformation-005-to-admin-target-stack"); err != nil {
		t.Fatalf("Failed to set STACK_NAME: %v", err)
	}

	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestCloudformation005Searchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search cloudformation"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestCloudformation005SearchByService(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search cfn"); err != nil {
		t.Fatalf("Expected search cfn to succeed: %v", err)
	}
}
