package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/cloudformation_updatestackset"
)

func TestCloudformation004ModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-004"); err != nil {
		t.Fatalf("Failed to use cloudformation-004: %v", err)
	}
}

func TestCloudformation004ModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cfn-004"); err != nil {
		t.Fatalf("Failed to use cfn-004 alias: %v", err)
	}
}

func TestCloudformation004ModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-004"); err != nil {
		t.Fatalf("Failed to use cloudformation-004: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestCloudformation004ModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-004"); err != nil {
		t.Fatalf("Failed to use cloudformation-004: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestCloudformation004ModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-004"); err != nil {
		t.Fatalf("Failed to use cloudformation-004: %v", err)
	}

	if err := r.ExecuteCommand("set STACKSET_NAME pl-prod-cloudformation-004-to-admin-stackset"); err != nil {
		t.Fatalf("Expected set STACKSET_NAME to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set ESCALATED_ROLE_NAME my-escalated-role"); err != nil {
		t.Fatalf("Expected set ESCALATED_ROLE_NAME to succeed: %v", err)
	}
}

func TestCloudformation004ExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-004"); err != nil {
		t.Fatalf("Failed to use cloudformation-004: %v", err)
	}

	if err := r.ExecuteCommand("set STACKSET_NAME pl-prod-cloudformation-004-to-admin-stackset"); err != nil {
		t.Fatalf("Failed to set STACKSET_NAME: %v", err)
	}

	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestCloudformation004Searchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search cloudformation"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestCloudformation004SearchByService(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search cfn"); err != nil {
		t.Fatalf("Expected search cfn to succeed: %v", err)
	}
}
