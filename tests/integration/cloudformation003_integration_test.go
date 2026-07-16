package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/cloudformation_passrole_createstackset_createstackinstances"
)

func TestCloudformation003ModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-003"); err != nil {
		t.Fatalf("Failed to use cloudformation-003: %v", err)
	}
}

func TestCloudformation003ModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cfn-003"); err != nil {
		t.Fatalf("Failed to use cfn-003 alias: %v", err)
	}
}

func TestCloudformation003ModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-003"); err != nil {
		t.Fatalf("Failed to use cloudformation-003: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestCloudformation003ModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-003"); err != nil {
		t.Fatalf("Failed to use cloudformation-003: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestCloudformation003ModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-003"); err != nil {
		t.Fatalf("Failed to use cloudformation-003: %v", err)
	}

	if err := r.ExecuteCommand("set EXECUTION_ROLE_NAME pl-prod-cloudformation-003-to-admin-execution-role"); err != nil {
		t.Fatalf("Expected set EXECUTION_ROLE_NAME to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set ESCALATED_ROLE_NAME my-escalated-role"); err != nil {
		t.Fatalf("Expected set ESCALATED_ROLE_NAME to succeed: %v", err)
	}
}

func TestCloudformation003ExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cloudformation-003"); err != nil {
		t.Fatalf("Failed to use cloudformation-003: %v", err)
	}

	if err := r.ExecuteCommand("set EXECUTION_ROLE_NAME pl-prod-cloudformation-003-to-admin-execution-role"); err != nil {
		t.Fatalf("Failed to set EXECUTION_ROLE_NAME: %v", err)
	}

	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestCloudformation003Searchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search cloudformation"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestCloudformation003SearchByService(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search cfn"); err != nil {
		t.Fatalf("Expected search cfn to succeed: %v", err)
	}
}
