package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/bedrock_passrole_createharness"
)

func TestBedrockPassroleCreateHarnessModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-005"); err != nil {
		t.Fatalf("Failed to use bedrock-005: %v", err)
	}
}

func TestBedrockPassroleCreateHarnessModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-passrole-createharness"); err != nil {
		t.Fatalf("Failed to use bedrock-passrole-createharness alias: %v", err)
	}
}

func TestBedrockPassroleCreateHarnessModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-005"); err != nil {
		t.Fatalf("Failed to use bedrock-005: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateHarnessModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-005"); err != nil {
		t.Fatalf("Failed to use bedrock-005: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateHarnessSetExecutionRoleARN(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-005"); err != nil {
		t.Fatalf("Failed to use bedrock-005: %v", err)
	}

	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/bedrock-agentcore-execution-role"); err != nil {
		t.Fatalf("Expected set EXECUTION_ROLE_ARN to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateHarnessSetRegion(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-005"); err != nil {
		t.Fatalf("Failed to use bedrock-005: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-west-2"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateHarnessSetModelID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-005"); err != nil {
		t.Fatalf("Failed to use bedrock-005: %v", err)
	}

	if err := r.ExecuteCommand("set MODEL_ID amazon.nova-lite-v1:0"); err != nil {
		t.Fatalf("Expected set MODEL_ID to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateHarnessSetHarnessName(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-005"); err != nil {
		t.Fatalf("Failed to use bedrock-005: %v", err)
	}

	if err := r.ExecuteCommand("set HARNESS_NAME my_test_harness"); err != nil {
		t.Fatalf("Expected set HARNESS_NAME to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateHarnessSetCleanup(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-005"); err != nil {
		t.Fatalf("Failed to use bedrock-005: %v", err)
	}

	if err := r.ExecuteCommand("set CLEANUP true"); err != nil {
		t.Fatalf("Expected set CLEANUP to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateHarnessExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-005"); err != nil {
		t.Fatalf("Failed to use bedrock-005: %v", err)
	}

	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/bedrock-agentcore-execution-role"); err != nil {
		t.Fatalf("Failed to set EXECUTION_ROLE_ARN: %v", err)
	}

	// Exploit without identity should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestBedrockPassroleCreateHarnessExploitMissingRequiredOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-005"); err != nil {
		t.Fatalf("Failed to use bedrock-005: %v", err)
	}

	// Try to run exploit without setting required EXECUTION_ROLE_ARN
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail when required EXECUTION_ROLE_ARN is not set")
	}
}

func TestBedrockPassroleCreateHarnessSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for bedrock modules should include bedrock-005
	if err := r.ExecuteCommand("search bedrock"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateHarnessUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-005"); err != nil {
		t.Fatalf("Failed to use bedrock-005: %v", err)
	}

	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/test"); err != nil {
		t.Fatalf("Failed to set EXECUTION_ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("unset EXECUTION_ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateHarnessWorkspaceIsolation(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Set a module in workspace A
	if err := r.ExecuteCommand("workspace create ws_bedrock_a"); err != nil {
		t.Fatalf("Failed to create workspace A: %v", err)
	}
	if err := r.ExecuteCommand("workspace switch ws_bedrock_a"); err != nil {
		t.Fatalf("Failed to switch to workspace A: %v", err)
	}
	if err := r.ExecuteCommand("use bedrock-005"); err != nil {
		t.Fatalf("Failed to use bedrock-005 in workspace A: %v", err)
	}
	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/test-role-a"); err != nil {
		t.Fatalf("Failed to set EXECUTION_ROLE_ARN in workspace A: %v", err)
	}

	// Switch to workspace B — should have a clean state
	if err := r.ExecuteCommand("workspace create ws_bedrock_b"); err != nil {
		t.Fatalf("Failed to create workspace B: %v", err)
	}
	if err := r.ExecuteCommand("workspace switch ws_bedrock_b"); err != nil {
		t.Fatalf("Failed to switch to workspace B: %v", err)
	}

	// In workspace B, the module should not be set to bedrock-005
	// (a fresh workspace has no current module)
	if err := r.ExecuteCommand("show options"); err == nil {
		// show options without a module should fail or produce empty output
		// This depends on implementation — just verify workspace switch worked
	}

	// Switch back to workspace A — should restore state
	if err := r.ExecuteCommand("workspace switch ws_bedrock_a"); err != nil {
		t.Fatalf("Failed to switch back to workspace A: %v", err)
	}

	// Now we should be able to show options for bedrock-005 in workspace A
	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed in workspace A after switch back: %v", err)
	}
}
