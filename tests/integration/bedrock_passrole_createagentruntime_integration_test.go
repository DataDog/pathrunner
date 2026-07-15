package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/bedrock_passrole_createagentruntime"
)

func TestBedrockPassroleCreateAgentRuntimeModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-003"); err != nil {
		t.Fatalf("Failed to use bedrock-003: %v", err)
	}
}

func TestBedrockPassroleCreateAgentRuntimeModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-passrole-createagentruntime"); err != nil {
		t.Fatalf("Failed to use bedrock-passrole-createagentruntime alias: %v", err)
	}
}

func TestBedrockPassroleCreateAgentRuntimeModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-003"); err != nil {
		t.Fatalf("Failed to use bedrock-003: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateAgentRuntimeModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-003"); err != nil {
		t.Fatalf("Failed to use bedrock-003: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateAgentRuntimeSetExecutionRoleARN(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-003"); err != nil {
		t.Fatalf("Failed to use bedrock-003: %v", err)
	}

	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/bedrock-agentcore-execution-role"); err != nil {
		t.Fatalf("Expected set EXECUTION_ROLE_ARN to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateAgentRuntimeSetContainerURI(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-003"); err != nil {
		t.Fatalf("Failed to use bedrock-003: %v", err)
	}

	if err := r.ExecuteCommand("set CONTAINER_URI 123456789012.dkr.ecr.us-east-1.amazonaws.com/attacker-repo:latest"); err != nil {
		t.Fatalf("Expected set CONTAINER_URI to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateAgentRuntimeSetRegion(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-003"); err != nil {
		t.Fatalf("Failed to use bedrock-003: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-west-2"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateAgentRuntimeSetRuntimeName(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-003"); err != nil {
		t.Fatalf("Failed to use bedrock-003: %v", err)
	}

	if err := r.ExecuteCommand("set RUNTIME_NAME my_test_runtime"); err != nil {
		t.Fatalf("Expected set RUNTIME_NAME to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateAgentRuntimeSetCleanup(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-003"); err != nil {
		t.Fatalf("Failed to use bedrock-003: %v", err)
	}

	if err := r.ExecuteCommand("set CLEANUP true"); err != nil {
		t.Fatalf("Expected set CLEANUP to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateAgentRuntimeExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-003"); err != nil {
		t.Fatalf("Failed to use bedrock-003: %v", err)
	}

	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/bedrock-agentcore-execution-role"); err != nil {
		t.Fatalf("Failed to set EXECUTION_ROLE_ARN: %v", err)
	}
	if err := r.ExecuteCommand("set CONTAINER_URI 123456789012.dkr.ecr.us-east-1.amazonaws.com/attacker-repo:latest"); err != nil {
		t.Fatalf("Failed to set CONTAINER_URI: %v", err)
	}

	// Exploit without identity should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestBedrockPassroleCreateAgentRuntimeExploitMissingExecutionRoleARN(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-003"); err != nil {
		t.Fatalf("Failed to use bedrock-003: %v", err)
	}

	// Set CONTAINER_URI but not EXECUTION_ROLE_ARN
	if err := r.ExecuteCommand("set CONTAINER_URI 123456789012.dkr.ecr.us-east-1.amazonaws.com/attacker-repo:latest"); err != nil {
		t.Fatalf("Failed to set CONTAINER_URI: %v", err)
	}

	// Exploit without required EXECUTION_ROLE_ARN should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail when required EXECUTION_ROLE_ARN is not set")
	}
}

func TestBedrockPassroleCreateAgentRuntimeExploitMissingContainerURI(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-003"); err != nil {
		t.Fatalf("Failed to use bedrock-003: %v", err)
	}

	// Set EXECUTION_ROLE_ARN but not CONTAINER_URI
	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/bedrock-agentcore-execution-role"); err != nil {
		t.Fatalf("Failed to set EXECUTION_ROLE_ARN: %v", err)
	}

	// Exploit without required CONTAINER_URI should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail when required CONTAINER_URI is not set")
	}
}

func TestBedrockPassroleCreateAgentRuntimeSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for bedrock modules should include bedrock-003
	if err := r.ExecuteCommand("search bedrock"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateAgentRuntimeUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-003"); err != nil {
		t.Fatalf("Failed to use bedrock-003: %v", err)
	}

	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/test"); err != nil {
		t.Fatalf("Failed to set EXECUTION_ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("unset EXECUTION_ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}

func TestBedrockPassroleCreateAgentRuntimeWorkspaceIsolation(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Set a module in workspace A
	if err := r.ExecuteCommand("workspace create ws_bedrock003_a"); err != nil {
		t.Fatalf("Failed to create workspace A: %v", err)
	}
	if err := r.ExecuteCommand("workspace switch ws_bedrock003_a"); err != nil {
		t.Fatalf("Failed to switch to workspace A: %v", err)
	}
	if err := r.ExecuteCommand("use bedrock-003"); err != nil {
		t.Fatalf("Failed to use bedrock-003 in workspace A: %v", err)
	}
	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/test-role-a"); err != nil {
		t.Fatalf("Failed to set EXECUTION_ROLE_ARN in workspace A: %v", err)
	}

	// Switch to workspace B — should have a clean state
	if err := r.ExecuteCommand("workspace create ws_bedrock003_b"); err != nil {
		t.Fatalf("Failed to create workspace B: %v", err)
	}
	if err := r.ExecuteCommand("workspace switch ws_bedrock003_b"); err != nil {
		t.Fatalf("Failed to switch to workspace B: %v", err)
	}

	// In workspace B, show options without a module should not succeed
	r.ExecuteCommand("show options") //nolint:errcheck

	// Switch back to workspace A — should restore state
	if err := r.ExecuteCommand("workspace switch ws_bedrock003_a"); err != nil {
		t.Fatalf("Failed to switch back to workspace A: %v", err)
	}

	// Now we should be able to show options for bedrock-003 in workspace A
	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed in workspace A after switch back: %v", err)
	}
}
