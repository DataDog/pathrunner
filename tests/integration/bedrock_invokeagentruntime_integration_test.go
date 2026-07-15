package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/bedrock_invokeagentruntime"
)

func TestBedrockInvokeAgentRuntimeModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by primary ID
	if err := r.ExecuteCommand("use bedrock-004"); err != nil {
		t.Fatalf("Failed to use bedrock-004: %v", err)
	}
}

func TestBedrockInvokeAgentRuntimeModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by alias
	if err := r.ExecuteCommand("use bedrock-invokeagentruntime"); err != nil {
		t.Fatalf("Failed to use bedrock-invokeagentruntime alias: %v", err)
	}
}

func TestBedrockInvokeAgentRuntimeModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-004"); err != nil {
		t.Fatalf("Failed to use bedrock-004: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestBedrockInvokeAgentRuntimeModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-004"); err != nil {
		t.Fatalf("Failed to use bedrock-004: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestBedrockInvokeAgentRuntimeModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-004"); err != nil {
		t.Fatalf("Failed to use bedrock-004: %v", err)
	}

	// Set TARGET_RUNTIME_ARN
	if err := r.ExecuteCommand("set TARGET_RUNTIME_ARN arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/test-runtime"); err != nil {
		t.Fatalf("Expected set TARGET_RUNTIME_ARN to succeed: %v", err)
	}

	// Set REGION
	if err := r.ExecuteCommand("set REGION us-west-2"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestBedrockInvokeAgentRuntimeExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-004"); err != nil {
		t.Fatalf("Failed to use bedrock-004: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_RUNTIME_ARN arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/test"); err != nil {
		t.Fatalf("Failed to set TARGET_RUNTIME_ARN: %v", err)
	}

	// Exploit without identity should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestBedrockInvokeAgentRuntimeSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for bedrock modules should include bedrock-004
	if err := r.ExecuteCommand("search bedrock"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestBedrockInvokeAgentRuntimeModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-004"); err != nil {
		t.Fatalf("Failed to use bedrock-004: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_RUNTIME_ARN arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/test"); err != nil {
		t.Fatalf("Failed to set TARGET_RUNTIME_ARN: %v", err)
	}

	// Unset should work
	if err := r.ExecuteCommand("unset TARGET_RUNTIME_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
