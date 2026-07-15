package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/bedrock_passrole_codeinterpreter"
	_ "pathrunner/pkg/payloads/bedrock" // Register bedrock payloads so PAYLOAD validation works
)

func TestBedrockPassroleCodeInterpreterModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-001"); err != nil {
		t.Fatalf("Failed to use bedrock-001: %v", err)
	}
}

func TestBedrockPassroleCodeInterpreterModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-passrole"); err != nil {
		t.Fatalf("Failed to use bedrock-passrole alias: %v", err)
	}
}

func TestBedrockPassroleCodeInterpreterModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-001"); err != nil {
		t.Fatalf("Failed to use bedrock-001: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestBedrockPassroleCodeInterpreterModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-001"); err != nil {
		t.Fatalf("Failed to use bedrock-001: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestBedrockPassroleCodeInterpreterSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-001"); err != nil {
		t.Fatalf("Failed to use bedrock-001: %v", err)
	}

	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/BedrockAdminRole"); err != nil {
		t.Fatalf("Expected set EXECUTION_ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set PAYLOAD exfil/response"); err != nil {
		t.Fatalf("Expected set PAYLOAD to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestBedrockPassroleCodeInterpreterExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-001"); err != nil {
		t.Fatalf("Failed to use bedrock-001: %v", err)
	}

	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/BedrockAdminRole"); err != nil {
		t.Fatalf("Failed to set EXECUTION_ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("set PAYLOAD exfil/response"); err != nil {
		t.Fatalf("Failed to set PAYLOAD: %v", err)
	}

	// Exploit without identity should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestBedrockPassroleCodeInterpreterSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search bedrock"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestBedrockPassroleCodeInterpreterModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-001"); err != nil {
		t.Fatalf("Failed to use bedrock-001: %v", err)
	}

	if err := r.ExecuteCommand("set EXECUTION_ROLE_ARN arn:aws:iam::123456789012:role/BedrockAdminRole"); err != nil {
		t.Fatalf("Failed to set EXECUTION_ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("unset EXECUTION_ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}

func TestBedrockPassroleCodeInterpreterShowPayloads(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-001"); err != nil {
		t.Fatalf("Failed to use bedrock-001: %v", err)
	}

	if err := r.ExecuteCommand("show payloads"); err != nil {
		t.Fatalf("Expected show payloads to succeed: %v", err)
	}
}
