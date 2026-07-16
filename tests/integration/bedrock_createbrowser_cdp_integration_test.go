package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/bedrock_createbrowser_cdp"
)

func TestBedrockCreateBrowserCDPModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by primary ID
	if err := r.ExecuteCommand("use bedrock-006"); err != nil {
		t.Fatalf("Failed to use bedrock-006: %v", err)
	}
}

func TestBedrockCreateBrowserCDPModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by alias
	if err := r.ExecuteCommand("use bedrock-createbrowser-cdp"); err != nil {
		t.Fatalf("Failed to use bedrock-createbrowser-cdp alias: %v", err)
	}
}

func TestBedrockCreateBrowserCDPModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-006"); err != nil {
		t.Fatalf("Failed to use bedrock-006: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestBedrockCreateBrowserCDPModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-006"); err != nil {
		t.Fatalf("Failed to use bedrock-006: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestBedrockCreateBrowserCDPModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-006"); err != nil {
		t.Fatalf("Failed to use bedrock-006: %v", err)
	}

	// Set ROLE_ARN (the required option)
	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/test-agentcore-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	// Set REGION
	if err := r.ExecuteCommand("set REGION us-west-2"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}

	// Set WAIT_TIMEOUT
	if err := r.ExecuteCommand("set WAIT_TIMEOUT 120"); err != nil {
		t.Fatalf("Expected set WAIT_TIMEOUT to succeed: %v", err)
	}
}

func TestBedrockCreateBrowserCDPExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-006"); err != nil {
		t.Fatalf("Failed to use bedrock-006: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/test-agentcore-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	// Exploit without identity should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestBedrockCreateBrowserCDPSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for bedrock modules should include bedrock-006
	if err := r.ExecuteCommand("search bedrock"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestBedrockCreateBrowserCDPModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-006"); err != nil {
		t.Fatalf("Failed to use bedrock-006: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/test-agentcore-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	// Unset should work
	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}

func TestBedrockCreateBrowserCDPModuleUseExploitAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select via the exploit/ alias
	if err := r.ExecuteCommand("use exploit/bedrock_createbrowser_cdp"); err != nil {
		t.Fatalf("Failed to use exploit/bedrock_createbrowser_cdp alias: %v", err)
	}
}
