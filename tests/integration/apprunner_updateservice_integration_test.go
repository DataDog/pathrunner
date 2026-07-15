package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/apprunner_updateservice"
	_ "pathrunner/pkg/payloads/apprunner"
)

func TestAppRunnerUpdateServiceModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by primary ID
	if err := r.ExecuteCommand("use apprunner-002"); err != nil {
		t.Fatalf("Failed to use apprunner-002: %v", err)
	}
}

func TestAppRunnerUpdateServiceModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by alias
	if err := r.ExecuteCommand("use apprunner-updateservice"); err != nil {
		t.Fatalf("Failed to use apprunner-updateservice alias: %v", err)
	}
}

func TestAppRunnerUpdateServiceModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use apprunner-002"); err != nil {
		t.Fatalf("Failed to use apprunner-002: %v", err)
	}

	// Info should succeed
	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestAppRunnerUpdateServiceModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use apprunner-002"); err != nil {
		t.Fatalf("Failed to use apprunner-002: %v", err)
	}

	// Show options should succeed
	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestAppRunnerUpdateServiceModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use apprunner-002"); err != nil {
		t.Fatalf("Failed to use apprunner-002: %v", err)
	}

	// Set SERVICE_ARN
	if err := r.ExecuteCommand("set SERVICE_ARN arn:aws:apprunner:us-east-1:123456789012:service/my-service/abc123"); err != nil {
		t.Fatalf("Expected set SERVICE_ARN to succeed: %v", err)
	}

	// Set TARGET_ARN
	if err := r.ExecuteCommand("set TARGET_ARN arn:aws:iam::123456789012:user/test-user"); err != nil {
		t.Fatalf("Expected set TARGET_ARN to succeed: %v", err)
	}

	// Set REGION
	if err := r.ExecuteCommand("set REGION us-west-2"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestAppRunnerUpdateServiceExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use apprunner-002"); err != nil {
		t.Fatalf("Failed to use apprunner-002: %v", err)
	}

	if err := r.ExecuteCommand("set SERVICE_ARN arn:aws:apprunner:us-east-1:123456789012:service/my-service/abc123"); err != nil {
		t.Fatalf("Failed to set SERVICE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("set PAYLOAD backdoor/attach-policy"); err != nil {
		t.Fatalf("Failed to set PAYLOAD: %v", err)
	}

	// Exploit without identity should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestAppRunnerUpdateServiceSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for apprunner modules should include apprunner-002
	if err := r.ExecuteCommand("search apprunner"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestAppRunnerUpdateServiceModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use apprunner-002"); err != nil {
		t.Fatalf("Failed to use apprunner-002: %v", err)
	}

	if err := r.ExecuteCommand("set SERVICE_ARN arn:aws:apprunner:us-east-1:123456789012:service/my-service/abc123"); err != nil {
		t.Fatalf("Failed to set SERVICE_ARN: %v", err)
	}

	// Unset should work
	if err := r.ExecuteCommand("unset SERVICE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
