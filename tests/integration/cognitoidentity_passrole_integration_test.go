package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/cognitoidentity_passrole"
)

func TestCognitoIdentityPassroleModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cognitoidentity-001"); err != nil {
		t.Fatalf("Failed to use cognitoidentity-001: %v", err)
	}
}

func TestCognitoIdentityPassroleModuleUseShortAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cognitoidentity-passrole"); err != nil {
		t.Fatalf("Failed to use cognitoidentity-passrole alias: %v", err)
	}
}

func TestCognitoIdentityPassroleModuleUseOldAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use exploit/cognitoidentity_passrole"); err != nil {
		t.Fatalf("Failed to use exploit/cognitoidentity_passrole alias: %v", err)
	}
}

func TestCognitoIdentityPassroleModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cognitoidentity-001"); err != nil {
		t.Fatalf("Failed to use cognitoidentity-001: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestCognitoIdentityPassroleModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cognitoidentity-001"); err != nil {
		t.Fatalf("Failed to use cognitoidentity-001: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestCognitoIdentityPassroleModuleSetRoleARN(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cognitoidentity-001"); err != nil {
		t.Fatalf("Failed to use cognitoidentity-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}
}

func TestCognitoIdentityPassroleModuleSetIdentityPoolID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cognitoidentity-001"); err != nil {
		t.Fatalf("Failed to use cognitoidentity-001: %v", err)
	}

	if err := r.ExecuteCommand("set IDENTITY_POOL_ID us-east-1:12345678-1234-1234-1234-123456789012"); err != nil {
		t.Fatalf("Expected set IDENTITY_POOL_ID to succeed: %v", err)
	}
}

func TestCognitoIdentityPassroleModuleSetOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cognitoidentity-001"); err != nil {
		t.Fatalf("Failed to use cognitoidentity-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set IDENTITY_POOL_ID us-east-1:12345678-1234-1234-1234-123456789012"); err != nil {
		t.Fatalf("Expected set IDENTITY_POOL_ID to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set SESSION_NAME test-session"); err != nil {
		t.Fatalf("Expected set SESSION_NAME to succeed: %v", err)
	}
}

func TestCognitoIdentityPassroleExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cognitoidentity-001"); err != nil {
		t.Fatalf("Failed to use cognitoidentity-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("set IDENTITY_POOL_ID us-east-1:12345678-1234-1234-1234-123456789012"); err != nil {
		t.Fatalf("Failed to set IDENTITY_POOL_ID: %v", err)
	}

	// Exploit without identity should fail with identity-required error.
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestCognitoIdentityPassroleSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search cognitoidentity"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestCognitoIdentityPassroleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use cognitoidentity-001"); err != nil {
		t.Fatalf("Failed to use cognitoidentity-001: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}

func TestCognitoIdentityPassroleModuleUseAndSearch(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Select the module, then search — both should work cleanly.
	if err := r.ExecuteCommand("use cognitoidentity-001"); err != nil {
		t.Fatalf("Failed to use cognitoidentity-001: %v", err)
	}

	// Search should still work while a module is active.
	if err := r.ExecuteCommand("search passrole"); err != nil {
		t.Fatalf("Expected search passrole to succeed: %v", err)
	}
}
