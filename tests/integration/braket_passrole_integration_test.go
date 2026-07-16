package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/braket_passrole"
)

func TestBraketPassroleModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use braket-001"); err != nil {
		t.Fatalf("Failed to use braket-001: %v", err)
	}
}

func TestBraketPassroleModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use braket-passrole"); err != nil {
		t.Fatalf("Failed to use braket-passrole alias: %v", err)
	}
}

func TestBraketPassroleModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use braket-001"); err != nil {
		t.Fatalf("Failed to use braket-001: %v", err)
	}
	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestBraketPassroleModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use braket-001"); err != nil {
		t.Fatalf("Failed to use braket-001: %v", err)
	}
	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestBraketPassroleModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use braket-001"); err != nil {
		t.Fatalf("Failed to use braket-001: %v", err)
	}
	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}
	if err := r.ExecuteCommand("set TARGET_USER victim-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}
	if err := r.ExecuteCommand("set SCRIPT_S3_URI s3://my-bucket/braket-001/exploit.py"); err != nil {
		t.Fatalf("Expected set SCRIPT_S3_URI to succeed: %v", err)
	}
}

func TestBraketPassroleExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use braket-001"); err != nil {
		t.Fatalf("Failed to use braket-001: %v", err)
	}
	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	// Exploit without identity should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestBraketPassroleSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search braket"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestBraketPassroleModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use braket-001"); err != nil {
		t.Fatalf("Failed to use braket-001: %v", err)
	}
	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}
	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
