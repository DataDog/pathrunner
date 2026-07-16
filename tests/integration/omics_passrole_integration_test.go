package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/omics_passrole"
)

func TestOmicsPassroleModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use omics-001"); err != nil {
		t.Fatalf("Failed to use omics-001: %v", err)
	}
}

func TestOmicsPassroleModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use omics-passrole"); err != nil {
		t.Fatalf("Failed to use omics-passrole alias: %v", err)
	}
}

func TestOmicsPassroleModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use omics-001"); err != nil {
		t.Fatalf("Failed to use omics-001: %v", err)
	}
	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestOmicsPassroleModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use omics-001"); err != nil {
		t.Fatalf("Failed to use omics-001: %v", err)
	}
	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestOmicsPassroleModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use omics-001"); err != nil {
		t.Fatalf("Failed to use omics-001: %v", err)
	}
	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}
	if err := r.ExecuteCommand("set CONTAINER_URI 123456789012.dkr.ecr.us-east-1.amazonaws.com/aws-cli:latest"); err != nil {
		t.Fatalf("Expected set CONTAINER_URI to succeed: %v", err)
	}
	if err := r.ExecuteCommand("set EXFIL_BUCKET my-attacker-bucket"); err != nil {
		t.Fatalf("Expected set EXFIL_BUCKET to succeed: %v", err)
	}
	if err := r.ExecuteCommand("set TARGET_USER victim-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}
}

func TestOmicsPassroleExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use omics-001"); err != nil {
		t.Fatalf("Failed to use omics-001: %v", err)
	}
	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	// Exploit without identity should fail.
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestOmicsPassroleSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search omics"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestOmicsPassroleModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use omics-001"); err != nil {
		t.Fatalf("Failed to use omics-001: %v", err)
	}
	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}
	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}

func TestOmicsPassroleModuleShowInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use omics-001"); err != nil {
		t.Fatalf("Failed to use omics-001: %v", err)
	}
	if err := r.ExecuteCommand("show info"); err != nil {
		t.Fatalf("Expected show info to succeed: %v", err)
	}
}
