package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/kinesisanalytics_passrole"
)

func TestKinesisAnalyticsPassroleModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use kinesisanalytics-001"); err != nil {
		t.Fatalf("Failed to use kinesisanalytics-001: %v", err)
	}
}

func TestKinesisAnalyticsPassroleModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use kinesisanalytics-passrole"); err != nil {
		t.Fatalf("Failed to use kinesisanalytics-passrole alias: %v", err)
	}
}

func TestKinesisAnalyticsPassroleModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use kinesisanalytics-001"); err != nil {
		t.Fatalf("Failed to use kinesisanalytics-001: %v", err)
	}
	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestKinesisAnalyticsPassroleModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use kinesisanalytics-001"); err != nil {
		t.Fatalf("Failed to use kinesisanalytics-001: %v", err)
	}
	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestKinesisAnalyticsPassroleModuleSetOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use kinesisanalytics-001"); err != nil {
		t.Fatalf("Failed to use kinesisanalytics-001: %v", err)
	}
	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}
	if err := r.ExecuteCommand("set CODE_BUCKET my-attacker-bucket"); err != nil {
		t.Fatalf("Expected set CODE_BUCKET to succeed: %v", err)
	}
	if err := r.ExecuteCommand("set CODE_KEY exploit/malicious-flink-app.jar"); err != nil {
		t.Fatalf("Expected set CODE_KEY to succeed: %v", err)
	}
	if err := r.ExecuteCommand("set TARGET_USER victim-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}
}

func TestKinesisAnalyticsPassroleExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use kinesisanalytics-001"); err != nil {
		t.Fatalf("Failed to use kinesisanalytics-001: %v", err)
	}
	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}
	if err := r.ExecuteCommand("set CODE_BUCKET my-attacker-bucket"); err != nil {
		t.Fatalf("Failed to set CODE_BUCKET: %v", err)
	}
	if err := r.ExecuteCommand("set CODE_KEY exploit/malicious-flink-app.jar"); err != nil {
		t.Fatalf("Failed to set CODE_KEY: %v", err)
	}

	// Exploit without identity should fail.
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestKinesisAnalyticsPassroleSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search kinesisanalytics"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestKinesisAnalyticsPassroleModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use kinesisanalytics-001"); err != nil {
		t.Fatalf("Failed to use kinesisanalytics-001: %v", err)
	}
	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}
	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
