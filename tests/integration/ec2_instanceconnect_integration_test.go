package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/ec2_instanceconnect"
)

func TestEC2InstanceConnectModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by primary ID.
	if err := r.ExecuteCommand("use ec2-003"); err != nil {
		t.Fatalf("Failed to use ec2-003: %v", err)
	}
}

func TestEC2InstanceConnectModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by alias.
	if err := r.ExecuteCommand("use ec2-instanceconnect"); err != nil {
		t.Fatalf("Failed to use ec2-instanceconnect alias: %v", err)
	}
}

func TestEC2InstanceConnectModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-003"); err != nil {
		t.Fatalf("Failed to use ec2-003: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestEC2InstanceConnectModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-003"); err != nil {
		t.Fatalf("Failed to use ec2-003: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestEC2InstanceConnectModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-003"); err != nil {
		t.Fatalf("Failed to use ec2-003: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_ID i-0abc1234567890def"); err != nil {
		t.Fatalf("Expected set INSTANCE_ID to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set EC2_USER ec2-user"); err != nil {
		t.Fatalf("Expected set EC2_USER to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_USER my-iam-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}
}

func TestEC2InstanceConnectExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-003"); err != nil {
		t.Fatalf("Failed to use ec2-003: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_ID i-0abc1234567890def"); err != nil {
		t.Fatalf("Failed to set INSTANCE_ID: %v", err)
	}

	// Exploit without identity should fail.
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestEC2InstanceConnectSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for ec2 modules should include ec2-003.
	if err := r.ExecuteCommand("search ec2-instanceconnect"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestEC2InstanceConnectModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-003"); err != nil {
		t.Fatalf("Failed to use ec2-003: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_ID i-0abc1234567890def"); err != nil {
		t.Fatalf("Failed to set INSTANCE_ID: %v", err)
	}

	if err := r.ExecuteCommand("unset INSTANCE_ID"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
