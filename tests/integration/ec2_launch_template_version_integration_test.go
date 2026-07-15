package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/ec2_launch_template_version"
)

func TestEC2LaunchTemplateVersionModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by primary ID
	if err := r.ExecuteCommand("use ec2-005"); err != nil {
		t.Fatalf("Failed to use ec2-005: %v", err)
	}
}

func TestEC2LaunchTemplateVersionModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by alias
	if err := r.ExecuteCommand("use ec2-launch-template-version"); err != nil {
		t.Fatalf("Failed to use ec2-launch-template-version alias: %v", err)
	}
}

func TestEC2LaunchTemplateVersionModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-005"); err != nil {
		t.Fatalf("Failed to use ec2-005: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestEC2LaunchTemplateVersionModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-005"); err != nil {
		t.Fatalf("Failed to use ec2-005: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestEC2LaunchTemplateVersionModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-005"); err != nil {
		t.Fatalf("Failed to use ec2-005: %v", err)
	}

	if err := r.ExecuteCommand("set LAUNCH_TEMPLATE_NAME pl-prod-ec2-005-victim-template"); err != nil {
		t.Fatalf("Expected set LAUNCH_TEMPLATE_NAME to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_ARN arn:aws:iam::123456789012:user/test-user"); err != nil {
		t.Fatalf("Expected set TARGET_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestEC2LaunchTemplateVersionExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-005"); err != nil {
		t.Fatalf("Failed to use ec2-005: %v", err)
	}

	if err := r.ExecuteCommand("set LAUNCH_TEMPLATE_NAME test-template"); err != nil {
		t.Fatalf("Failed to set LAUNCH_TEMPLATE_NAME: %v", err)
	}

	// Exploit without identity should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestEC2LaunchTemplateVersionSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for ec2 should include ec2-005
	if err := r.ExecuteCommand("search ec2"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestEC2LaunchTemplateVersionModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-005"); err != nil {
		t.Fatalf("Failed to use ec2-005: %v", err)
	}

	if err := r.ExecuteCommand("set LAUNCH_TEMPLATE_NAME test-template"); err != nil {
		t.Fatalf("Failed to set LAUNCH_TEMPLATE_NAME: %v", err)
	}

	if err := r.ExecuteCommand("unset LAUNCH_TEMPLATE_NAME"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}

func TestEC2LaunchTemplateVersionModuleUseExploitAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should also work via the exploit/ alias
	if err := r.ExecuteCommand("use exploit/ec2_launch_template_version"); err != nil {
		t.Fatalf("Failed to use exploit/ec2_launch_template_version alias: %v", err)
	}
}
