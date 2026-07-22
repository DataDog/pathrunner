// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/ec2_passrole_requestspotinstances"
)

func TestEc2PassroleRequestSpotInstancesModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-004"); err != nil {
		t.Fatalf("Failed to use ec2-004: %v", err)
	}
}

func TestEc2PassroleRequestSpotInstancesModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-passrole-spot"); err != nil {
		t.Fatalf("Failed to use ec2-passrole-spot alias: %v", err)
	}
}

func TestEc2PassroleRequestSpotInstancesModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-004"); err != nil {
		t.Fatalf("Failed to use ec2-004: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestEc2PassroleRequestSpotInstancesModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-004"); err != nil {
		t.Fatalf("Failed to use ec2-004: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestEc2PassroleRequestSpotInstancesModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-004"); err != nil {
		t.Fatalf("Failed to use ec2-004: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_PROFILE my-admin-profile"); err != nil {
		t.Fatalf("Expected set INSTANCE_PROFILE to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set PAYLOAD backdoor/attach-policy"); err != nil {
		t.Fatalf("Expected set PAYLOAD to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_ARN arn:aws:iam::123456789012:user/test-user"); err != nil {
		t.Fatalf("Expected set TARGET_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestEc2PassroleRequestSpotInstancesExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-004"); err != nil {
		t.Fatalf("Failed to use ec2-004: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_PROFILE my-admin-profile"); err != nil {
		t.Fatalf("Failed to set INSTANCE_PROFILE: %v", err)
	}

	if err := r.ExecuteCommand("set PAYLOAD backdoor/attach-policy"); err != nil {
		t.Fatalf("Failed to set PAYLOAD: %v", err)
	}

	// Exploit without identity should fail with identity required error.
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestEc2PassroleRequestSpotInstancesSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search ec2"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestEc2PassroleRequestSpotInstancesModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-004"); err != nil {
		t.Fatalf("Failed to use ec2-004: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_PROFILE my-admin-profile"); err != nil {
		t.Fatalf("Failed to set INSTANCE_PROFILE: %v", err)
	}

	if err := r.ExecuteCommand("unset INSTANCE_PROFILE"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
