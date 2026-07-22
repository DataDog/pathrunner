// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/ec2_modifyinstanceattribute"
)

func TestEC2ModifyInstanceAttributeModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by primary ID
	if err := r.ExecuteCommand("use ec2-002"); err != nil {
		t.Fatalf("Failed to use ec2-002: %v", err)
	}
}

func TestEC2ModifyInstanceAttributeModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by short alias
	if err := r.ExecuteCommand("use ec2-modifyinstanceattribute"); err != nil {
		t.Fatalf("Failed to use ec2-modifyinstanceattribute alias: %v", err)
	}
}

func TestEC2ModifyInstanceAttributeModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-002"); err != nil {
		t.Fatalf("Failed to use ec2-002: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestEC2ModifyInstanceAttributeModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-002"); err != nil {
		t.Fatalf("Failed to use ec2-002: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestEC2ModifyInstanceAttributeModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-002"); err != nil {
		t.Fatalf("Failed to use ec2-002: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_ID i-0abc1234567890def"); err != nil {
		t.Fatalf("Expected set INSTANCE_ID to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set PAYLOAD backdoor/attach-policy"); err != nil {
		t.Fatalf("Expected set PAYLOAD to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestEC2ModifyInstanceAttributeExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-002"); err != nil {
		t.Fatalf("Failed to use ec2-002: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_ID i-0abc1234567890def"); err != nil {
		t.Fatalf("Failed to set INSTANCE_ID: %v", err)
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

func TestEC2ModifyInstanceAttributeSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for ec2 should include ec2-002
	if err := r.ExecuteCommand("search ec2"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestEC2ModifyInstanceAttributeModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ec2-002"); err != nil {
		t.Fatalf("Failed to use ec2-002: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_ID i-0abc1234567890def"); err != nil {
		t.Fatalf("Failed to set INSTANCE_ID: %v", err)
	}

	if err := r.ExecuteCommand("unset INSTANCE_ID"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
