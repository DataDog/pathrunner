// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/glue_passrole_createsession"
	_ "github.com/DataDog/pathrunner/pkg/payloads/glue"
)

func TestGluePassroleCreatesessionModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-007"); err != nil {
		t.Fatalf("Failed to use glue-007: %v", err)
	}
}

func TestGluePassroleCreatesessionModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-passrole-createsession"); err != nil {
		t.Fatalf("Failed to use glue-passrole-createsession alias: %v", err)
	}
}

func TestGluePassroleCreatesessionModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-007"); err != nil {
		t.Fatalf("Failed to use glue-007: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestGluePassroleCreatesessionModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-007"); err != nil {
		t.Fatalf("Failed to use glue-007: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestGluePassroleCreatesessionModuleSetOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-007"); err != nil {
		t.Fatalf("Failed to use glue-007: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/pl-prod-glue-007-to-admin-admin-role"); err != nil {
		t.Fatalf("Expected set ROLE_ARN to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set PAYLOAD backdoor/attach-policy"); err != nil {
		t.Fatalf("Expected set PAYLOAD to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestGluePassroleCreatesessionExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-007"); err != nil {
		t.Fatalf("Failed to use glue-007: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}
	if err := r.ExecuteCommand("set PAYLOAD backdoor/attach-policy"); err != nil {
		t.Fatalf("Failed to set PAYLOAD: %v", err)
	}
	if err := r.ExecuteCommand("set TARGET_ARN test-user"); err != nil {
		t.Fatalf("Failed to set TARGET_ARN: %v", err)
	}

	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestGluePassroleCreatesessionSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search glue"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestGluePassroleCreatesessionModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-007"); err != nil {
		t.Fatalf("Failed to use glue-007: %v", err)
	}

	if err := r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/admin-role"); err != nil {
		t.Fatalf("Failed to set ROLE_ARN: %v", err)
	}

	if err := r.ExecuteCommand("unset ROLE_ARN"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}

func TestGluePassroleCreatesessionModuleShowPayloads(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use glue-007"); err != nil {
		t.Fatalf("Failed to use glue-007: %v", err)
	}

	if err := r.ExecuteCommand("show payloads"); err != nil {
		t.Fatalf("Expected show payloads to succeed: %v", err)
	}
}
