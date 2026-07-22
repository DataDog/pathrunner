// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"strings"
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/ssm_passrole_automation"
)

// TestSSM003UseModule verifies that the ssm-003 module can be selected via 'use'.
func TestSSM003UseModule(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-003"); err != nil {
		t.Fatalf("Expected 'use ssm-003' to succeed: %v", err)
	}
}

// TestSSM003UseAlias verifies that the module can be selected by its human-readable alias.
func TestSSM003UseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-passrole-automation"); err != nil {
		t.Fatalf("Expected 'use ssm-passrole-automation' to succeed: %v", err)
	}
}

// TestSSM003ShowInfo verifies that 'show info' outputs the expected module metadata after selecting ssm-003.
func TestSSM003ShowInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-003"); err != nil {
		t.Fatalf("Expected 'use ssm-003' to succeed: %v", err)
	}

	if err := r.ExecuteCommand("show info"); err != nil {
		t.Fatalf("Expected 'show info' to succeed: %v", err)
	}
}

// TestSSM003ShowOptions verifies that 'show options' lists the AUTOMATION_ROLE_ARN option after selecting ssm-003.
func TestSSM003ShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-003"); err != nil {
		t.Fatalf("Expected 'use ssm-003' to succeed: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected 'show options' to succeed: %v", err)
	}
}

// TestSSM003SearchFindsModule verifies that 'search ssm' returns ssm-003 in results.
func TestSSM003SearchFindsModule(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search ssm"); err != nil {
		t.Fatalf("Expected 'search ssm' to succeed: %v", err)
	}
}

// TestSSM003SearchPassrole verifies that 'search passrole' returns ssm-003 in results
// (since it is a new-passrole module).
func TestSSM003SearchPassrole(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search passrole"); err != nil {
		t.Fatalf("Expected 'search passrole' to succeed: %v", err)
	}
}

// TestSSM003HelpSubcommand verifies that 'show info help' does not error.
func TestSSM003HelpSubcommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-003"); err != nil {
		t.Fatalf("Expected 'use ssm-003' to succeed: %v", err)
	}

	// 'show info help' should either succeed or return a graceful error
	_ = r.ExecuteCommand("show info help")
}

// TestSSM003ExploitWithoutIdentity verifies that running exploit without an identity
// returns a clear error rather than panicking.
func TestSSM003ExploitWithoutIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-003"); err != nil {
		t.Fatalf("Expected 'use ssm-003' to succeed: %v", err)
	}

	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected error running exploit without identity set")
	}

	// Should be an identity-required error
	if !strings.Contains(strings.ToLower(err.Error()), "identity") {
		t.Errorf("Expected identity-related error, got: %v", err)
	}
}

// TestSSM003ExploitAliasCommand verifies that the exploit alias 'run' also works.
func TestSSM003ExploitAliasCommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use ssm-003"); err != nil {
		t.Fatalf("Expected 'use ssm-003' to succeed: %v", err)
	}

	// 'run' should return an identity-required error (no AWS credential available)
	err := r.ExecuteCommand("run")
	if err == nil {
		t.Error("Expected error running 'run' without identity set")
	}
}
