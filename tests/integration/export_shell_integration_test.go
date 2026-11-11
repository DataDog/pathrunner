// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"strings"
	"testing"

	"github.com/DataDog/pathrunner/pkg/core"
	"github.com/DataDog/pathrunner/pkg/modules"
)

// addTestIdentity sets up a static-keys identity as current and returns it.
func addTestIdentity(t *testing.T, im *core.IdentityManager, name string) *modules.Identity {
	t.Helper()
	identity := &modules.Identity{
		Name:         name,
		Type:         "keys",
		AccessKeyID:  "ASIA" + strings.ToUpper(strings.ReplaceAll(name, "-", "")) + "KEY",
		SecretKey:    "wJalrXUtnFEMIexample",
		SessionToken: "FwoGZXIvYXdzEXAMPLE",
		Region:       "us-east-1",
	}
	im.SetIdentities(map[string]*modules.Identity{name: identity})
	im.SetCurrent(identity)
	return identity
}

func TestShellHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	output := captureOutput(func() {
		err := r.ExecuteCommand("shell help")
		if err != nil {
			t.Errorf("Expected no error for 'shell help', got: %v", err)
		}
	})

	if !strings.Contains(output, "Shell Command:") {
		t.Errorf("Expected shell help output, got: %s", output)
	}
	if !strings.Contains(output, "AWS_ACCESS_KEY_ID") {
		t.Errorf("Expected env var docs in shell help, got: %s", output)
	}
}

func TestShellWithoutIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("shell")
	if err == nil {
		t.Error("Expected error when spawning shell without identity")
	}

	if !strings.Contains(err.Error(), "identity") {
		t.Errorf("Expected identity-related error, got: %v", err)
	}
}

func TestShellRejectsArguments(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("shell extra-arg")
	if err == nil {
		t.Error("Expected error when passing arguments to shell")
	}

	if !strings.Contains(err.Error(), "no arguments") {
		t.Errorf("Expected 'no arguments' error, got: %v", err)
	}
}

func TestExportHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	output := captureOutput(func() {
		err := r.ExecuteCommand("identity export help")
		if err != nil {
			t.Errorf("Expected no error for 'export help', got: %v", err)
		}
	})

	if !strings.Contains(output, "Identity Export Command:") {
		t.Errorf("Expected identity export help output, got: %s", output)
	}
	if !strings.Contains(output, "--format") {
		t.Errorf("Expected --format docs in export help, got: %s", output)
	}
}

func TestExportWithoutIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("identity export")
	if err == nil {
		t.Error("Expected error when exporting without identity")
	}

	if !strings.Contains(err.Error(), "identity") {
		t.Errorf("Expected identity-related error, got: %v", err)
	}
}

func TestExportEnvFormat(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	identity := addTestIdentity(t, im, "escalated-role")

	output := captureOutput(func() {
		err := r.ExecuteCommand("identity export")
		if err != nil {
			t.Errorf("Expected no error exporting, got: %v", err)
		}
	})

	expectedLines := []string{
		"export AWS_ACCESS_KEY_ID=" + identity.AccessKeyID,
		"export AWS_SECRET_ACCESS_KEY=" + identity.SecretKey,
		"export AWS_SESSION_TOKEN=" + identity.SessionToken,
		"export AWS_DEFAULT_REGION=us-east-1",
	}
	for _, line := range expectedLines {
		if !strings.Contains(output, line) {
			t.Errorf("Expected output to contain '%s', got: %s", line, output)
		}
	}
}

func TestExportProfileFormat(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	addTestIdentity(t, im, "escalated-role")

	output := captureOutput(func() {
		err := r.ExecuteCommand("identity export --format profile")
		if err != nil {
			t.Errorf("Expected no error exporting profile format, got: %v", err)
		}
	})

	expectedParts := []string{
		"[escalated-role]",
		"aws_access_key_id = ",
		"aws_secret_access_key = ",
		"aws_session_token = ",
		"region = us-east-1",
	}
	for _, part := range expectedParts {
		if !strings.Contains(output, part) {
			t.Errorf("Expected profile output to contain '%s', got: %s", part, output)
		}
	}
}

func TestExportJsonFormat(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	addTestIdentity(t, im, "escalated-role")

	output := captureOutput(func() {
		err := r.ExecuteCommand("identity export --format=json")
		if err != nil {
			t.Errorf("Expected no error exporting json format, got: %v", err)
		}
	})

	if !strings.Contains(output, `"AWS_ACCESS_KEY_ID"`) {
		t.Errorf("Expected AWS_ACCESS_KEY_ID key in json output, got: %s", output)
	}
}

func TestExportNamedIdentity(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	current := &modules.Identity{
		Name:        "initial-identity",
		Type:        "keys",
		AccessKeyID: "AKIAINITIALKEY",
		SecretKey:   "initial-secret",
		Region:      "us-east-1",
	}
	target := &modules.Identity{
		Name:        "stolen-role",
		Type:        "keys",
		AccessKeyID: "ASIASTOLENROLEKEY",
		SecretKey:   "stolen-secret",
		Region:      "us-west-2",
	}
	im.SetIdentities(map[string]*modules.Identity{
		"initial-identity": current,
		"stolen-role":      target,
	})
	im.SetCurrent(current)

	// Export a non-current identity by name
	output := captureOutput(func() {
		err := r.ExecuteCommand("identity export stolen-role")
		if err != nil {
			t.Errorf("Expected no error exporting named identity, got: %v", err)
		}
	})

	if !strings.Contains(output, "export AWS_ACCESS_KEY_ID="+target.AccessKeyID) {
		t.Errorf("Expected target identity's key in output, got: %s", output)
	}
	if strings.Contains(output, current.AccessKeyID) {
		t.Errorf("Did not expect current identity's key in output, got: %s", output)
	}
}

func TestExportNonExistentIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("identity export nonexistent")
	if err == nil {
		t.Error("Expected error exporting non-existent identity")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

func TestExportInvalidFormat(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	addTestIdentity(t, im, "escalated-role")

	err := r.ExecuteCommand("identity export --format yaml")
	if err == nil {
		t.Error("Expected error for invalid format")
	}

	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("Expected 'unknown format' error, got: %v", err)
	}
}

func TestExportRemovedFromTopLevel(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// 'export' moved under 'identity' — the bare top-level command should
	// no longer exist
	err := r.ExecuteCommand("export")
	if err == nil {
		t.Error("Expected error for top-level 'export' after move to 'identity export'")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected not-found error, got: %v", err)
	}
}

func TestExportViaIdentityAlias(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	identity := addTestIdentity(t, im, "escalated-role")

	// 'identities' is an alias for 'identity' and inherits the export subcommand
	output := captureOutput(func() {
		err := r.ExecuteCommand("identities export")
		if err != nil {
			t.Errorf("Expected no error exporting via alias, got: %v", err)
		}
	})

	if !strings.Contains(output, "export AWS_ACCESS_KEY_ID="+identity.AccessKeyID) {
		t.Errorf("Expected identity's key in alias export output, got: %s", output)
	}
}
