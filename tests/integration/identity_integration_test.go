// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"strings"
	"testing"
)

// TestIdentityList tests the identity list command
func TestIdentityList(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("identity list")
	if err != nil {
		t.Errorf("Expected no error listing identities, got: %v", err)
	}
}

// TestIdentitySwitchNonExistent tests switching to non-existent identity
func TestIdentitySwitchNonExistent(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("identity switch nonexistent")
	if err == nil {
		t.Error("Expected error when switching to non-existent identity")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

// TestIdentityClearExpired tests clearing expired identities
func TestIdentityClearExpired(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("identity clear --expired")
	if err != nil {
		t.Errorf("Expected no error clearing expired identities, got: %v", err)
	}
}

// TestIdentityClearNonExistent tests clearing non-existent identity
func TestIdentityClearNonExistent(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("identity clear nonexistent")
	if err == nil {
		t.Error("Expected error when clearing non-existent identity")
	}
}

// TestIdentityShowCurrent tests showing current identity
func TestIdentityShowCurrent(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("identity show")
	if err != nil {
		t.Errorf("Expected no error showing current identity, got: %v", err)
	}
}

// TestIdentityAliases tests identity command aliases
func TestIdentityAliases(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Test "identities" alias
	err := r.ExecuteCommand("identities")
	if err != nil {
		t.Errorf("Expected 'identities' alias to work, got: %v", err)
	}

	err = r.ExecuteCommand("identities list")
	if err != nil {
		t.Errorf("Expected 'identities list' to work, got: %v", err)
	}
}

// TestIdentityCheckWithoutIdentity tests identity check with no identity
func TestIdentityCheckWithoutIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("identity check")
	if err == nil {
		t.Error("Expected error when checking admin with no identity")
	}

	if !strings.Contains(err.Error(), "no current identity") {
		t.Errorf("Expected 'no current identity' error, got: %v", err)
	}
}

// TestIdentityCheckNonExistent tests identity check with non-existent identity
func TestIdentityCheckNonExistent(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("identity check nonexistent")
	if err == nil {
		t.Error("Expected error when checking non-existent identity")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

// TestIdentityCheckHelp tests identity check help
func TestIdentityCheckHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("identity check help")
	if err != nil {
		t.Errorf("Expected no error for identity check help, got: %v", err)
	}
}

// TestIdentityCommandValidation tests argument validation
func TestIdentityCommandValidation(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	testCases := []struct {
		name        string
		command     string
		expectError bool
		errorCheck  func(error) bool
	}{
		{
			name:        "switch without name",
			command:     "identity switch",
			expectError: true,
			errorCheck: func(err error) bool {
				return strings.Contains(err.Error(), "requires")
			},
		},
		{
			name:        "clear without argument",
			command:     "identity clear",
			expectError: true,
			errorCheck: func(err error) bool {
				return strings.Contains(err.Error(), "requires")
			},
		},
		{
			name:        "refresh without current",
			command:     "identity refresh",
			expectError: true,
			errorCheck: func(err error) bool {
				return strings.Contains(err.Error(), "no current identity")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.ExecuteCommand(tc.command)

			if tc.expectError && err == nil {
				t.Errorf("Expected error for command '%s'", tc.command)
			}

			if !tc.expectError && err != nil {
				t.Errorf("Expected no error for command '%s', got: %v", tc.command, err)
			}

			if tc.expectError && tc.errorCheck != nil && err != nil {
				if !tc.errorCheck(err) {
					t.Errorf("Error check failed for command '%s': %v", tc.command, err)
				}
			}
		})
	}
}

// TestIdentityAddFromEnvVarsRequiresEnvVars verifies that 'identity add
// --from-env-vars' fails cleanly (without storing anything) when the AWS
// environment variables are absent.
func TestIdentityAddFromEnvVarsRequiresEnvVars(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	err := r.ExecuteCommand("identity add --from-env-vars")
	if err == nil {
		t.Fatal("expected error when AWS environment variables are not set")
	}
	if !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID") {
		t.Errorf("expected error to mention AWS_ACCESS_KEY_ID, got: %v", err)
	}
	if len(im.GetIdentities()) != 0 {
		t.Error("expected no identity to be stored on failure")
	}
}

// TestIdentityAddFromIMDSUnreachable verifies that 'identity add --from-imds'
// fails cleanly (without storing anything) when the EC2 instance metadata
// service is not available.
func TestIdentityAddFromIMDSUnreachable(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("identity add --from-imds")
	if err == nil {
		// The test host is an EC2 instance with an attached role; the
		// identity was legitimately added.
		t.Skip("IMDS available; running on an EC2 instance with an attached role")
	}
	if !strings.Contains(err.Error(), "--from-imds requires") {
		t.Errorf("expected IMDS requirement message, got: %v", err)
	}
	if len(im.GetIdentities()) != 0 {
		t.Error("expected no identity to be stored on failure")
	}
}
