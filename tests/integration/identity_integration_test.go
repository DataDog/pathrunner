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
