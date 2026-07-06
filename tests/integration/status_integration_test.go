package integration

import (
	"testing"
)

func TestModulesStatusCommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// modules status should succeed (reads from testdata/module-status.json)
	if err := r.ExecuteCommand("modules status"); err != nil {
		t.Fatalf("Expected modules status to succeed: %v", err)
	}
}

func TestModulesStatusSingleModule(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// modules status lambda-001 should succeed
	if err := r.ExecuteCommand("modules status lambda-001"); err != nil {
		t.Fatalf("Expected modules status lambda-001 to succeed: %v", err)
	}
}

func TestModulesStatusUnknownModule(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// modules status nonexistent should fail
	err := r.ExecuteCommand("modules status nonexistent-999")
	if err == nil {
		t.Error("Expected error for unknown module in status")
	}
}

func TestModulesHelpIncludesStatus(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// modules help should succeed (and include status info)
	if err := r.ExecuteCommand("modules help"); err != nil {
		t.Fatalf("Expected modules help to succeed: %v", err)
	}
}

func TestModulesMarkStatusInvalid(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// mark-status with invalid status should fail
	err := r.ExecuteCommand("modules mark-status lambda-001 banana")
	if err == nil {
		t.Error("Expected error for invalid status value")
	}
}

func TestModulesMarkStatusMissingArgs(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("modules mark-status")
	if err == nil {
		t.Error("Expected error for mark-status with no args")
	}

	err = r.ExecuteCommand("modules mark-status lambda-001")
	if err == nil {
		t.Error("Expected error for mark-status with only module ID")
	}
}

func TestModulesMarkTestedMissingArgs(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("modules mark-tested")
	if err == nil {
		t.Error("Expected error for mark-tested with no args")
	}
}
