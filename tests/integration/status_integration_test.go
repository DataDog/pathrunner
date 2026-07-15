package integration

import (
	"os"
	"path/filepath"
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

func TestModulesMarkResultsMissingArgs(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("modules mark-results")
	if err == nil {
		t.Error("Expected error for mark-results with no args")
	}

	err = r.ExecuteCommand("modules mark-results lambda-001")
	if err == nil {
		t.Error("Expected error for mark-results with only module ID")
	}

	err = r.ExecuteCommand("modules mark-results lambda-001 lambda-001-to-admin")
	if err == nil {
		t.Error("Expected error for mark-results with no file path")
	}
}

func TestModulesMarkResultsInvalidFile(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("modules mark-results lambda-001 lambda-001-to-admin /nonexistent/file.json")
	if err == nil {
		t.Error("Expected error for nonexistent results file")
	}
}

func TestModulesMarkResultsInvalidJSON(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Write invalid JSON to a temp file
	tmpFile := filepath.Join(t.TempDir(), "bad-results.json")
	if err := os.WriteFile(tmpFile, []byte("not json"), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	err := r.ExecuteCommand("modules mark-results lambda-001 lambda-001-to-admin " + tmpFile)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestModulesMarkResultsSuccess(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	resultsJSON := `[{"payload":"exfil/response","execution":"PASS","creds_obtained":"YES","verified":"YES"}]`
	tmpFile := filepath.Join(t.TempDir(), "results.json")
	if err := os.WriteFile(tmpFile, []byte(resultsJSON), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	err := r.ExecuteCommand("modules mark-results lambda-001 lambda-001-to-admin " + tmpFile)
	if err != nil {
		t.Fatalf("Expected mark-results to succeed: %v", err)
	}

	// Verify status shows no error after recording results
	if err := r.ExecuteCommand("modules status lambda-001"); err != nil {
		t.Fatalf("Expected modules status to succeed after mark-results: %v", err)
	}
}
