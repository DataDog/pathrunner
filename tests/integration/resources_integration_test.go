package integration

import (
	"os"
	"path/filepath"
	"testing"
)

const cloudfoxIntFixtureDir = "../fixtures/cloudfox"

// Test cloudfox help via ExecuteCommand
func TestCloudfoxHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("cloudfox help")
	if err != nil {
		t.Errorf("Expected no error for 'cloudfox help', got: %v", err)
	}
}

// Test cloudfox with no args shows help
func TestCloudfoxNoArgs(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("cloudfox")
	if err != nil {
		t.Errorf("Expected no error for 'cloudfox', got: %v", err)
	}
}

// Test cloudfox unknown subcommand
func TestCloudfoxUnknownSubcommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("cloudfox bogus")
	if err == nil {
		t.Error("Expected error for unknown cloudfox subcommand")
	}
}

// Test cloudfox import with fixture data
func TestCloudfoxImportFixture(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	absFixturePath, err := filepath.Abs(filepath.Join(cloudfoxIntFixtureDir, "testprofile-123456789012"))
	if err != nil {
		t.Fatalf("Failed to get absolute fixture path: %v", err)
	}

	err = r.ExecuteCommand("cloudfox import --path " + absFixturePath)
	if err != nil {
		t.Errorf("Expected no error for cloudfox import, got: %v", err)
	}

	// Verify persistence file was created
	home := os.Getenv("HOME")
	resourceFile := filepath.Join(home, ".pathrunner", "resources", "123456789012.json")
	if _, err := os.Stat(resourceFile); os.IsNotExist(err) {
		t.Error("Expected resource file to be persisted after import")
	}
}

// Test cloudfox import with bare path (no --path flag)
func TestCloudfoxImportBarePath(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	absFixturePath, err := filepath.Abs(filepath.Join(cloudfoxIntFixtureDir, "testprofile-123456789012"))
	if err != nil {
		t.Fatalf("Failed to get absolute fixture path: %v", err)
	}

	err = r.ExecuteCommand("cloudfox import " + absFixturePath)
	if err != nil {
		t.Errorf("Expected no error for cloudfox import with bare path, got: %v", err)
	}
}

// Test cloudfox import with invalid path
func TestCloudfoxImportInvalidPath(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("cloudfox import --path /nonexistent/path")
	if err == nil {
		t.Error("Expected error for import with invalid path")
	}
}

// Test cloudfox import help
func TestCloudfoxImportHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("cloudfox import help")
	if err != nil {
		t.Errorf("Expected no error for 'cloudfox import help', got: %v", err)
	}
}

// Test cloudfox import --path missing value
func TestCloudfoxImportPathMissingValue(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("cloudfox import --path")
	if err == nil {
		t.Error("Expected error when --path has no value")
	}
}

// Test resources help
func TestResourcesHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("resources help")
	if err != nil {
		t.Errorf("Expected no error for 'resources help', got: %v", err)
	}
}

// Test resources with no args shows help
func TestResourcesNoArgs(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("resources")
	if err != nil {
		t.Errorf("Expected no error for 'resources', got: %v", err)
	}
}

// Test resources unknown subcommand
func TestResourcesUnknownSubcommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("resources bogus")
	if err == nil {
		t.Error("Expected error for unknown resources subcommand")
	}
}

// Test resources list with no data
func TestResourcesListEmpty(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("resources list")
	if err != nil {
		t.Errorf("Expected no error for 'resources list' with no data, got: %v", err)
	}
}

// Test resources summary with no data
func TestResourcesSummaryEmpty(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("resources summary")
	if err != nil {
		t.Errorf("Expected no error for 'resources summary' with no data, got: %v", err)
	}
}

// Test resources status with no data
func TestResourcesStatusEmpty(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("resources status")
	if err != nil {
		t.Errorf("Expected no error for 'resources status' with no data, got: %v", err)
	}
}

// Test full workflow: import then list, summary, status
func TestResourcesWorkflow(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	absFixturePath, err := filepath.Abs(filepath.Join(cloudfoxIntFixtureDir, "testprofile-123456789012"))
	if err != nil {
		t.Fatalf("Failed to get absolute fixture path: %v", err)
	}

	// Import
	err = r.ExecuteCommand("resources import --path " + absFixturePath)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// List all
	err = r.ExecuteCommand("resources list")
	if err != nil {
		t.Errorf("Expected no error for 'resources list', got: %v", err)
	}

	// List filtered by service
	err = r.ExecuteCommand("resources list ec2")
	if err != nil {
		t.Errorf("Expected no error for 'resources list ec2', got: %v", err)
	}

	// List with --wide
	err = r.ExecuteCommand("resources list --wide")
	if err != nil {
		t.Errorf("Expected no error for 'resources list --wide', got: %v", err)
	}

	// Summary
	err = r.ExecuteCommand("resources summary")
	if err != nil {
		t.Errorf("Expected no error for 'resources summary', got: %v", err)
	}

	// Status
	err = r.ExecuteCommand("resources status")
	if err != nil {
		t.Errorf("Expected no error for 'resources status', got: %v", err)
	}
}

// Test resources list help
func TestResourcesListHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("resources list help")
	if err != nil {
		t.Errorf("Expected no error for 'resources list help', got: %v", err)
	}
}

// Test resources summary help
func TestResourcesSummaryHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("resources summary help")
	if err != nil {
		t.Errorf("Expected no error for 'resources summary help', got: %v", err)
	}
}

// Test resources status help
func TestResourcesStatusHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("resources status help")
	if err != nil {
		t.Errorf("Expected no error for 'resources status help', got: %v", err)
	}
}

// Test help resources (via global help)
func TestHelpResources(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("help resources")
	if err != nil {
		t.Errorf("Expected no error for 'help resources', got: %v", err)
	}
}

// Test help cloudfox (via global help)
func TestHelpCloudfox(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("help cloudfox")
	if err != nil {
		t.Errorf("Expected no error for 'help cloudfox', got: %v", err)
	}
}

// Test show resources (via show proxy)
func TestShowResources(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	absFixturePath, err := filepath.Abs(filepath.Join(cloudfoxIntFixtureDir, "testprofile-123456789012"))
	if err != nil {
		t.Fatalf("Failed to get absolute fixture path: %v", err)
	}

	err = r.ExecuteCommand("cloudfox import --path " + absFixturePath)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// show resources list
	err = r.ExecuteCommand("show resources list")
	if err != nil {
		t.Errorf("Expected no error for 'show resources list', got: %v", err)
	}

	// show resources summary
	err = r.ExecuteCommand("show resources summary")
	if err != nil {
		t.Errorf("Expected no error for 'show resources summary', got: %v", err)
	}

	// show resources status
	err = r.ExecuteCommand("show resources status")
	if err != nil {
		t.Errorf("Expected no error for 'show resources status', got: %v", err)
	}
}

// Test show resources import is blocked (write operation)
func TestShowResourcesImportBlocked(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("show resources import")
	if err == nil {
		t.Error("Expected error for 'show resources import' (write operation should be blocked)")
	}
}

// Test resources list with non-existent service filter
func TestResourcesListNonExistentService(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	absFixturePath, err := filepath.Abs(filepath.Join(cloudfoxIntFixtureDir, "testprofile-123456789012"))
	if err != nil {
		t.Fatalf("Failed to get absolute fixture path: %v", err)
	}

	err = r.ExecuteCommand("cloudfox import --path " + absFixturePath)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// Should not error, just show "no resources found"
	err = r.ExecuteCommand("resources list nonexistentservice")
	if err != nil {
		t.Errorf("Expected no error for non-existent service filter, got: %v", err)
	}
}

// Test that resources list shows Source column after import
func TestResourcesListShowsSourceColumn(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	absFixturePath, err := filepath.Abs(filepath.Join(cloudfoxIntFixtureDir, "testprofile-123456789012"))
	if err != nil {
		t.Fatalf("Failed to get absolute fixture path: %v", err)
	}

	// Import
	err = r.ExecuteCommand("cloudfox import --path " + absFixturePath)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// List should work (Source column is now part of the table)
	err = r.ExecuteCommand("resources list")
	if err != nil {
		t.Errorf("Expected no error for 'resources list', got: %v", err)
	}

	// Wide list should also work
	err = r.ExecuteCommand("resources list --wide")
	if err != nil {
		t.Errorf("Expected no error for 'resources list --wide', got: %v", err)
	}
}

// Test that resources status shows import type for cloudfox imports
func TestResourcesStatusShowsSourceType(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	absFixturePath, err := filepath.Abs(filepath.Join(cloudfoxIntFixtureDir, "testprofile-123456789012"))
	if err != nil {
		t.Fatalf("Failed to get absolute fixture path: %v", err)
	}

	err = r.ExecuteCommand("cloudfox import --path " + absFixturePath)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// Status should show import type
	err = r.ExecuteCommand("resources status")
	if err != nil {
		t.Errorf("Expected no error for 'resources status', got: %v", err)
	}
}

// Test resources import works as alias for cloudfox import
func TestResourcesImportAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	absFixturePath, err := filepath.Abs(filepath.Join(cloudfoxIntFixtureDir, "testprofile-123456789012"))
	if err != nil {
		t.Fatalf("Failed to get absolute fixture path: %v", err)
	}

	err = r.ExecuteCommand("resources import --path " + absFixturePath)
	if err != nil {
		t.Errorf("Expected no error for 'resources import', got: %v", err)
	}
}
