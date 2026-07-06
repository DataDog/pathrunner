package unit

import (
	"os"
	"path/filepath"
	"pathrunner/pkg/status"
	"testing"
)

func writeTestManifest(t *testing.T, dir string, content string) string {
	t.Helper()
	path := filepath.Join(dir, "module-status.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test manifest: %v", err)
	}
	return path
}

const testManifestJSON = `{
  "modules": {
    "lambda-001": {
      "status": "tested",
      "last_tested": "2026-06-15",
      "tested_against": "pathfinding-labs/lambda-001",
      "notes": ""
    },
    "iam-001": {
      "status": "untested",
      "last_tested": null,
      "tested_against": null,
      "notes": "needs testing"
    },
    "ec2-001": {
      "status": "failing",
      "last_tested": "2026-06-10",
      "tested_against": "pathfinding-labs/ec2-001",
      "notes": "timeout on job run"
    }
  }
}`

func TestLoadManifestFromPath(t *testing.T) {
	dir := t.TempDir()
	path := writeTestManifest(t, dir, testManifestJSON)

	manifest, err := status.LoadManifestFromPath(path)
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	if len(manifest.Modules) != 3 {
		t.Errorf("Expected 3 modules, got %d", len(manifest.Modules))
	}

	lambda := manifest.Modules["lambda-001"]
	if lambda.Status != "tested" {
		t.Errorf("Expected lambda-001 status 'tested', got '%s'", lambda.Status)
	}
	if lambda.LastTested == nil || *lambda.LastTested != "2026-06-15" {
		t.Error("Expected lambda-001 last_tested '2026-06-15'")
	}

	iam := manifest.Modules["iam-001"]
	if iam.Status != "untested" {
		t.Errorf("Expected iam-001 status 'untested', got '%s'", iam.Status)
	}
	if iam.LastTested != nil {
		t.Error("Expected iam-001 last_tested to be nil")
	}
	if iam.Notes != "needs testing" {
		t.Errorf("Expected iam-001 notes 'needs testing', got '%s'", iam.Notes)
	}
}

func TestLoadManifestFromPathInvalid(t *testing.T) {
	_, err := status.LoadManifestFromPath("/nonexistent/path.json")
	if err == nil {
		t.Error("Expected error for nonexistent path")
	}
}

func TestLoadManifestFromPathMalformed(t *testing.T) {
	dir := t.TempDir()
	path := writeTestManifest(t, dir, "not json")

	_, err := status.LoadManifestFromPath(path)
	if err == nil {
		t.Error("Expected error for malformed JSON")
	}
}

func TestSaveManifestToPath(t *testing.T) {
	dir := t.TempDir()
	path := writeTestManifest(t, dir, testManifestJSON)

	manifest, err := status.LoadManifestFromPath(path)
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	// Modify and save
	manifest.MarkTested("iam-001", "pathfinding-labs/iam-001")

	savePath := filepath.Join(dir, "saved-status.json")
	if err := status.SaveManifestToPath(manifest, savePath); err != nil {
		t.Fatalf("Failed to save manifest: %v", err)
	}

	// Reload and verify
	reloaded, err := status.LoadManifestFromPath(savePath)
	if err != nil {
		t.Fatalf("Failed to reload manifest: %v", err)
	}

	iam := reloaded.Modules["iam-001"]
	if iam.Status != "tested" {
		t.Errorf("Expected iam-001 status 'tested' after mark, got '%s'", iam.Status)
	}
	if iam.LastTested == nil {
		t.Fatal("Expected iam-001 last_tested to be set after mark")
	}
	if iam.TestedAgainst == nil || *iam.TestedAgainst != "pathfinding-labs/iam-001" {
		t.Error("Expected iam-001 tested_against 'pathfinding-labs/iam-001'")
	}
}

func TestMarkStatus(t *testing.T) {
	dir := t.TempDir()
	path := writeTestManifest(t, dir, testManifestJSON)

	manifest, err := status.LoadManifestFromPath(path)
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	// Valid status changes
	for _, validStatus := range status.ValidStatuses {
		if err := manifest.MarkStatus("lambda-001", validStatus); err != nil {
			t.Errorf("Expected valid status '%s' to succeed: %v", validStatus, err)
		}
	}

	// Invalid status
	if err := manifest.MarkStatus("lambda-001", "banana"); err == nil {
		t.Error("Expected error for invalid status 'banana'")
	}
}

func TestSummary(t *testing.T) {
	dir := t.TempDir()
	path := writeTestManifest(t, dir, testManifestJSON)

	manifest, err := status.LoadManifestFromPath(path)
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	summary := manifest.Summary()
	if summary["tested"] != 1 {
		t.Errorf("Expected 1 tested, got %d", summary["tested"])
	}
	if summary["untested"] != 1 {
		t.Errorf("Expected 1 untested, got %d", summary["untested"])
	}
	if summary["failing"] != 1 {
		t.Errorf("Expected 1 failing, got %d", summary["failing"])
	}
}

func TestSortedModuleIDs(t *testing.T) {
	dir := t.TempDir()
	path := writeTestManifest(t, dir, testManifestJSON)

	manifest, err := status.LoadManifestFromPath(path)
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	ids := manifest.SortedModuleIDs()
	if len(ids) != 3 {
		t.Fatalf("Expected 3 IDs, got %d", len(ids))
	}
	if ids[0] != "ec2-001" || ids[1] != "iam-001" || ids[2] != "lambda-001" {
		t.Errorf("Expected sorted order [ec2-001, iam-001, lambda-001], got %v", ids)
	}
}

func TestMarkTestedSetsDate(t *testing.T) {
	dir := t.TempDir()
	path := writeTestManifest(t, dir, testManifestJSON)

	manifest, err := status.LoadManifestFromPath(path)
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	manifest.MarkTested("iam-001", "")
	entry := manifest.Modules["iam-001"]

	if entry.Status != "tested" {
		t.Errorf("Expected status 'tested', got '%s'", entry.Status)
	}
	if entry.LastTested == nil {
		t.Fatal("Expected last_tested to be set")
	}
	// Date should be today's date in YYYY-MM-DD format
	if len(*entry.LastTested) != 10 {
		t.Errorf("Expected date in YYYY-MM-DD format, got '%s'", *entry.LastTested)
	}
}
