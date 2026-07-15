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

func TestPayloadResultsSerialization(t *testing.T) {
	manifestJSON := `{
  "modules": {
    "lambda-001": {
      "status": "failing",
      "last_tested": "2026-07-10",
      "tested_against": "lambda-001-to-admin",
      "notes": "",
      "payload_results": [
        {"payload": "exfil/response", "execution": "PASS", "creds_obtained": "YES", "verified": "YES"},
        {"payload": "backdoor/attach-policy", "execution": "FAIL", "creds_obtained": "NO", "verified": "SKIP", "fail_reason": "AccessDenied"}
      ]
    }
  }
}`
	dir := t.TempDir()
	path := writeTestManifest(t, dir, manifestJSON)

	manifest, err := status.LoadManifestFromPath(path)
	if err != nil {
		t.Fatalf("Failed to load manifest with payload results: %v", err)
	}

	entry := manifest.Modules["lambda-001"]
	if len(entry.PayloadResults) != 2 {
		t.Fatalf("Expected 2 payload results, got %d", len(entry.PayloadResults))
	}
	if entry.PayloadResults[0].Payload != "exfil/response" {
		t.Errorf("Expected first payload 'exfil/response', got '%s'", entry.PayloadResults[0].Payload)
	}
	if entry.PayloadResults[1].FailReason != "AccessDenied" {
		t.Errorf("Expected fail reason 'AccessDenied', got '%s'", entry.PayloadResults[1].FailReason)
	}

	// Round-trip: save and reload
	savePath := filepath.Join(dir, "round-trip.json")
	if err := status.SaveManifestToPath(manifest, savePath); err != nil {
		t.Fatalf("Failed to save manifest: %v", err)
	}

	reloaded, err := status.LoadManifestFromPath(savePath)
	if err != nil {
		t.Fatalf("Failed to reload manifest: %v", err)
	}

	reloadedEntry := reloaded.Modules["lambda-001"]
	if len(reloadedEntry.PayloadResults) != 2 {
		t.Fatalf("Expected 2 payload results after round-trip, got %d", len(reloadedEntry.PayloadResults))
	}
	if reloadedEntry.PayloadResults[1].FailReason != "AccessDenied" {
		t.Errorf("Expected fail reason preserved after round-trip")
	}
}

func TestBackwardCompatibilityNoPayloadResults(t *testing.T) {
	// The existing testManifestJSON has no payload_results field — should load cleanly
	dir := t.TempDir()
	path := writeTestManifest(t, dir, testManifestJSON)

	manifest, err := status.LoadManifestFromPath(path)
	if err != nil {
		t.Fatalf("Failed to load manifest without payload_results: %v", err)
	}

	entry := manifest.Modules["lambda-001"]
	if len(entry.PayloadResults) != 0 {
		t.Errorf("Expected empty payload results for old format, got %d", len(entry.PayloadResults))
	}
}

func TestMarkTestedWithResultsAllPassed(t *testing.T) {
	dir := t.TempDir()
	path := writeTestManifest(t, dir, testManifestJSON)

	manifest, err := status.LoadManifestFromPath(path)
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	results := []status.PayloadResult{
		{Payload: "exfil/response", Execution: "PASS", Creds: "YES", Verified: "YES"},
		{Payload: "backdoor/attach-policy", Execution: "PASS", Creds: "NO", Verified: "YES"},
	}
	manifest.MarkTestedWithResults("iam-001", "iam-001-to-admin", results)

	entry := manifest.Modules["iam-001"]
	if entry.Status != "tested" {
		t.Errorf("Expected status 'tested' when all passed, got '%s'", entry.Status)
	}
	if len(entry.PayloadResults) != 2 {
		t.Errorf("Expected 2 payload results, got %d", len(entry.PayloadResults))
	}
	if entry.LastTested == nil {
		t.Fatal("Expected last_tested to be set")
	}
	if entry.TestedAgainst == nil || *entry.TestedAgainst != "iam-001-to-admin" {
		t.Error("Expected tested_against to be 'iam-001-to-admin'")
	}
}

func TestMarkTestedWithResultsSomeFailing(t *testing.T) {
	dir := t.TempDir()
	path := writeTestManifest(t, dir, testManifestJSON)

	manifest, err := status.LoadManifestFromPath(path)
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	results := []status.PayloadResult{
		{Payload: "exfil/response", Execution: "PASS", Creds: "YES", Verified: "YES"},
		{Payload: "backdoor/attach-policy", Execution: "FAIL", Creds: "NO", Verified: "SKIP", FailReason: "AccessDenied"},
	}
	manifest.MarkTestedWithResults("lambda-001", "lambda-001-to-admin", results)

	entry := manifest.Modules["lambda-001"]
	if entry.Status != "failing" {
		t.Errorf("Expected status 'failing' when some failed, got '%s'", entry.Status)
	}
}

func TestMarkTestedWithResultsEmptyResults(t *testing.T) {
	dir := t.TempDir()
	path := writeTestManifest(t, dir, testManifestJSON)

	manifest, err := status.LoadManifestFromPath(path)
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	manifest.MarkTestedWithResults("lambda-001", "lambda-001-to-admin", []status.PayloadResult{})

	entry := manifest.Modules["lambda-001"]
	if entry.Status != "failing" {
		t.Errorf("Expected status 'failing' for empty results, got '%s'", entry.Status)
	}
}

func TestMarkTestedWithResultsSkipVerifiedCountsAsPass(t *testing.T) {
	dir := t.TempDir()
	path := writeTestManifest(t, dir, testManifestJSON)

	manifest, err := status.LoadManifestFromPath(path)
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	// Modules with no credential output use SKIP for verification — should still count as passed
	results := []status.PayloadResult{
		{Payload: "exfil/response", Execution: "PASS", Creds: "YES", Verified: "SKIP"},
	}
	manifest.MarkTestedWithResults("iam-001", "iam-001-to-admin", results)

	entry := manifest.Modules["iam-001"]
	if entry.Status != "tested" {
		t.Errorf("Expected status 'tested' when SKIP verified, got '%s'", entry.Status)
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
