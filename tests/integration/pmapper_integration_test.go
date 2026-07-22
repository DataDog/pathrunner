// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"os"
	"path/filepath"
	"github.com/DataDog/pathrunner/pkg/modules"
	"testing"
)

const pmapperFixtureDir = "../fixtures/pmapper"

// Test pmapper help via ExecuteCommand
func TestPmapperHelpViaExecuteCommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("pmapper help")
	if err != nil {
		t.Errorf("Expected no error for 'pmapper help', got: %v", err)
	}
}

// Test pmapper with no args shows help
func TestPmapperNoArgs(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("pmapper")
	if err != nil {
		t.Errorf("Expected no error for 'pmapper', got: %v", err)
	}
}

// Test pmapper import with fixture data
func TestPmapperImportFixture(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Get absolute path to fixtures
	absFixturePath, err := filepath.Abs(pmapperFixtureDir)
	if err != nil {
		t.Fatalf("Failed to get absolute fixture path: %v", err)
	}

	err = r.ExecuteCommand("pmapper import --path " + absFixturePath)
	if err != nil {
		t.Errorf("Expected no error for pmapper import, got: %v", err)
	}

	// Verify persistence file was created
	home := os.Getenv("HOME")
	graphFile := filepath.Join(home, ".pathrunner", "graphs", "123456789012.json")
	if _, err := os.Stat(graphFile); os.IsNotExist(err) {
		t.Error("Expected graph file to be persisted after import")
	}
}

// Test pmapper status after import
func TestPmapperStatusAfterImport(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	absFixturePath, err := filepath.Abs(pmapperFixtureDir)
	if err != nil {
		t.Fatalf("Failed to get absolute fixture path: %v", err)
	}

	err = r.ExecuteCommand("pmapper import --path " + absFixturePath)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	err = r.ExecuteCommand("pmapper status")
	if err != nil {
		t.Errorf("Expected no error for pmapper status, got: %v", err)
	}
}

// Test pmapper status with no graphs
func TestPmapperStatusEmpty(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("pmapper status")
	if err != nil {
		t.Errorf("Expected no error for pmapper status with no graphs, got: %v", err)
	}
}

// Test pmapper analyze requires identity
func TestPmapperAnalyzeNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("pmapper analyze")
	if err == nil {
		t.Error("Expected error when analyzing without identity")
	}
}

// Test pmapper analyze with identity but no graph
func TestPmapperAnalyzeNoGraph(t *testing.T) {
	r, sm, im, cleanup := setupTest(t)
	defer cleanup()

	// Add an identity with CallerARN
	identity := &modules.Identity{
		Name:      "lab-user",
		Type:      "keys",
		Region:    "us-east-1",
		CallerARN: "arn:aws:iam::123456789012:user/LabUser",
	}
	identities := map[string]*modules.Identity{"lab-user": identity}
	im.SetIdentities(identities)
	im.SetCurrent(identity)

	// Save to session so REPL sees it
	currentSession := sm.GetCurrentSession()
	currentSession.Identities = identities
	currentSession.CurrentIdentity = "lab-user"
	sm.SaveSession(currentSession)

	err := r.ExecuteCommand("pmapper analyze")
	if err == nil {
		t.Error("Expected error when analyzing without imported graph")
	}
}

// Test pmapper import with invalid path
func TestPmapperImportInvalidPath(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("pmapper import --path /nonexistent/path")
	if err == nil {
		t.Error("Expected error for import with invalid path")
	}
}

// Test pmapper unknown subcommand
func TestPmapperUnknownSubcommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("pmapper bogus")
	if err == nil {
		t.Error("Expected error for unknown pmapper subcommand")
	}
}

// Test pmapper import help
func TestPmapperImportHelpSubcommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("pmapper import help")
	if err != nil {
		t.Errorf("Expected no error for 'pmapper import help', got: %v", err)
	}
}

// Test pmapper analyze help
func TestPmapperAnalyzeHelpSubcommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("pmapper analyze help")
	if err != nil {
		t.Errorf("Expected no error for 'pmapper analyze help', got: %v", err)
	}
}

// Test pmapper status help
func TestPmapperStatusHelpSubcommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("pmapper status help")
	if err != nil {
		t.Errorf("Expected no error for 'pmapper status help', got: %v", err)
	}
}

// Test help pmapper (via global help)
func TestHelpPmapper(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("help pmapper")
	if err != nil {
		t.Errorf("Expected no error for 'help pmapper', got: %v", err)
	}
}

// Test import with --path missing value
func TestPmapperImportPathMissingValue(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("pmapper import --path")
	if err == nil {
		t.Error("Expected error when --path has no value")
	}
}

// Test pmapper analyze with admin identity (self-escalation)
func TestPmapperAnalyzeSelfEscalation(t *testing.T) {
	r, sm, im, cleanup := setupTest(t)
	defer cleanup()

	selfEscFixture, err := filepath.Abs("../fixtures/pmapper_selfesc")
	if err != nil {
		t.Fatalf("Failed to get absolute fixture path: %v", err)
	}

	// Import self-escalation fixtures
	err = r.ExecuteCommand("pmapper import --path " + selfEscFixture)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// Add identity for PolicyVersionUser (admin via self-escalation)
	identity := &modules.Identity{
		Name:      "selfesc-user",
		Type:      "keys",
		Region:    "us-east-1",
		CallerARN: "arn:aws:iam::111111111111:user/PolicyVersionUser",
	}
	identities := map[string]*modules.Identity{"selfesc-user": identity}
	im.SetIdentities(identities)
	im.SetCurrent(identity)

	currentSession := sm.GetCurrentSession()
	currentSession.Identities = identities
	currentSession.CurrentIdentity = "selfesc-user"
	sm.SaveSession(currentSession)

	// Analyze should NOT return error — it should show self-escalation paths
	err = r.ExecuteCommand("pmapper analyze")
	if err != nil {
		t.Errorf("Expected no error for admin identity with self-escalation, got: %v", err)
	}
}

// Test pmapper analyze with admin identity but no policies imported
func TestPmapperAnalyzeAdminNoPolicies(t *testing.T) {
	r, sm, im, cleanup := setupTest(t)
	defer cleanup()

	// Import original fixtures (AdminRole is admin, but policies.json only has non-IAM policies)
	absFixturePath, err := filepath.Abs(pmapperFixtureDir)
	if err != nil {
		t.Fatalf("Failed to get absolute fixture path: %v", err)
	}

	err = r.ExecuteCommand("pmapper import --path " + absFixturePath)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// Add identity for AdminRole
	identity := &modules.Identity{
		Name:      "admin-role",
		Type:      "keys",
		Region:    "us-east-1",
		CallerARN: "arn:aws:iam::123456789012:role/AdminRole",
	}
	identities := map[string]*modules.Identity{"admin-role": identity}
	im.SetIdentities(identities)
	im.SetCurrent(identity)

	currentSession := sm.GetCurrentSession()
	currentSession.Identities = identities
	currentSession.CurrentIdentity = "admin-role"
	sm.SaveSession(currentSession)

	// Should gracefully handle admin with no self-escalation results
	err = r.ExecuteCommand("pmapper analyze")
	if err != nil {
		t.Errorf("Expected no error for admin with no self-escalation, got: %v", err)
	}
}

// Test analyze --all with no identities
func TestPmapperAnalyzeAllNoIdentities(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("pmapper analyze --all")
	if err == nil {
		t.Error("Expected error when analyzing --all with no identities")
	}
}
