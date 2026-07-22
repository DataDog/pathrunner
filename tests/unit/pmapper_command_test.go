// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/core/repl"
	"github.com/DataDog/pathrunner/pkg/modules"
	"testing"
)

// Test pmapper command registration
func TestPmapperCommandExists(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	_, exists := commands["pmapper"]
	if !exists {
		t.Fatal("Expected pmapper command to exist")
	}
}

// Test pmapper help (no args)
func TestPmapperCommandNoArgs(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	pmapperCmd := commands["pmapper"]

	// No args should show help (no error)
	err := pmapperCmd.Handler(r, []string{})
	if err != nil {
		t.Errorf("Expected no error for pmapper with no args, got: %v", err)
	}
}

// Test pmapper help subcommand
func TestPmapperHelpSubcommand(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	pmapperCmd := commands["pmapper"]

	err := pmapperCmd.Handler(r, []string{"help"})
	if err != nil {
		t.Errorf("Expected no error for pmapper help, got: %v", err)
	}
}

// Test pmapper import help
func TestPmapperImportHelp(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	pmapperCmd := commands["pmapper"]

	err := pmapperCmd.Handler(r, []string{"import", "help"})
	if err != nil {
		t.Errorf("Expected no error for pmapper import help, got: %v", err)
	}
}

// Test pmapper analyze help
func TestPmapperAnalyzeHelp(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	pmapperCmd := commands["pmapper"]

	err := pmapperCmd.Handler(r, []string{"analyze", "help"})
	if err != nil {
		t.Errorf("Expected no error for pmapper analyze help, got: %v", err)
	}
}

// Test pmapper status help
func TestPmapperStatusHelp(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	pmapperCmd := commands["pmapper"]

	err := pmapperCmd.Handler(r, []string{"status", "help"})
	if err != nil {
		t.Errorf("Expected no error for pmapper status help, got: %v", err)
	}
}

// Test pmapper unknown subcommand
func TestPmapperUnknownSubcommand(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	pmapperCmd := commands["pmapper"]

	err := pmapperCmd.Handler(r, []string{"bogus"})
	if err == nil {
		t.Error("Expected error for unknown pmapper subcommand")
	}
}

// Test pmapper status with no loaded graphs
func TestPmapperStatusNoGraphs(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	pmapperCmd := commands["pmapper"]

	// Should work without error even with no graphs
	err := pmapperCmd.Handler(r, []string{"status"})
	if err != nil {
		t.Errorf("Expected no error for pmapper status with no graphs, got: %v", err)
	}
}

// Test pmapper analyze requires identity
func TestPmapperAnalyzeRequiresIdentity(t *testing.T) {
	// Use a mock that returns nil for current identity
	im := &MockNilIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	pmapperCmd := commands["pmapper"]

	err := pmapperCmd.Handler(r, []string{"analyze"})
	if err == nil {
		t.Error("Expected error when analyzing without identity")
	}
}

// Test pmapper import with invalid flag
func TestPmapperImportInvalidFlag(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	pmapperCmd := commands["pmapper"]

	err := pmapperCmd.Handler(r, []string{"import", "--invalid"})
	if err == nil {
		t.Error("Expected error for invalid import flag")
	}
}

// Test pmapper import missing path value
func TestPmapperImportMissingPathValue(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	pmapperCmd := commands["pmapper"]

	err := pmapperCmd.Handler(r, []string{"import", "--path"})
	if err == nil {
		t.Error("Expected error when --path has no value")
	}
}

// Test pmapper analyze with invalid flag
func TestPmapperAnalyzeInvalidFlag(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	pmapperCmd := commands["pmapper"]

	err := pmapperCmd.Handler(r, []string{"analyze", "--invalid"})
	if err == nil {
		t.Error("Expected error for invalid analyze flag")
	}
}

// Test that PMapperManager is accessible
func TestPmapperManagerAccessor(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	mgr := r.GetPMapperManager()
	if mgr == nil {
		t.Fatal("Expected PMapper manager to be initialized")
	}
}

// MockNilIdentityManager returns nil for current identity
type MockNilIdentityManager struct {
	MockIdentityManager
}

func (m *MockNilIdentityManager) GetCurrent() *modules.Identity {
	return nil
}

func (m *MockNilIdentityManager) FindIdentityByARN(arn string) *modules.Identity {
	return nil
}

func (m *MockNilIdentityManager) UpdateIdentityCredentials(name, accessKeyID, secretKey, sessionToken string) error {
	return nil
}
