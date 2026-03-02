package integration

import (
	"strings"
	"testing"

	// Import modules and payloads to register them
	_ "pathrunner/pkg/exploits/ec2_passrole"
	_ "pathrunner/pkg/exploits/lambda_passrole"
	_ "pathrunner/pkg/exploits/sts_assume_role"
	_ "pathrunner/pkg/payloads/ec2"
	_ "pathrunner/pkg/payloads/lambda"
)

func TestShowInfoWithModule(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Select a module first
	err := r.ExecuteCommand("use lambda-001")
	if err != nil {
		t.Fatalf("Failed to use lambda-001: %v", err)
	}

	// show info should succeed
	err = r.ExecuteCommand("show info")
	if err != nil {
		t.Errorf("Expected no error from show info, got: %v", err)
	}
}

func TestShowInfoWithoutModule(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// show info without module should error
	err := r.ExecuteCommand("show info")
	if err == nil {
		t.Error("Expected error from show info without module selected")
	}
}

func TestSearchCommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search should work
	err := r.ExecuteCommand("search lambda")
	if err != nil {
		t.Errorf("Expected no error from search lambda, got: %v", err)
	}
}

func TestSearchCommandNoResults(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search with no results should not error
	err := r.ExecuteCommand("search zzz_nonexistent_xyz")
	if err != nil {
		t.Errorf("Expected no error from search with no results, got: %v", err)
	}
}

func TestSearchCommandNoArgs(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search without query should error
	err := r.ExecuteCommand("search")
	if err == nil {
		t.Error("Expected error from search without query")
	}
}

func TestUsePrimaryID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-001")
	if err != nil {
		t.Fatalf("Expected no error using lambda-001, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-001" {
		t.Errorf("Expected module name %q, got %q", "lambda-001", mod.Name())
	}
}

func TestUseOldAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Old exploit/lambda_passrole alias should still work
	err := r.ExecuteCommand("use exploit/lambda_passrole")
	if err != nil {
		t.Fatalf("Expected no error using exploit/lambda_passrole alias, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-001" {
		t.Errorf("Expected module name %q, got %q", "lambda-001", mod.Name())
	}
}

func TestUseShortAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use ec2-passrole")
	if err != nil {
		t.Fatalf("Expected no error using ec2-passrole alias, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "ec2-001" {
		t.Errorf("Expected module name %q, got %q", "ec2-001", mod.Name())
	}
}

func TestShowModulesEnriched(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// show modules should not error
	err := r.ExecuteCommand("show modules")
	if err != nil {
		t.Errorf("Expected no error from show modules, got: %v", err)
	}
}

func TestModulesListCommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// modules list should work
	err := r.ExecuteCommand("modules list")
	if err != nil {
		t.Errorf("Expected no error from modules list, got: %v", err)
	}
}

func TestModulesSearchCommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("modules search passrole")
	if err != nil {
		t.Errorf("Expected no error from modules search, got: %v", err)
	}
}

func TestPayloadsListCommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// payloads list without module should show all
	err := r.ExecuteCommand("payloads list")
	if err != nil {
		t.Errorf("Expected no error from payloads list, got: %v", err)
	}
}

func TestPayloadsListWithModule(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-001")
	if err != nil {
		t.Fatalf("Failed to use lambda-001: %v", err)
	}

	err = r.ExecuteCommand("payloads list")
	if err != nil {
		t.Errorf("Expected no error from payloads list with module, got: %v", err)
	}
}

func TestBackwardCompatSessionLoad(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Create workspace, set module with old name, switch away, switch back
	err := r.ExecuteCommand("workspace create compat-test")
	if err != nil {
		t.Fatalf("Failed to create workspace: %v", err)
	}

	// Use new ID
	err = r.ExecuteCommand("use lambda-001")
	if err != nil {
		t.Fatalf("Failed to use lambda-001: %v", err)
	}

	// Save
	err = r.ExecuteCommand("workspace save")
	if err != nil {
		t.Fatalf("Failed to save workspace: %v", err)
	}

	// Create and switch to another workspace
	err = r.ExecuteCommand("workspace create temp-ws")
	if err != nil {
		t.Fatalf("Failed to create temp workspace: %v", err)
	}

	// Switch back
	err = r.ExecuteCommand("workspace switch compat-test")
	if err != nil {
		t.Fatalf("Failed to switch back: %v", err)
	}

	// Module should be restored
	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected module to be restored after workspace switch")
	}
	if mod.Name() != "lambda-001" {
		t.Errorf("Expected restored module name %q, got %q", "lambda-001", mod.Name())
	}
}

func TestSearchByDifferentCriteria(t *testing.T) {
	testCases := []struct {
		name    string
		query   string
		wantMin int
	}{
		{"by_service_ec2", "ec2", 1},
		{"by_service_sts", "sts", 1},
		{"by_category", "new-passrole", 2},
		{"by_permission", "PassRole", 2},
		{"by_description", "Lambda", 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, _, _, cleanup := setupTest(t)
			defer cleanup()

			err := r.ExecuteCommand("search " + tc.query)
			if err != nil {
				t.Errorf("Expected no error from search %q, got: %v", tc.query, err)
			}
		})
	}
}

func TestModuleInfoViaPathInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Use all three modules and verify PathInfo is accessible
	moduleIDs := []string{"lambda-001", "ec2-001", "sts-001"}
	for _, id := range moduleIDs {
		t.Run(id, func(t *testing.T) {
			err := r.ExecuteCommand("use " + id)
			if err != nil {
				t.Fatalf("Failed to use %s: %v", id, err)
			}

			mod := r.GetCurrentModule()
			if mod == nil {
				t.Fatalf("Expected module to be set for %s", id)
			}

			info := mod.PathInfo()
			if info.ID != id {
				t.Errorf("Expected PathInfo().ID = %q, got %q", id, info.ID)
			}
			if info.Name == "" {
				t.Error("Expected non-empty PathInfo().Name")
			}
			if info.Category == "" {
				t.Error("Expected non-empty PathInfo().Category")
			}
			if len(info.Services) == 0 {
				t.Error("Expected non-empty PathInfo().Services")
			}
		})
	}
}

func TestShowInfoOutput(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use sts-001")
	if err != nil {
		t.Fatalf("Failed to use sts-001: %v", err)
	}

	// show info should work (we can't easily capture stdout but verify no error)
	err = r.ExecuteCommand("show info")
	if err != nil {
		t.Errorf("Expected no error from show info for sts-001, got: %v", err)
	}
}

func TestPromptWithNewID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-001")
	if err != nil {
		t.Fatalf("Failed to use lambda-001: %v", err)
	}

	prompt := r.BuildContextualPrompt()
	// The prompt should contain "lambda-001" (the new short ID format)
	if !strings.Contains(prompt, "lambda-001") {
		t.Errorf("Expected prompt to contain 'lambda-001', got: %q", prompt)
	}
}

func TestModulesCommandDefault(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// modules with no args should list all modules
	err := r.ExecuteCommand("modules")
	if err != nil {
		t.Errorf("Expected no error from modules command, got: %v", err)
	}
}

func TestPayloadsCommandDefault(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// payloads with no args should list all
	err := r.ExecuteCommand("payloads")
	if err != nil {
		t.Errorf("Expected no error from payloads command, got: %v", err)
	}
}

func TestSearchHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("search help")
	if err != nil {
		t.Errorf("Expected no error from search help, got: %v", err)
	}
}

func TestModulesHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("modules help")
	if err != nil {
		t.Errorf("Expected no error from modules help, got: %v", err)
	}
}

func TestPayloadsHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("payloads help")
	if err != nil {
		t.Errorf("Expected no error from payloads help, got: %v", err)
	}
}

func TestHelpIncludesNewCommands(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// help search should work
	err := r.ExecuteCommand("help search")
	if err != nil {
		t.Errorf("Expected no error from help search, got: %v", err)
	}

	// help modules should work
	err = r.ExecuteCommand("help modules")
	if err != nil {
		t.Errorf("Expected no error from help modules, got: %v", err)
	}

	// help payloads should work
	err = r.ExecuteCommand("help payloads")
	if err != nil {
		t.Errorf("Expected no error from help payloads, got: %v", err)
	}
}
