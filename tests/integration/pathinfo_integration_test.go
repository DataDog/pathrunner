package integration

import (
	"strings"
	"testing"

	// Import modules and payloads to register them
	_ "pathrunner/pkg/exploits/ec2_passrole"
	_ "pathrunner/pkg/exploits/glue_passrole_job"
	_ "pathrunner/pkg/exploits/iam_addusertogroup"
	_ "pathrunner/pkg/exploits/iam_attachgrouppolicy"
	_ "pathrunner/pkg/exploits/iam_attachrolepolicy"
	_ "pathrunner/pkg/exploits/iam_attachrolepolicy_assumerole"
	_ "pathrunner/pkg/exploits/iam_attachrolepolicy_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_attachuserpolicy"
	_ "pathrunner/pkg/exploits/iam_attachuserpolicy_createaccesskey"
	_ "pathrunner/pkg/exploits/iam_create_policy_version"
	_ "pathrunner/pkg/exploits/iam_createaccesskey"
	_ "pathrunner/pkg/exploits/iam_createloginprofile"
	_ "pathrunner/pkg/exploits/iam_createpolicyversion_assumerole"
	_ "pathrunner/pkg/exploits/iam_createpolicyversion_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_deleteaccesskey_createaccesskey"
	_ "pathrunner/pkg/exploits/iam_putgrouppolicy"
	_ "pathrunner/pkg/exploits/iam_putrolepolicy"
	_ "pathrunner/pkg/exploits/iam_putrolepolicy_assumerole"
	_ "pathrunner/pkg/exploits/iam_putrolepolicy_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_putuserpolicy"
	_ "pathrunner/pkg/exploits/iam_putuserpolicy_createaccesskey"
	_ "pathrunner/pkg/exploits/iam_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_updateloginprofile"
	_ "pathrunner/pkg/exploits/lambda_createfunction_addpermission"
	_ "pathrunner/pkg/exploits/lambda_passrole"
	_ "pathrunner/pkg/exploits/lambda_passrole_esm"
	_ "pathrunner/pkg/exploits/lambda_updatecode"
	_ "pathrunner/pkg/exploits/lambda_updatecode_addpermission"
	_ "pathrunner/pkg/exploits/lambda_updatecode_invoke"
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

	// help info should work
	err = r.ExecuteCommand("help info")
	if err != nil {
		t.Errorf("Expected no error from help info, got: %v", err)
	}
}

func TestUseLambda002ByID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-002")
	if err != nil {
		t.Fatalf("Expected no error using lambda-002, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-002" {
		t.Errorf("Expected module name %q, got %q", "lambda-002", mod.Name())
	}
}

func TestUseLambda002ByAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-passrole-esm")
	if err != nil {
		t.Fatalf("Expected no error using lambda-passrole-esm, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-002" {
		t.Errorf("Expected module name %q, got %q", "lambda-002", mod.Name())
	}
}

func TestUseLambda002OldAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use exploit/lambda_passrole_esm")
	if err != nil {
		t.Fatalf("Expected no error using exploit/lambda_passrole_esm, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-002" {
		t.Errorf("Expected module name %q, got %q", "lambda-002", mod.Name())
	}
}

func TestShowInfoLambda002(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-002")
	if err != nil {
		t.Fatalf("Failed to use lambda-002: %v", err)
	}

	err = r.ExecuteCommand("show info")
	if err != nil {
		t.Errorf("Expected no error from show info for lambda-002, got: %v", err)
	}
}

func TestSearchFindsLambda002(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("search CreateEventSourceMapping")
	if err != nil {
		t.Errorf("Expected no error from search, got: %v", err)
	}
}

func TestLambda002InModulesList(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("modules list")
	if err != nil {
		t.Errorf("Expected no error from modules list, got: %v", err)
	}
}

func TestLambda002PromptContainsID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-002")
	if err != nil {
		t.Fatalf("Failed to use lambda-002: %v", err)
	}

	prompt := r.BuildContextualPrompt()
	if !strings.Contains(prompt, "lambda-002") {
		t.Errorf("Expected prompt to contain 'lambda-002', got: %q", prompt)
	}
}

func TestLambda002PayloadsList(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-002")
	if err != nil {
		t.Fatalf("Failed to use lambda-002: %v", err)
	}

	err = r.ExecuteCommand("payloads list")
	if err != nil {
		t.Errorf("Expected no error from payloads list with lambda-002, got: %v", err)
	}
}

func TestModuleInfoViaPathInfoIncludesLambda002(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	moduleIDs := []string{"lambda-001", "lambda-002", "lambda-003", "lambda-004", "lambda-005", "lambda-006", "ec2-001", "sts-001",
		"iam-001", "iam-002", "iam-003", "iam-004", "iam-005", "iam-006", "iam-007", "iam-008", "iam-009", "iam-010",
		"iam-011", "iam-012", "iam-013", "iam-014", "iam-015", "iam-016", "iam-017", "iam-018", "iam-019", "iam-020", "iam-021"}
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

// lambda-004 integration tests

func TestUseLambda004ByID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-004")
	if err != nil {
		t.Fatalf("Expected no error using lambda-004, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-004" {
		t.Errorf("Expected module name %q, got %q", "lambda-004", mod.Name())
	}
}

func TestUseLambda004ByAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-updatecode-invoke")
	if err != nil {
		t.Fatalf("Expected no error using lambda-updatecode-invoke, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-004" {
		t.Errorf("Expected module name %q, got %q", "lambda-004", mod.Name())
	}
}

func TestUseLambda004OldAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use exploit/lambda_updatecode_invoke")
	if err != nil {
		t.Fatalf("Expected no error using exploit/lambda_updatecode_invoke, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-004" {
		t.Errorf("Expected module name %q, got %q", "lambda-004", mod.Name())
	}
}

func TestShowInfoLambda004(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-004")
	if err != nil {
		t.Fatalf("Failed to use lambda-004: %v", err)
	}

	err = r.ExecuteCommand("show info")
	if err != nil {
		t.Errorf("Expected no error from show info for lambda-004, got: %v", err)
	}
}

func TestSearchFindsLambda004(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("search InvokeFunction")
	if err != nil {
		t.Errorf("Expected no error from search, got: %v", err)
	}
}

func TestSearchExistingPassroleFindsLambda004(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("search existing-passrole")
	if err != nil {
		t.Errorf("Expected no error from search, got: %v", err)
	}
}

func TestLambda004PromptContainsID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-004")
	if err != nil {
		t.Fatalf("Failed to use lambda-004: %v", err)
	}

	prompt := r.BuildContextualPrompt()
	if !strings.Contains(prompt, "lambda-004") {
		t.Errorf("Expected prompt to contain 'lambda-004', got: %q", prompt)
	}
}

func TestLambda004PayloadsList(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-004")
	if err != nil {
		t.Fatalf("Failed to use lambda-004: %v", err)
	}

	err = r.ExecuteCommand("payloads list")
	if err != nil {
		t.Errorf("Expected no error from payloads list with lambda-004, got: %v", err)
	}
}

func TestLambda004ShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-004")
	if err != nil {
		t.Fatalf("Failed to use lambda-004: %v", err)
	}

	err = r.ExecuteCommand("show options")
	if err != nil {
		t.Errorf("Expected no error from show options for lambda-004, got: %v", err)
	}
}

func TestLambda004WorkspacePersistence(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("workspace create lambda004-test")
	if err != nil {
		t.Fatalf("Failed to create workspace: %v", err)
	}

	err = r.ExecuteCommand("use lambda-004")
	if err != nil {
		t.Fatalf("Failed to use lambda-004: %v", err)
	}

	err = r.ExecuteCommand("workspace save")
	if err != nil {
		t.Fatalf("Failed to save workspace: %v", err)
	}

	err = r.ExecuteCommand("workspace create temp-ws-004")
	if err != nil {
		t.Fatalf("Failed to create temp workspace: %v", err)
	}

	err = r.ExecuteCommand("workspace switch lambda004-test")
	if err != nil {
		t.Fatalf("Failed to switch back: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected module to be restored after workspace switch")
	}
	if mod.Name() != "lambda-004" {
		t.Errorf("Expected restored module name %q, got %q", "lambda-004", mod.Name())
	}
}

// lambda-003 integration tests

func TestUseLambda003ByID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-003")
	if err != nil {
		t.Fatalf("Expected no error using lambda-003, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-003" {
		t.Errorf("Expected module name %q, got %q", "lambda-003", mod.Name())
	}
}

func TestUseLambda003ByAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-updatecode")
	if err != nil {
		t.Fatalf("Expected no error using lambda-updatecode, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-003" {
		t.Errorf("Expected module name %q, got %q", "lambda-003", mod.Name())
	}
}

func TestUseLambda003OldAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use exploit/lambda_updatecode")
	if err != nil {
		t.Fatalf("Expected no error using exploit/lambda_updatecode, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-003" {
		t.Errorf("Expected module name %q, got %q", "lambda-003", mod.Name())
	}
}

func TestShowInfoLambda003(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-003")
	if err != nil {
		t.Fatalf("Failed to use lambda-003: %v", err)
	}

	err = r.ExecuteCommand("show info")
	if err != nil {
		t.Errorf("Expected no error from show info for lambda-003, got: %v", err)
	}
}

func TestSearchFindsLambda003(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("search UpdateFunctionCode")
	if err != nil {
		t.Errorf("Expected no error from search, got: %v", err)
	}
}

func TestSearchExistingPassroleFindsLambda003(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("search existing-passrole")
	if err != nil {
		t.Errorf("Expected no error from search, got: %v", err)
	}
}

func TestLambda003InModulesList(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("modules list")
	if err != nil {
		t.Errorf("Expected no error from modules list, got: %v", err)
	}
}

func TestLambda003PromptContainsID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-003")
	if err != nil {
		t.Fatalf("Failed to use lambda-003: %v", err)
	}

	prompt := r.BuildContextualPrompt()
	if !strings.Contains(prompt, "lambda-003") {
		t.Errorf("Expected prompt to contain 'lambda-003', got: %q", prompt)
	}
}

func TestLambda003PayloadsList(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-003")
	if err != nil {
		t.Fatalf("Failed to use lambda-003: %v", err)
	}

	err = r.ExecuteCommand("payloads list")
	if err != nil {
		t.Errorf("Expected no error from payloads list with lambda-003, got: %v", err)
	}
}

func TestLambda003ShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-003")
	if err != nil {
		t.Fatalf("Failed to use lambda-003: %v", err)
	}

	err = r.ExecuteCommand("show options")
	if err != nil {
		t.Errorf("Expected no error from show options for lambda-003, got: %v", err)
	}
}

func TestLambda003WorkspacePersistence(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Set up lambda-003 in a workspace
	err := r.ExecuteCommand("workspace create lambda003-test")
	if err != nil {
		t.Fatalf("Failed to create workspace: %v", err)
	}

	err = r.ExecuteCommand("use lambda-003")
	if err != nil {
		t.Fatalf("Failed to use lambda-003: %v", err)
	}

	err = r.ExecuteCommand("workspace save")
	if err != nil {
		t.Fatalf("Failed to save workspace: %v", err)
	}

	// Switch away and back
	err = r.ExecuteCommand("workspace create temp-ws-003")
	if err != nil {
		t.Fatalf("Failed to create temp workspace: %v", err)
	}

	err = r.ExecuteCommand("workspace switch lambda003-test")
	if err != nil {
		t.Fatalf("Failed to switch back: %v", err)
	}

	// Module should be restored
	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected module to be restored after workspace switch")
	}
	if mod.Name() != "lambda-003" {
		t.Errorf("Expected restored module name %q, got %q", "lambda-003", mod.Name())
	}
}

// lambda-005 integration tests

func TestUseLambda005ByID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-005")
	if err != nil {
		t.Fatalf("Expected no error using lambda-005, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-005" {
		t.Errorf("Expected module name %q, got %q", "lambda-005", mod.Name())
	}
}

func TestUseLambda005ByAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-updatecode-addpermission")
	if err != nil {
		t.Fatalf("Expected no error using lambda-updatecode-addpermission, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-005" {
		t.Errorf("Expected module name %q, got %q", "lambda-005", mod.Name())
	}
}

func TestUseLambda005OldAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use exploit/lambda_updatecode_addpermission")
	if err != nil {
		t.Fatalf("Expected no error using exploit/lambda_updatecode_addpermission, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-005" {
		t.Errorf("Expected module name %q, got %q", "lambda-005", mod.Name())
	}
}

func TestShowInfoLambda005(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-005")
	if err != nil {
		t.Fatalf("Failed to use lambda-005: %v", err)
	}

	err = r.ExecuteCommand("show info")
	if err != nil {
		t.Errorf("Expected no error from show info for lambda-005, got: %v", err)
	}
}

func TestSearchFindsLambda005(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("search AddPermission")
	if err != nil {
		t.Errorf("Expected no error from search, got: %v", err)
	}
}

func TestLambda005PromptContainsID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-005")
	if err != nil {
		t.Fatalf("Failed to use lambda-005: %v", err)
	}

	prompt := r.BuildContextualPrompt()
	if !strings.Contains(prompt, "lambda-005") {
		t.Errorf("Expected prompt to contain 'lambda-005', got: %q", prompt)
	}
}

func TestLambda005PayloadsList(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-005")
	if err != nil {
		t.Fatalf("Failed to use lambda-005: %v", err)
	}

	err = r.ExecuteCommand("payloads list")
	if err != nil {
		t.Errorf("Expected no error from payloads list with lambda-005, got: %v", err)
	}
}

func TestLambda005ShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-005")
	if err != nil {
		t.Fatalf("Failed to use lambda-005: %v", err)
	}

	err = r.ExecuteCommand("show options")
	if err != nil {
		t.Errorf("Expected no error from show options for lambda-005, got: %v", err)
	}
}

// lambda-006 integration tests

func TestUseLambda006ByID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-006")
	if err != nil {
		t.Fatalf("Expected no error using lambda-006, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-006" {
		t.Errorf("Expected module name %q, got %q", "lambda-006", mod.Name())
	}
}

func TestUseLambda006ByAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-createfunction-addpermission")
	if err != nil {
		t.Fatalf("Expected no error using lambda-createfunction-addpermission, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-006" {
		t.Errorf("Expected module name %q, got %q", "lambda-006", mod.Name())
	}
}

func TestUseLambda006OldAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use exploit/lambda_createfunction_addpermission")
	if err != nil {
		t.Fatalf("Expected no error using exploit/lambda_createfunction_addpermission, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "lambda-006" {
		t.Errorf("Expected module name %q, got %q", "lambda-006", mod.Name())
	}
}

func TestShowInfoLambda006(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-006")
	if err != nil {
		t.Fatalf("Failed to use lambda-006: %v", err)
	}

	err = r.ExecuteCommand("show info")
	if err != nil {
		t.Errorf("Expected no error from show info for lambda-006, got: %v", err)
	}
}

func TestSearchFindsLambda006(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("search CreateFunction")
	if err != nil {
		t.Errorf("Expected no error from search, got: %v", err)
	}
}

func TestSearchNewPassroleFindsLambda006(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("search new-passrole")
	if err != nil {
		t.Errorf("Expected no error from search, got: %v", err)
	}
}

func TestLambda006PromptContainsID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-006")
	if err != nil {
		t.Fatalf("Failed to use lambda-006: %v", err)
	}

	prompt := r.BuildContextualPrompt()
	if !strings.Contains(prompt, "lambda-006") {
		t.Errorf("Expected prompt to contain 'lambda-006', got: %q", prompt)
	}
}

func TestLambda006PayloadsList(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-006")
	if err != nil {
		t.Fatalf("Failed to use lambda-006: %v", err)
	}

	err = r.ExecuteCommand("payloads list")
	if err != nil {
		t.Errorf("Expected no error from payloads list with lambda-006, got: %v", err)
	}
}

func TestLambda006ShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-006")
	if err != nil {
		t.Fatalf("Failed to use lambda-006: %v", err)
	}

	err = r.ExecuteCommand("show options")
	if err != nil {
		t.Errorf("Expected no error from show options for lambda-006, got: %v", err)
	}
}

// iam-001 integration tests

func TestUseIAM001ByID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-001")
	if err != nil {
		t.Fatalf("Expected no error using iam-001, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "iam-001" {
		t.Errorf("Expected module name %q, got %q", "iam-001", mod.Name())
	}
}

func TestUseIAM001ByAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-createpolicyversion")
	if err != nil {
		t.Fatalf("Expected no error using iam-createpolicyversion, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "iam-001" {
		t.Errorf("Expected module name %q, got %q", "iam-001", mod.Name())
	}
}

func TestUseIAM001OldAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use exploit/iam_create_policy_version")
	if err != nil {
		t.Fatalf("Expected no error using exploit/iam_create_policy_version, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "iam-001" {
		t.Errorf("Expected module name %q, got %q", "iam-001", mod.Name())
	}
}

func TestShowInfoIAM001(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-001")
	if err != nil {
		t.Fatalf("Failed to use iam-001: %v", err)
	}

	err = r.ExecuteCommand("show info")
	if err != nil {
		t.Errorf("Expected no error from show info for iam-001, got: %v", err)
	}
}

func TestIAM001ShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-001")
	if err != nil {
		t.Fatalf("Failed to use iam-001: %v", err)
	}

	err = r.ExecuteCommand("show options")
	if err != nil {
		t.Errorf("Expected no error from show options for iam-001, got: %v", err)
	}
}

func TestSearchSelfEscalationFindsIAM001(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("search self-escalation")
	if err != nil {
		t.Errorf("Expected no error from search, got: %v", err)
	}
}

func TestIAM001PromptContainsID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-001")
	if err != nil {
		t.Fatalf("Failed to use iam-001: %v", err)
	}

	prompt := r.BuildContextualPrompt()
	if !strings.Contains(prompt, "iam-001") {
		t.Errorf("Expected prompt to contain 'iam-001', got: %q", prompt)
	}
}

// iam-002 integration tests

func TestUseIAM002ByID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-002")
	if err != nil {
		t.Fatalf("Expected no error using iam-002, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "iam-002" {
		t.Errorf("Expected module name %q, got %q", "iam-002", mod.Name())
	}
}

func TestUseIAM002ByAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-createaccesskey")
	if err != nil {
		t.Fatalf("Expected no error using iam-createaccesskey, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "iam-002" {
		t.Errorf("Expected module name %q, got %q", "iam-002", mod.Name())
	}
}

func TestShowInfoIAM002(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-002")
	if err != nil {
		t.Fatalf("Failed to use iam-002: %v", err)
	}

	err = r.ExecuteCommand("show info")
	if err != nil {
		t.Errorf("Expected no error from show info for iam-002, got: %v", err)
	}
}

func TestIAM002ShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-002")
	if err != nil {
		t.Fatalf("Failed to use iam-002: %v", err)
	}

	err = r.ExecuteCommand("show options")
	if err != nil {
		t.Errorf("Expected no error from show options for iam-002, got: %v", err)
	}
}

// iam-003 integration tests

func TestUseIAM003ByID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-003")
	if err != nil {
		t.Fatalf("Expected no error using iam-003, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "iam-003" {
		t.Errorf("Expected module name %q, got %q", "iam-003", mod.Name())
	}
}

func TestUseIAM003ByAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-deleteaccesskey-createaccesskey")
	if err != nil {
		t.Fatalf("Expected no error using iam-deleteaccesskey-createaccesskey, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "iam-003" {
		t.Errorf("Expected module name %q, got %q", "iam-003", mod.Name())
	}
}

func TestShowInfoIAM003(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-003")
	if err != nil {
		t.Fatalf("Failed to use iam-003: %v", err)
	}

	err = r.ExecuteCommand("show info")
	if err != nil {
		t.Errorf("Expected no error from show info for iam-003, got: %v", err)
	}
}

func TestIAM003ShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-003")
	if err != nil {
		t.Fatalf("Failed to use iam-003: %v", err)
	}

	err = r.ExecuteCommand("show options")
	if err != nil {
		t.Errorf("Expected no error from show options for iam-003, got: %v", err)
	}
}

// iam-004 integration tests

func TestUseIAM004ByID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-004")
	if err != nil {
		t.Fatalf("Expected no error using iam-004, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "iam-004" {
		t.Errorf("Expected module name %q, got %q", "iam-004", mod.Name())
	}
}

func TestUseIAM004ByAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-createloginprofile")
	if err != nil {
		t.Fatalf("Expected no error using iam-createloginprofile, got: %v", err)
	}

	mod := r.GetCurrentModule()
	if mod == nil {
		t.Fatal("Expected current module to be set")
	}
	if mod.Name() != "iam-004" {
		t.Errorf("Expected module name %q, got %q", "iam-004", mod.Name())
	}
}

func TestShowInfoIAM004(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-004")
	if err != nil {
		t.Fatalf("Failed to use iam-004: %v", err)
	}

	err = r.ExecuteCommand("show info")
	if err != nil {
		t.Errorf("Expected no error from show info for iam-004, got: %v", err)
	}
}

func TestIAM004ShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use iam-004")
	if err != nil {
		t.Fatalf("Failed to use iam-004: %v", err)
	}

	err = r.ExecuteCommand("show options")
	if err != nil {
		t.Errorf("Expected no error from show options for iam-004, got: %v", err)
	}
}

func TestSearchPrincipalAccessFindsIAMModules(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("search principal-access")
	if err != nil {
		t.Errorf("Expected no error from search, got: %v", err)
	}
}
