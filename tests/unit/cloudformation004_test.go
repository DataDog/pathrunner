package unit

import (
	cfn004 "pathrunner/pkg/exploits/cloudformation_updatestackset"
	"pathrunner/pkg/modules"
	"testing"
)

func TestCloudformation004ModuleInit(t *testing.T) {
	mod := cfn004.NewModule()

	if mod.Name() != "cloudformation-004" {
		t.Errorf("Expected name 'cloudformation-004', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "cloudformation-004" {
		t.Errorf("Expected ID 'cloudformation-004', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestCloudformation004Description(t *testing.T) {
	mod := cfn004.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestCloudformation004Services(t *testing.T) {
	mod := cfn004.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "cloudformation": true}
	for _, svc := range pathInfo.Services {
		if !expectedServices[svc] {
			t.Errorf("Unexpected service: %s", svc)
		}
		delete(expectedServices, svc)
	}
	for svc := range expectedServices {
		t.Errorf("Missing expected service: %s", svc)
	}
}

func TestCloudformation004Options(t *testing.T) {
	mod := cfn004.NewModule()
	options := mod.Options()

	requiredOptions := map[string]bool{}
	optionalOptions := map[string]bool{}

	for _, opt := range options {
		if opt.Required {
			requiredOptions[opt.Name] = true
		} else {
			optionalOptions[opt.Name] = true
		}
	}

	if !requiredOptions["STACKSET_NAME"] {
		t.Error("Expected STACKSET_NAME to be required")
	}

	expectedOptional := []string{"ADMIN_ROLE_ARN", "EXECUTION_ROLE_NAME", "ESCALATED_ROLE_NAME", "TRUST_PRINCIPAL", "REGION", "ASSUME_ROLE", "AUTO_SWITCH", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestCloudformation004CleanupDefaultsToFalse(t *testing.T) {
	mod := cfn004.NewModule()
	options := mod.Options()

	for _, opt := range options {
		if opt.Name == "CLEANUP" {
			if opt.Default != "false" {
				t.Errorf("Expected CLEANUP default to be 'false', got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("CLEANUP option not found")
}

func TestCloudformation004Permissions(t *testing.T) {
	mod := cfn004.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "cloudformation:UpdateStackSet"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestCloudformation004Aliases(t *testing.T) {
	mod := cfn004.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}
}

func TestCloudformation004DiscoverableOptions(t *testing.T) {
	mod := cfn004.NewModule()

	discoverable, ok := any(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	optionSet := map[string]bool{}
	for _, opt := range options {
		optionSet[opt] = true
	}

	if !optionSet["STACKSET_NAME"] {
		t.Error("Expected STACKSET_NAME in discoverable options")
	}
}

func TestCloudformation004Registration(t *testing.T) {
	mod, err := modules.LoadModule("cloudformation-004")
	if err != nil {
		t.Fatalf("Expected module 'cloudformation-004' to be registered: %v", err)
	}
	if mod.Name() != "cloudformation-004" {
		t.Errorf("Expected name 'cloudformation-004', got '%s'", mod.Name())
	}
}

func TestCloudformation004AliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("cfn-004")
	if err != nil {
		t.Fatalf("Expected module to be loadable via alias 'cfn-004': %v", err)
	}
	if mod.Name() != "cloudformation-004" {
		t.Errorf("Expected name 'cloudformation-004', got '%s'", mod.Name())
	}
}

func TestCloudformation004MITRE(t *testing.T) {
	mod := cfn004.NewModule()
	pathInfo := mod.PathInfo()

	if pathInfo.MITRE == nil {
		t.Fatal("Expected MITRE mapping to be set")
	}

	if len(pathInfo.MITRE.Tactics) == 0 {
		t.Error("Expected at least one MITRE tactic")
	}
	if len(pathInfo.MITRE.Techniques) == 0 {
		t.Error("Expected at least one MITRE technique")
	}
}

func TestCloudformation004References(t *testing.T) {
	mod := cfn004.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/cloudformation-004") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for cloudformation-004")
	}
}

func TestCloudformation004ExecuteMissingStackSetName(t *testing.T) {
	mod := cfn004.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			// STACKSET_NAME intentionally omitted
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when STACKSET_NAME is missing")
	}
	if err != nil && !contains(err.Error(), "STACKSET_NAME") {
		t.Errorf("Expected error mentioning STACKSET_NAME, got: %v", err)
	}
}

func TestCloudformation004PrerequisitesSet(t *testing.T) {
	mod := cfn004.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected admin prerequisites to be set")
	}
	if len(pathInfo.Prerequisites.Lateral) == 0 {
		t.Error("Expected lateral prerequisites to be set")
	}
}

func TestCloudformation004RelatedPaths(t *testing.T) {
	mod := cfn004.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.RelatedPaths) == 0 {
		t.Error("Expected related paths to be set")
	}

	hasCloudformation := false
	for _, path := range pathInfo.RelatedPaths {
		if contains(path, "cloudformation") {
			hasCloudformation = true
		}
	}
	if !hasCloudformation {
		t.Error("Expected at least one related cloudformation path")
	}
}
