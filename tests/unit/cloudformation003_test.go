package unit

import (
	cfn003 "pathrunner/pkg/exploits/cloudformation_passrole_createstackset_createstackinstances"
	"pathrunner/pkg/modules"
	"testing"
)

func TestCloudformation003ModuleInit(t *testing.T) {
	mod := cfn003.NewModule()

	if mod.Name() != "cloudformation-003" {
		t.Errorf("Expected name 'cloudformation-003', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "cloudformation-003" {
		t.Errorf("Expected ID 'cloudformation-003', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestCloudformation003Description(t *testing.T) {
	mod := cfn003.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestCloudformation003Services(t *testing.T) {
	mod := cfn003.NewModule()
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

func TestCloudformation003Options(t *testing.T) {
	mod := cfn003.NewModule()
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

	if !requiredOptions["EXECUTION_ROLE_NAME"] {
		t.Error("Expected EXECUTION_ROLE_NAME to be required")
	}

	expectedOptional := []string{"ROLE_ARN", "STACKSET_NAME", "ESCALATED_ROLE_NAME", "TRUST_PRINCIPAL", "REGION", "ASSUME_ROLE", "AUTO_SWITCH", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestCloudformation003CleanupDefaultsToFalse(t *testing.T) {
	mod := cfn003.NewModule()
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

func TestCloudformation003Permissions(t *testing.T) {
	mod := cfn003.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "cloudformation:CreateStackSet", "cloudformation:CreateStackInstances"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestCloudformation003Aliases(t *testing.T) {
	mod := cfn003.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}
}

func TestCloudformation003DiscoverableOptions(t *testing.T) {
	mod := cfn003.NewModule()

	discoverable, ok := any(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	optionSet := map[string]bool{}
	for _, opt := range options {
		optionSet[opt] = true
	}

	if !optionSet["EXECUTION_ROLE_NAME"] {
		t.Error("Expected EXECUTION_ROLE_NAME in discoverable options")
	}
}

func TestCloudformation003Registration(t *testing.T) {
	mod, err := modules.LoadModule("cloudformation-003")
	if err != nil {
		t.Fatalf("Expected module 'cloudformation-003' to be registered: %v", err)
	}
	if mod.Name() != "cloudformation-003" {
		t.Errorf("Expected name 'cloudformation-003', got '%s'", mod.Name())
	}
}

func TestCloudformation003AliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("cfn-003")
	if err != nil {
		t.Fatalf("Expected module to be loadable via alias 'cfn-003': %v", err)
	}
	if mod.Name() != "cloudformation-003" {
		t.Errorf("Expected name 'cloudformation-003', got '%s'", mod.Name())
	}
}

func TestCloudformation003MITRE(t *testing.T) {
	mod := cfn003.NewModule()
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

func TestCloudformation003References(t *testing.T) {
	mod := cfn003.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/cloudformation-003") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for cloudformation-003")
	}
}

func TestCloudformation003ExecuteMissingExecutionRoleName(t *testing.T) {
	mod := cfn003.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			// EXECUTION_ROLE_NAME intentionally omitted
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when EXECUTION_ROLE_NAME is missing")
	}
	if err != nil && !contains(err.Error(), "EXECUTION_ROLE_NAME") {
		t.Errorf("Expected error mentioning EXECUTION_ROLE_NAME, got: %v", err)
	}
}

func TestCloudformation003PrerequisitesSet(t *testing.T) {
	mod := cfn003.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected admin prerequisites to be set")
	}
	if len(pathInfo.Prerequisites.Lateral) == 0 {
		t.Error("Expected lateral prerequisites to be set")
	}
}

func TestCloudformation003RelatedPaths(t *testing.T) {
	mod := cfn003.NewModule()
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
