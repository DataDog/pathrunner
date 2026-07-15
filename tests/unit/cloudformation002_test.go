package unit

import (
	cfn002 "pathrunner/pkg/exploits/cloudformation_updatestack"
	"pathrunner/pkg/modules"
	"testing"
)

func TestCloudformation002ModuleInit(t *testing.T) {
	mod := cfn002.NewModule()

	if mod.Name() != "cloudformation-002" {
		t.Errorf("Expected name 'cloudformation-002', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "cloudformation-002" {
		t.Errorf("Expected ID 'cloudformation-002', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestCloudformation002Description(t *testing.T) {
	mod := cfn002.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestCloudformation002Services(t *testing.T) {
	mod := cfn002.NewModule()
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

func TestCloudformation002Options(t *testing.T) {
	mod := cfn002.NewModule()
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

	if !requiredOptions["STACK_NAME"] {
		t.Error("Expected STACK_NAME to be required")
	}

	expectedOptional := []string{"ESCALATED_ROLE_NAME", "TRUST_PRINCIPAL", "REGION", "ASSUME_ROLE", "AUTO_SWITCH", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestCloudformation002CleanupDefaultsToFalse(t *testing.T) {
	mod := cfn002.NewModule()
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

func TestCloudformation002Permissions(t *testing.T) {
	mod := cfn002.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"cloudformation:UpdateStack"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestCloudformation002Aliases(t *testing.T) {
	mod := cfn002.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	hasShortAlias := false
	for _, alias := range pathInfo.Aliases {
		if alias == "cfn-002" {
			hasShortAlias = true
		}
	}
	if !hasShortAlias {
		t.Error("Expected 'cfn-002' short alias")
	}
}

func TestCloudformation002DiscoverableOptions(t *testing.T) {
	mod := cfn002.NewModule()

	discoverable, ok := any(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	optionSet := map[string]bool{}
	for _, opt := range options {
		optionSet[opt] = true
	}

	if !optionSet["STACK_NAME"] {
		t.Error("Expected STACK_NAME in discoverable options")
	}
}

func TestCloudformation002Registration(t *testing.T) {
	mod, err := modules.LoadModule("cloudformation-002")
	if err != nil {
		t.Fatalf("Expected module 'cloudformation-002' to be registered: %v", err)
	}
	if mod.Name() != "cloudformation-002" {
		t.Errorf("Expected name 'cloudformation-002', got '%s'", mod.Name())
	}
}

func TestCloudformation002AliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("cfn-002")
	if err != nil {
		t.Fatalf("Expected module to be loadable via alias 'cfn-002': %v", err)
	}
	if mod.Name() != "cloudformation-002" {
		t.Errorf("Expected name 'cloudformation-002', got '%s'", mod.Name())
	}
}

func TestCloudformation002MITRE(t *testing.T) {
	mod := cfn002.NewModule()
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

func TestCloudformation002References(t *testing.T) {
	mod := cfn002.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/cloudformation-002") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for cloudformation-002")
	}
}

func TestCloudformation002ExecuteMissingStackName(t *testing.T) {
	mod := cfn002.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			// STACK_NAME intentionally omitted
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when STACK_NAME is missing")
	}
	if err != nil && !contains(err.Error(), "STACK_NAME") {
		t.Errorf("Expected error mentioning STACK_NAME, got: %v", err)
	}
}

func TestCloudformation002PrerequisitesSet(t *testing.T) {
	mod := cfn002.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected admin prerequisites to be set")
	}
	if len(pathInfo.Prerequisites.Lateral) == 0 {
		t.Error("Expected lateral prerequisites to be set")
	}
}

func TestCloudformation002RelatedPaths(t *testing.T) {
	mod := cfn002.NewModule()
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
