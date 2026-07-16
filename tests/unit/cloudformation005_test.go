package unit

import (
	cfn005 "github.com/DataDog/pathrunner/pkg/exploits/cloudformation_createchangeset_executechangeset"
	"github.com/DataDog/pathrunner/pkg/modules"
	"testing"
)

func TestCloudformation005ModuleInit(t *testing.T) {
	mod := cfn005.NewModule()

	if mod.Name() != "cloudformation-005" {
		t.Errorf("Expected name 'cloudformation-005', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "cloudformation-005" {
		t.Errorf("Expected ID 'cloudformation-005', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestCloudformation005Description(t *testing.T) {
	mod := cfn005.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestCloudformation005Services(t *testing.T) {
	mod := cfn005.NewModule()
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

func TestCloudformation005Options(t *testing.T) {
	mod := cfn005.NewModule()
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

	expectedOptional := []string{"ESCALATED_ROLE_NAME", "CHANGESET_NAME", "TRUST_PRINCIPAL", "REGION", "ASSUME_ROLE", "AUTO_SWITCH", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestCloudformation005CleanupDefaultsToFalse(t *testing.T) {
	mod := cfn005.NewModule()
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

func TestCloudformation005Permissions(t *testing.T) {
	mod := cfn005.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestCloudformation005Aliases(t *testing.T) {
	mod := cfn005.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}
}

func TestCloudformation005DiscoverableOptions(t *testing.T) {
	mod := cfn005.NewModule()

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

func TestCloudformation005Registration(t *testing.T) {
	mod, err := modules.LoadModule("cloudformation-005")
	if err != nil {
		t.Fatalf("Expected module 'cloudformation-005' to be registered: %v", err)
	}
	if mod.Name() != "cloudformation-005" {
		t.Errorf("Expected name 'cloudformation-005', got '%s'", mod.Name())
	}
}

func TestCloudformation005AliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("cfn-005")
	if err != nil {
		t.Fatalf("Expected module to be loadable via alias 'cfn-005': %v", err)
	}
	if mod.Name() != "cloudformation-005" {
		t.Errorf("Expected name 'cloudformation-005', got '%s'", mod.Name())
	}
}

func TestCloudformation005MITRE(t *testing.T) {
	mod := cfn005.NewModule()
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

func TestCloudformation005References(t *testing.T) {
	mod := cfn005.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/cloudformation-005") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for cloudformation-005")
	}
}

func TestCloudformation005ExecuteMissingStackName(t *testing.T) {
	mod := cfn005.NewModule()

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

func TestCloudformation005PrerequisitesSet(t *testing.T) {
	mod := cfn005.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected admin prerequisites to be set")
	}
	if len(pathInfo.Prerequisites.Lateral) == 0 {
		t.Error("Expected lateral prerequisites to be set")
	}
}

func TestCloudformation005RelatedPaths(t *testing.T) {
	mod := cfn005.NewModule()
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
