package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/apprunner_passrole"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/apprunner"
	"testing"
)

func TestAppRunnerPassroleModuleInit(t *testing.T) {
	mod := apprunner_passrole.NewModule()

	if mod.Name() != "apprunner-001" {
		t.Errorf("Expected name 'apprunner-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "apprunner-001" {
		t.Errorf("Expected ID 'apprunner-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestAppRunnerPassroleDescription(t *testing.T) {
	mod := apprunner_passrole.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestAppRunnerPassroleServices(t *testing.T) {
	mod := apprunner_passrole.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "apprunner": true}
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

func TestAppRunnerPassroleOptions(t *testing.T) {
	mod := apprunner_passrole.NewModule()
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

	// ROLE_ARN and PAYLOAD are required
	if !requiredOptions["ROLE_ARN"] {
		t.Error("Expected ROLE_ARN to be required")
	}
	if !requiredOptions["PAYLOAD"] {
		t.Error("Expected PAYLOAD to be required")
	}

	// These should be optional
	expectedOptional := []string{"REGION", "SERVICE_NAME", "CONTAINER_IMAGE", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestAppRunnerPassroleCleanupDefaultFalse(t *testing.T) {
	mod := apprunner_passrole.NewModule()

	for _, opt := range mod.Options() {
		if opt.Name == "CLEANUP" {
			if opt.Default != "false" {
				t.Errorf("Expected CLEANUP default to be 'false' (starting user lacks apprunner:DeleteService), got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("CLEANUP option not found")
}

func TestAppRunnerPassrolePermissions(t *testing.T) {
	mod := apprunner_passrole.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "apprunner:CreateService"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestAppRunnerPassroleAliases(t *testing.T) {
	mod := apprunner_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["apprunner-passrole"] {
		t.Error("Expected alias 'apprunner-passrole'")
	}
}

func TestAppRunnerPassroleDiscoverableOptions(t *testing.T) {
	mod := apprunner_passrole.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	optionSet := map[string]bool{}
	for _, opt := range options {
		optionSet[opt] = true
	}

	if !optionSet["ROLE_ARN"] {
		t.Error("Expected ROLE_ARN in discoverable options")
	}
}

func TestAppRunnerPassroleRegistration(t *testing.T) {
	mod, err := modules.LoadModule("apprunner-001")
	if err != nil {
		t.Fatalf("Expected module 'apprunner-001' to be registered: %v", err)
	}
	if mod.Name() != "apprunner-001" {
		t.Errorf("Expected name 'apprunner-001', got '%s'", mod.Name())
	}
}

func TestAppRunnerPassroleAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("apprunner-passrole")
	if err != nil {
		t.Fatalf("Expected alias 'apprunner-passrole' to be registered: %v", err)
	}
	if mod.Name() != "apprunner-001" {
		t.Errorf("Expected name 'apprunner-001' via alias, got '%s'", mod.Name())
	}
}

func TestAppRunnerPassrolePayloadCompatible(t *testing.T) {
	mod := apprunner_passrole.NewModule()

	// Module should list apprunner payloads from the registry
	payloadList := mod.ListPayloads()
	if len(payloadList) == 0 {
		t.Error("Expected at least one apprunner payload registered")
	}

	// Verify compatible tags
	compatible, ok := interface{}(mod).(modules.PayloadCompatible)
	if !ok {
		t.Fatal("Expected module to implement PayloadCompatible interface")
	}

	tags := compatible.GetCompatibleTags()
	hasAppRunner := false
	for _, tag := range tags {
		if tag == "apprunner" {
			hasAppRunner = true
		}
	}
	if !hasAppRunner {
		t.Error("Expected compatible tags to include 'apprunner'")
	}

	ctx := compatible.GetPayloadContext()
	if ctx != "apprunner" {
		t.Errorf("Expected payload context 'apprunner', got '%s'", ctx)
	}
}

func TestAppRunnerPassroleExecuteInvalidPayload(t *testing.T) {
	mod := apprunner_passrole.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN": "arn:aws:iam::123456789012:role/admin",
			"PAYLOAD":  "nonexistent/payload",
		},
		AttackerIdentity: nil,
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error with invalid payload type")
	}
	if err != nil && !contains(err.Error(), "unknown payload type") {
		t.Errorf("Expected error about unknown payload type, got: %v", err)
	}
}

func TestAppRunnerPassroleMITRE(t *testing.T) {
	mod := apprunner_passrole.NewModule()
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

func TestAppRunnerPassroleReferences(t *testing.T) {
	mod := apprunner_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/apprunner-001") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference")
	}
}
