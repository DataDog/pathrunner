package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/codebuild_passrole"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/codebuild"
	"testing"
)

func TestCodeBuildPassroleModuleInit(t *testing.T) {
	mod := codebuild_passrole.NewModule()

	if mod.Name() != "codebuild-001" {
		t.Errorf("Expected name 'codebuild-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "codebuild-001" {
		t.Errorf("Expected ID 'codebuild-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestCodeBuildPassroleDescription(t *testing.T) {
	mod := codebuild_passrole.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestCodeBuildPassroleServices(t *testing.T) {
	mod := codebuild_passrole.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "codebuild": true}
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

func TestCodeBuildPassroleOptions(t *testing.T) {
	mod := codebuild_passrole.NewModule()
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
	expectedOptional := []string{"TARGET_USER", "REGION", "PROJECT_NAME", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestCodeBuildPassrolePermissions(t *testing.T) {
	mod := codebuild_passrole.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestCodeBuildPassroleAliases(t *testing.T) {
	mod := codebuild_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["codebuild-passrole"] {
		t.Error("Expected alias 'codebuild-passrole'")
	}
}

func TestCodeBuildPassroleDiscoverableOptions(t *testing.T) {
	mod := codebuild_passrole.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	if len(options) != 1 || options[0] != "ROLE_ARN" {
		t.Errorf("Expected DiscoverableOptions to return ['ROLE_ARN'], got %v", options)
	}
}

func TestCodeBuildPassroleRegistration(t *testing.T) {
	// Module should be registered via init()
	mod, err := modules.LoadModule("codebuild-001")
	if err != nil {
		t.Fatalf("Expected module 'codebuild-001' to be registered: %v", err)
	}
	if mod.Name() != "codebuild-001" {
		t.Errorf("Expected name 'codebuild-001', got '%s'", mod.Name())
	}
}

func TestCodeBuildPassroleAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("codebuild-passrole")
	if err != nil {
		t.Fatalf("Expected alias 'codebuild-passrole' to be registered: %v", err)
	}
	if mod.Name() != "codebuild-001" {
		t.Errorf("Expected name 'codebuild-001' via alias, got '%s'", mod.Name())
	}
}

func TestCodeBuildPassrolePayloadCompatible(t *testing.T) {
	mod := codebuild_passrole.NewModule()

	// Module should list CodeBuild payloads from the registry
	payloadList := mod.ListPayloads()
	if len(payloadList) == 0 {
		t.Error("Expected at least one CodeBuild payload registered")
	}

	// Verify compatible tags
	compatible, ok := interface{}(mod).(modules.PayloadCompatible)
	if !ok {
		t.Fatal("Expected module to implement PayloadCompatible interface")
	}

	tags := compatible.GetCompatibleTags()
	hasCodeBuild := false
	for _, tag := range tags {
		if tag == "codebuild" {
			hasCodeBuild = true
		}
	}
	if !hasCodeBuild {
		t.Error("Expected compatible tags to include 'codebuild'")
	}

	ctx := compatible.GetPayloadContext()
	if ctx != "codebuild" {
		t.Errorf("Expected payload context 'codebuild', got '%s'", ctx)
	}
}

func TestCodeBuildPassroleExecuteInvalidPayload(t *testing.T) {
	mod := codebuild_passrole.NewModule()

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
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error with invalid payload type")
	}
	if err != nil && !containsCB(err.Error(), "unknown payload type") {
		t.Errorf("Expected error about unknown payload type, got: %v", err)
	}
}

func TestCodeBuildPassroleMITRE(t *testing.T) {
	mod := codebuild_passrole.NewModule()
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

func TestCodeBuildPassroleReferences(t *testing.T) {
	mod := codebuild_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if containsCB(ref.URL, "pathfinding.cloud/paths/codebuild-001") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for codebuild-001")
	}
}

func containsCB(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
