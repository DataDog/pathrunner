package unit

import (
	"pathrunner/pkg/exploits/glue_passrole_createsession"
	"pathrunner/pkg/modules"
	"testing"
)

func TestGluePassroleCreatesessionModuleInit(t *testing.T) {
	mod := glue_passrole_createsession.NewModule()

	if mod.Name() != "glue-007" {
		t.Errorf("Expected name 'glue-007', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "glue-007" {
		t.Errorf("Expected ID 'glue-007', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestGluePassroleCreatesessionDescription(t *testing.T) {
	mod := glue_passrole_createsession.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestGluePassroleCreatesessionServices(t *testing.T) {
	mod := glue_passrole_createsession.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "glue": true}
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

func TestGluePassroleCreatesessionOptions(t *testing.T) {
	mod := glue_passrole_createsession.NewModule()
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
	expectedOptional := []string{"REGION", "SESSION_ID", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestGluePassroleCreatesessionCleanupDefaultsTrue(t *testing.T) {
	mod := glue_passrole_createsession.NewModule()

	for _, opt := range mod.Options() {
		if opt.Name == "CLEANUP" {
			if opt.Default != "true" {
				t.Errorf("Expected CLEANUP default to be 'true', got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("CLEANUP option not found")
}

func TestGluePassroleCreatesessionPermissions(t *testing.T) {
	mod := glue_passrole_createsession.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	if !requiredPerms["iam:PassRole"] {
		t.Error("Missing required permission: iam:PassRole")
	}
	if !requiredPerms["glue:CreateSession"] {
		t.Error("Missing required permission: glue:CreateSession")
	}
	if !requiredPerms["glue:RunStatement"] {
		t.Error("Missing required permission: glue:RunStatement")
	}
}

func TestGluePassroleCreatesessionAliases(t *testing.T) {
	mod := glue_passrole_createsession.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["glue-passrole-createsession"] {
		t.Error("Expected alias 'glue-passrole-createsession'")
	}
}

func TestGluePassroleCreatesessionDiscoverableOptions(t *testing.T) {
	mod := glue_passrole_createsession.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	discoverySet := map[string]bool{}
	for _, opt := range options {
		discoverySet[opt] = true
	}

	if !discoverySet["ROLE_ARN"] {
		t.Error("Expected ROLE_ARN to be discoverable")
	}
}

func TestGluePassroleCreatesessionRegistration(t *testing.T) {
	mod, err := modules.LoadModule("glue-007")
	if err != nil {
		t.Fatalf("Expected module 'glue-007' to be registered: %v", err)
	}
	if mod.Name() != "glue-007" {
		t.Errorf("Expected name 'glue-007', got '%s'", mod.Name())
	}
}

func TestGluePassroleCreatesessionAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("glue-passrole-createsession")
	if err != nil {
		t.Fatalf("Expected alias 'glue-passrole-createsession' to be registered: %v", err)
	}
	if mod.Name() != "glue-007" {
		t.Errorf("Expected name 'glue-007' via alias, got '%s'", mod.Name())
	}
}

func TestGluePassroleCreatesessionMITRE(t *testing.T) {
	mod := glue_passrole_createsession.NewModule()
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

func TestGluePassroleCreatesessionReferences(t *testing.T) {
	mod := glue_passrole_createsession.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if glueContains(ref.URL, "pathfinding.cloud/paths/glue-007") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for glue-007")
	}
}

func TestGluePassroleCreatesessionPayloadCompatible(t *testing.T) {
	mod := glue_passrole_createsession.NewModule()

	payloadCompatible, ok := interface{}(mod).(modules.PayloadCompatible)
	if !ok {
		t.Fatal("Expected module to implement PayloadCompatible interface")
	}

	tags := payloadCompatible.GetCompatibleTags()
	if len(tags) == 0 {
		t.Error("Expected at least one compatible tag")
	}
}

func TestGluePassroleCreatesessionRelatedPaths(t *testing.T) {
	mod := glue_passrole_createsession.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.RelatedPaths) == 0 {
		t.Error("Expected at least one related path")
	}

	relatedSet := map[string]bool{}
	for _, path := range pathInfo.RelatedPaths {
		relatedSet[path] = true
	}

	if !relatedSet["glue-003"] {
		t.Error("Expected glue-003 in related paths")
	}
}

func TestGluePassroleCreatesessionExecuteRequiresRoleARN(t *testing.T) {
	mod := glue_passrole_createsession.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"PAYLOAD": "backdoor/attach-policy",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when ROLE_ARN is missing")
	}
}

func TestGluePassroleCreatesessionExecuteRequiresPayload(t *testing.T) {
	mod := glue_passrole_createsession.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN": "arn:aws:iam::123456789012:role/admin-role",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when PAYLOAD is missing")
	}
}

// glueContains is a local helper for substring matching within glue-007 tests.
func glueContains(s, substr string) bool {
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
