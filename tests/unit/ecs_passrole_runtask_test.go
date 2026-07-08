package unit

import (
	"pathrunner/pkg/exploits/ecs_passrole_runtask"
	"pathrunner/pkg/modules"
	_ "pathrunner/pkg/payloads/ecs"
	"testing"
)

func TestEcsPassroleRuntaskModuleInit(t *testing.T) {
	mod := ecs_passrole_runtask.NewModule()

	if mod.Name() != "ecs-008" {
		t.Errorf("Expected name 'ecs-008', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ecs-008" {
		t.Errorf("Expected ID 'ecs-008', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestEcsPassroleRuntaskDescription(t *testing.T) {
	mod := ecs_passrole_runtask.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestEcsPassroleRuntaskServices(t *testing.T) {
	mod := ecs_passrole_runtask.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "ecs": true}
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

func TestEcsPassroleRuntaskOptions(t *testing.T) {
	mod := ecs_passrole_runtask.NewModule()
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

	// ROLE_ARN, CLUSTER_NAME, TASK_DEFINITION, and PAYLOAD are required
	if !requiredOptions["ROLE_ARN"] {
		t.Error("Expected ROLE_ARN to be required")
	}
	if !requiredOptions["CLUSTER_NAME"] {
		t.Error("Expected CLUSTER_NAME to be required")
	}
	if !requiredOptions["TASK_DEFINITION"] {
		t.Error("Expected TASK_DEFINITION to be required")
	}
	if !requiredOptions["PAYLOAD"] {
		t.Error("Expected PAYLOAD to be required")
	}

	// These should be optional
	expectedOptional := []string{"REGION", "SUBNET_ID", "CONTAINER_NAME"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestEcsPassroleRuntaskPermissions(t *testing.T) {
	mod := ecs_passrole_runtask.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	// ECS-008 does NOT require ecs:RegisterTaskDefinition — that is the key difference from ECS-004
	expectedPerms := []string{"iam:PassRole", "ecs:RunTask"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}

	if requiredPerms["ecs:RegisterTaskDefinition"] {
		t.Error("ECS-008 should NOT require ecs:RegisterTaskDefinition")
	}
}

func TestEcsPassroleRuntaskAliases(t *testing.T) {
	mod := ecs_passrole_runtask.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["ecs-passrole-runtask"] {
		t.Error("Expected alias 'ecs-passrole-runtask'")
	}
}

func TestEcsPassroleRuntaskDiscoverableOptions(t *testing.T) {
	mod := ecs_passrole_runtask.NewModule()

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
	if !optionSet["CLUSTER_NAME"] {
		t.Error("Expected CLUSTER_NAME in discoverable options")
	}
	if !optionSet["TASK_DEFINITION"] {
		t.Error("Expected TASK_DEFINITION in discoverable options")
	}
}

func TestEcsPassroleRuntaskRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-008")
	if err != nil {
		t.Fatalf("Expected module 'ecs-008' to be registered: %v", err)
	}
	if mod.Name() != "ecs-008" {
		t.Errorf("Expected name 'ecs-008', got '%s'", mod.Name())
	}
}

func TestEcsPassroleRuntaskAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-passrole-runtask")
	if err != nil {
		t.Fatalf("Expected alias 'ecs-passrole-runtask' to be registered: %v", err)
	}
	if mod.Name() != "ecs-008" {
		t.Errorf("Expected name 'ecs-008' via alias, got '%s'", mod.Name())
	}
}

func TestEcsPassroleRuntaskPayloadCompatible(t *testing.T) {
	mod := ecs_passrole_runtask.NewModule()

	// Module should list ECS payloads from the registry
	payloadList := mod.ListPayloads()
	if len(payloadList) == 0 {
		t.Error("Expected at least one ECS payload registered")
	}

	// Verify compatible tags
	compatible, ok := interface{}(mod).(modules.PayloadCompatible)
	if !ok {
		t.Fatal("Expected module to implement PayloadCompatible interface")
	}

	tags := compatible.GetCompatibleTags()
	hasECS := false
	for _, tag := range tags {
		if tag == "ecs" {
			hasECS = true
		}
	}
	if !hasECS {
		t.Error("Expected compatible tags to include 'ecs'")
	}

	ctx := compatible.GetPayloadContext()
	if ctx != "ecs" {
		t.Errorf("Expected payload context 'ecs', got '%s'", ctx)
	}
}

func TestEcsPassroleRuntaskExecuteInvalidPayload(t *testing.T) {
	mod := ecs_passrole_runtask.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN":        "arn:aws:iam::123456789012:role/admin",
			"CLUSTER_NAME":    "test-cluster",
			"TASK_DEFINITION": "my-task-family:1",
			"PAYLOAD":         "nonexistent/payload",
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

func TestEcsPassroleRuntaskMITRE(t *testing.T) {
	mod := ecs_passrole_runtask.NewModule()
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

func TestEcsPassroleRuntaskReferences(t *testing.T) {
	mod := ecs_passrole_runtask.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/ecs-008") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference")
	}
}
