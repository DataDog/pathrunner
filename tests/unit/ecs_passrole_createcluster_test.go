package unit

import (
	"pathrunner/pkg/exploits/ecs_passrole_createcluster"
	"pathrunner/pkg/modules"
	_ "pathrunner/pkg/payloads/ecs"
	"testing"
)

func TestEcsPassroleCreateclusterModuleInit(t *testing.T) {
	mod := ecs_passrole_createcluster.NewModule()

	if mod.Name() != "ecs-002" {
		t.Errorf("Expected name 'ecs-002', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ecs-002" {
		t.Errorf("Expected ID 'ecs-002', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestEcsPassroleCreateclusterDescription(t *testing.T) {
	mod := ecs_passrole_createcluster.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestEcsPassroleCreateclusterServices(t *testing.T) {
	mod := ecs_passrole_createcluster.NewModule()
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

func TestEcsPassroleCreateclusterOptions(t *testing.T) {
	mod := ecs_passrole_createcluster.NewModule()
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

	// CLUSTER_NAME should be optional (module creates the cluster)
	if requiredOptions["CLUSTER_NAME"] {
		t.Error("Expected CLUSTER_NAME to be optional, not required")
	}
	if !optionalOptions["CLUSTER_NAME"] {
		t.Error("Expected CLUSTER_NAME to be optional")
	}

	// These should be optional
	expectedOptional := []string{"REGION", "SUBNET_ID", "TASK_FAMILY", "CONTAINER_IMAGE", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestEcsPassroleCreateclusterPermissions(t *testing.T) {
	mod := ecs_passrole_createcluster.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "ecs:CreateCluster", "ecs:RegisterTaskDefinition", "ecs:RunTask"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestEcsPassroleCreateclusterAliases(t *testing.T) {
	mod := ecs_passrole_createcluster.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["ecs-passrole-createcluster"] {
		t.Error("Expected alias 'ecs-passrole-createcluster'")
	}
}

func TestEcsPassroleCreateclusterDiscoverableOptions(t *testing.T) {
	mod := ecs_passrole_createcluster.NewModule()

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

	// CLUSTER_NAME should NOT be discoverable since we create our own
	if optionSet["CLUSTER_NAME"] {
		t.Error("CLUSTER_NAME should not be discoverable since this module creates its own cluster")
	}
}

func TestEcsPassroleCreateclusterRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-002")
	if err != nil {
		t.Fatalf("Expected module 'ecs-002' to be registered: %v", err)
	}
	if mod.Name() != "ecs-002" {
		t.Errorf("Expected name 'ecs-002', got '%s'", mod.Name())
	}
}

func TestEcsPassroleCreateclusterAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-passrole-createcluster")
	if err != nil {
		t.Fatalf("Expected alias 'ecs-passrole-createcluster' to be registered: %v", err)
	}
	if mod.Name() != "ecs-002" {
		t.Errorf("Expected name 'ecs-002' via alias, got '%s'", mod.Name())
	}
}

func TestEcsPassroleCreateclusterPayloadCompatible(t *testing.T) {
	mod := ecs_passrole_createcluster.NewModule()

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

func TestEcsPassroleCreateclusterExecuteInvalidPayload(t *testing.T) {
	mod := ecs_passrole_createcluster.NewModule()

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

func TestEcsPassroleCreateclusterMITRE(t *testing.T) {
	mod := ecs_passrole_createcluster.NewModule()
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

func TestEcsPassroleCreateclusterReferences(t *testing.T) {
	mod := ecs_passrole_createcluster.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/ecs-002") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference")
	}
}
