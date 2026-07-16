package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/ecs_passrole_createcluster_createservice"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/ecs"
	"testing"
)

func TestECSPassroleCreateclusterCreateserviceModuleInit(t *testing.T) {
	mod := ecs_passrole_createcluster_createservice.NewModule()

	if mod.Name() != "ecs-001" {
		t.Errorf("Expected name 'ecs-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ecs-001" {
		t.Errorf("Expected ID 'ecs-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestECSPassroleCreateclusterCreateserviceDescription(t *testing.T) {
	mod := ecs_passrole_createcluster_createservice.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestECSPassroleCreateclusterCreateserviceServices(t *testing.T) {
	mod := ecs_passrole_createcluster_createservice.NewModule()
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

func TestECSPassroleCreateclusterCreateserviceOptions(t *testing.T) {
	mod := ecs_passrole_createcluster_createservice.NewModule()
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
	expectedOptional := []string{"REGION", "CLUSTER_NAME", "SUBNET_ID", "TASK_FAMILY", "SERVICE_NAME", "CONTAINER_IMAGE", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestECSPassroleCreateclusterCreateservicePermissions(t *testing.T) {
	mod := ecs_passrole_createcluster_createservice.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "ecs:CreateCluster", "ecs:RegisterTaskDefinition", "ecs:CreateService"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestECSPassroleCreateclusterCreateserviceAliases(t *testing.T) {
	mod := ecs_passrole_createcluster_createservice.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["ecs-passrole-createcluster-createservice"] {
		t.Error("Expected alias 'ecs-passrole-createcluster-createservice'")
	}
}

func TestECSPassroleCreateclusterCreateserviceDiscoverableOptions(t *testing.T) {
	mod := ecs_passrole_createcluster_createservice.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	if len(options) != 1 || options[0] != "ROLE_ARN" {
		t.Errorf("Expected DiscoverableOptions to return ['ROLE_ARN'], got %v", options)
	}
}

func TestECSPassroleCreateclusterCreateserviceRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-001")
	if err != nil {
		t.Fatalf("Expected module 'ecs-001' to be registered: %v", err)
	}
	if mod.Name() != "ecs-001" {
		t.Errorf("Expected name 'ecs-001', got '%s'", mod.Name())
	}
}

func TestECSPassroleCreateclusterCreateserviceAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-passrole-createcluster-createservice")
	if err != nil {
		t.Fatalf("Expected alias 'ecs-passrole-createcluster-createservice' to be registered: %v", err)
	}
	if mod.Name() != "ecs-001" {
		t.Errorf("Expected name 'ecs-001' via alias, got '%s'", mod.Name())
	}
}

func TestECSPassroleCreateclusterCreateservicePayloadCompatible(t *testing.T) {
	mod := ecs_passrole_createcluster_createservice.NewModule()

	payloadList := mod.ListPayloads()
	if len(payloadList) == 0 {
		t.Error("Expected at least one ECS payload registered")
	}

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

func TestECSPassroleCreateclusterCreateserviceExecuteInvalidPayload(t *testing.T) {
	mod := ecs_passrole_createcluster_createservice.NewModule()

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
	if err != nil && !containsSubstr(err.Error(), "unknown payload type") {
		t.Errorf("Expected error about unknown payload type, got: %v", err)
	}
}

func TestECSPassroleCreateclusterCreateserviceMITRE(t *testing.T) {
	mod := ecs_passrole_createcluster_createservice.NewModule()
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

func TestECSPassroleCreateclusterCreateserviceReferences(t *testing.T) {
	mod := ecs_passrole_createcluster_createservice.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if containsSubstr(ref.URL, "pathfinding.cloud/paths/ecs-001") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference")
	}
}

// containsSubstr avoids importing strings in this test file
func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
