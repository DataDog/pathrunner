package unit

import (
	"os"
	"github.com/DataDog/pathrunner/pkg/exploits/ecs_passrole_createservice"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/ecs"
	"testing"
)

func TestECSPassroleCreateserviceModuleInit(t *testing.T) {
	mod := ecs_passrole_createservice.NewModule()

	if mod.Name() != "ecs-003" {
		t.Errorf("Expected name 'ecs-003', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ecs-003" {
		t.Errorf("Expected ID 'ecs-003', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestECSPassroleCreateserviceDescription(t *testing.T) {
	mod := ecs_passrole_createservice.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestECSPassroleCreateserviceServices(t *testing.T) {
	mod := ecs_passrole_createservice.NewModule()
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

func TestECSPassroleCreateserviceOptions(t *testing.T) {
	mod := ecs_passrole_createservice.NewModule()
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

	// ROLE_ARN, CLUSTER_ARN, and PAYLOAD are required
	if !requiredOptions["ROLE_ARN"] {
		t.Error("Expected ROLE_ARN to be required")
	}
	if !requiredOptions["CLUSTER_ARN"] {
		t.Error("Expected CLUSTER_ARN to be required")
	}
	if !requiredOptions["PAYLOAD"] {
		t.Error("Expected PAYLOAD to be required")
	}

	// These should be optional
	expectedOptional := []string{"REGION", "SUBNET_ID", "TASK_FAMILY", "SERVICE_NAME", "CONTAINER_IMAGE", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestECSPassroleCreateservicePermissions(t *testing.T) {
	mod := ecs_passrole_createservice.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:CreateService"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestECSPassroleCreateserviceAliases(t *testing.T) {
	mod := ecs_passrole_createservice.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["ecs-passrole-createservice"] {
		t.Error("Expected alias 'ecs-passrole-createservice'")
	}
}

func TestECSPassroleCreateserviceDiscoverableOptions(t *testing.T) {
	mod := ecs_passrole_createservice.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	expectedDiscoverable := map[string]bool{"ROLE_ARN": true, "CLUSTER_ARN": true}
	for _, opt := range options {
		if !expectedDiscoverable[opt] {
			t.Errorf("Unexpected discoverable option: %s", opt)
		}
		delete(expectedDiscoverable, opt)
	}
	for opt := range expectedDiscoverable {
		t.Errorf("Missing expected discoverable option: %s", opt)
	}
}

func TestECSPassroleCreateserviceRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-003")
	if err != nil {
		t.Fatalf("Expected module 'ecs-003' to be registered: %v", err)
	}
	if mod.Name() != "ecs-003" {
		t.Errorf("Expected name 'ecs-003', got '%s'", mod.Name())
	}
}

func TestECSPassroleCreateserviceAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-passrole-createservice")
	if err != nil {
		t.Fatalf("Expected alias 'ecs-passrole-createservice' to be registered: %v", err)
	}
	if mod.Name() != "ecs-003" {
		t.Errorf("Expected name 'ecs-003' via alias, got '%s'", mod.Name())
	}
}

func TestECSPassroleCreateservicePayloadCompatible(t *testing.T) {
	mod := ecs_passrole_createservice.NewModule()

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

func TestECSPassroleCreateserviceExecuteInvalidPayload(t *testing.T) {
	mod := ecs_passrole_createservice.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN":    "arn:aws:iam::123456789012:role/admin",
			"CLUSTER_ARN": "arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster",
			"PAYLOAD":     "nonexistent/payload",
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

func TestECSPassroleCreateserviceExecuteNoSubnet(t *testing.T) {
	// Use temp HOME to ensure no deploy state interferes
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	mod := ecs_passrole_createservice.NewModule()

	// Execute with valid payload but no AWS credentials should fail at subnet detection or API call
	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN":    "arn:aws:iam::123456789012:role/admin",
			"CLUSTER_ARN": "arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster",
			"PAYLOAD":     "backdoor/attach-policy",
			"TARGET_ARN":  "arn:aws:iam::123456789012:user/test-user",
		},
		AttackerIdentity: nil,
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when executing without valid AWS credentials")
	}
}

func TestECSPassroleCreateserviceMITRE(t *testing.T) {
	mod := ecs_passrole_createservice.NewModule()
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

func TestECSPassroleCreateserviceReferences(t *testing.T) {
	mod := ecs_passrole_createservice.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/ecs-003") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference")
	}
}
