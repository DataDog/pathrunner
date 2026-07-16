package unit

import (
	ecs005 "github.com/DataDog/pathrunner/pkg/exploits/ecs_registertaskdefinition_runtask"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/ecs"
	"testing"
)

func TestEcs005ModuleInit(t *testing.T) {
	mod := ecs005.NewModule()

	if mod.Name() != "ecs-005" {
		t.Errorf("Expected name 'ecs-005', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ecs-005" {
		t.Errorf("Expected ID 'ecs-005', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestEcs005Description(t *testing.T) {
	mod := ecs005.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestEcs005Services(t *testing.T) {
	mod := ecs005.NewModule()
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

func TestEcs005Options(t *testing.T) {
	mod := ecs005.NewModule()
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

	if !requiredOptions["ROLE_ARN"] {
		t.Error("Expected ROLE_ARN to be required")
	}
	if !requiredOptions["CLUSTER_NAME"] {
		t.Error("Expected CLUSTER_NAME to be required")
	}
	if !requiredOptions["CONTAINER_INSTANCE_ARN"] {
		t.Error("Expected CONTAINER_INSTANCE_ARN to be required")
	}
	if !requiredOptions["PAYLOAD"] {
		t.Error("Expected PAYLOAD to be required")
	}

	expectedOptional := []string{"REGION", "TASK_FAMILY", "CONTAINER_IMAGE", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestEcs005Permissions(t *testing.T) {
	mod := ecs005.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:StartTask"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestEcs005Aliases(t *testing.T) {
	mod := ecs005.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}
}

func TestEcs005DiscoverableOptions(t *testing.T) {
	mod := ecs005.NewModule()

	discoverable, ok := any(mod).(modules.Discoverable)
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
	if !optionSet["CONTAINER_INSTANCE_ARN"] {
		t.Error("Expected CONTAINER_INSTANCE_ARN in discoverable options")
	}
}

func TestEcs005Registration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-005")
	if err != nil {
		t.Fatalf("Expected module 'ecs-005' to be registered: %v", err)
	}
	if mod.Name() != "ecs-005" {
		t.Errorf("Expected name 'ecs-005', got '%s'", mod.Name())
	}
}

func TestEcs005PayloadCompatible(t *testing.T) {
	mod := ecs005.NewModule()

	payloadList := mod.ListPayloads()
	if len(payloadList) == 0 {
		t.Error("Expected at least one ECS payload registered")
	}

	compatible, ok := any(mod).(modules.PayloadCompatible)
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

func TestEcs005ExecuteInvalidPayload(t *testing.T) {
	mod := ecs005.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN":               "arn:aws:iam::123456789012:role/admin",
			"CLUSTER_NAME":           "test-cluster",
			"CONTAINER_INSTANCE_ARN": "arn:aws:ecs:us-east-1:123456789012:container-instance/test",
			"PAYLOAD":                "nonexistent/payload",
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

func TestEcs005MITRE(t *testing.T) {
	mod := ecs005.NewModule()
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

func TestEcs005References(t *testing.T) {
	mod := ecs005.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/ecs-005") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference")
	}
}
