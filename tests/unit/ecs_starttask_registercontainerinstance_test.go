package unit

import (
	"os"
	"pathrunner/pkg/exploits/ecs_starttask_registercontainerinstance"
	"pathrunner/pkg/modules"
	_ "pathrunner/pkg/payloads/ecs"
	"testing"
)

func TestECSStarttaskRegistercontainerinstanceModuleInit(t *testing.T) {
	mod := ecs_starttask_registercontainerinstance.NewModule()

	if mod.Name() != "ecs-007" {
		t.Errorf("Expected name 'ecs-007', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ecs-007" {
		t.Errorf("Expected ID 'ecs-007', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestECSStarttaskRegistercontainerinstanceDescription(t *testing.T) {
	mod := ecs_starttask_registercontainerinstance.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestECSStarttaskRegistercontainerinstanceServices(t *testing.T) {
	mod := ecs_starttask_registercontainerinstance.NewModule()
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

func TestECSStarttaskRegistercontainerinstanceOptions(t *testing.T) {
	mod := ecs_starttask_registercontainerinstance.NewModule()
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

	// These should be required
	expectedRequired := []string{"ROLE_ARN", "CLUSTER_NAME", "TASK_DEFINITION", "CONTAINER_INSTANCE_ARN", "CONTAINER_NAME", "PAYLOAD"}
	for _, name := range expectedRequired {
		if !requiredOptions[name] {
			t.Errorf("Expected %s to be required", name)
		}
	}

	// REGION should be optional
	if !optionalOptions["REGION"] {
		t.Error("Expected REGION to be optional")
	}
}

func TestECSStarttaskRegistercontainerinstancePermissions(t *testing.T) {
	mod := ecs_starttask_registercontainerinstance.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "ecs:RegisterContainerInstance", "ecs:StartTask"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestECSStarttaskRegistercontainerinstanceAliases(t *testing.T) {
	mod := ecs_starttask_registercontainerinstance.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["ecs-starttask-registercontainerinstance"] {
		t.Error("Expected alias 'ecs-starttask-registercontainerinstance'")
	}
}

func TestECSStarttaskRegistercontainerinstanceDiscoverableOptions(t *testing.T) {
	mod := ecs_starttask_registercontainerinstance.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	expectedDiscoverable := map[string]bool{
		"ROLE_ARN":               true,
		"CLUSTER_NAME":           true,
		"TASK_DEFINITION":        true,
		"CONTAINER_INSTANCE_ARN": true,
	}
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

func TestECSStarttaskRegistercontainerinstanceRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-007")
	if err != nil {
		t.Fatalf("Expected module 'ecs-007' to be registered: %v", err)
	}
	if mod.Name() != "ecs-007" {
		t.Errorf("Expected name 'ecs-007', got '%s'", mod.Name())
	}
}

func TestECSStarttaskRegistercontainerinstanceAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-starttask-registercontainerinstance")
	if err != nil {
		t.Fatalf("Expected alias 'ecs-starttask-registercontainerinstance' to be registered: %v", err)
	}
	if mod.Name() != "ecs-007" {
		t.Errorf("Expected name 'ecs-007' via alias, got '%s'", mod.Name())
	}
}

func TestECSStarttaskRegistercontainerinstancePayloadCompatible(t *testing.T) {
	mod := ecs_starttask_registercontainerinstance.NewModule()

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

func TestECSStarttaskRegistercontainerinstanceExecuteInvalidPayload(t *testing.T) {
	mod := ecs_starttask_registercontainerinstance.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN":               "arn:aws:iam::123456789012:role/admin",
			"CLUSTER_NAME":           "test-cluster",
			"TASK_DEFINITION":        "test-task-family",
			"CONTAINER_INSTANCE_ARN": "arn:aws:ecs:us-east-1:123456789012:container-instance/test-cluster/abc123",
			"CONTAINER_NAME":         "test-container",
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

func TestECSStarttaskRegistercontainerinstanceExecuteNoCredentials(t *testing.T) {
	// Use temp HOME to ensure no deploy state interferes
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	mod := ecs_starttask_registercontainerinstance.NewModule()

	// Execute with valid payload but no AWS credentials should fail at API call
	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN":               "arn:aws:iam::123456789012:role/admin",
			"CLUSTER_NAME":           "test-cluster",
			"TASK_DEFINITION":        "test-task-family",
			"CONTAINER_INSTANCE_ARN": "arn:aws:ecs:us-east-1:123456789012:container-instance/test-cluster/abc123",
			"CONTAINER_NAME":         "test-container",
			"PAYLOAD":                "backdoor/attach-policy",
			"TARGET_ARN":             "arn:aws:iam::123456789012:role/instance-role",
		},
		AttackerIdentity: nil,
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when executing without valid AWS credentials")
	}
}

func TestECSStarttaskRegistercontainerinstanceMITRE(t *testing.T) {
	mod := ecs_starttask_registercontainerinstance.NewModule()
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

func TestECSStarttaskRegistercontainerinstanceReferences(t *testing.T) {
	mod := ecs_starttask_registercontainerinstance.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/ecs-007") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference")
	}
}
