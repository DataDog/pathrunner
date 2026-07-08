package unit

import (
	"pathrunner/pkg/exploits/ecs_passrole_starttask"
	"pathrunner/pkg/modules"
	_ "pathrunner/pkg/payloads/ecs"
	"testing"
)

func TestEcsPassroleStarttaskModuleInit(t *testing.T) {
	mod := ecs_passrole_starttask.NewModule()

	if mod.Name() != "ecs-009" {
		t.Errorf("Expected name 'ecs-009', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ecs-009" {
		t.Errorf("Expected ID 'ecs-009', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestEcsPassroleStarttaskDescription(t *testing.T) {
	mod := ecs_passrole_starttask.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestEcsPassroleStarttaskServices(t *testing.T) {
	mod := ecs_passrole_starttask.NewModule()
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

func TestEcsPassroleStarttaskOptions(t *testing.T) {
	mod := ecs_passrole_starttask.NewModule()
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

	// These are all required for ecs-009
	expectedRequired := []string{"ROLE_ARN", "CLUSTER_NAME", "CONTAINER_INSTANCE_ARN", "TASK_DEFINITION", "CONTAINER_NAME", "PAYLOAD"}
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

func TestEcsPassroleStarttaskPermissions(t *testing.T) {
	mod := ecs_passrole_starttask.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "ecs:StartTask"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}

	// ecs-009 does NOT require ecs:RegisterTaskDefinition
	if requiredPerms["ecs:RegisterTaskDefinition"] {
		t.Error("ecs-009 should NOT require ecs:RegisterTaskDefinition")
	}
}

func TestEcsPassroleStarttaskAliases(t *testing.T) {
	mod := ecs_passrole_starttask.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["ecs-passrole-starttask"] {
		t.Error("Expected alias 'ecs-passrole-starttask'")
	}
	if !aliasSet["exploit/ecs_passrole_starttask"] {
		t.Error("Expected alias 'exploit/ecs_passrole_starttask'")
	}
}

func TestEcsPassroleStarttaskDiscoverableOptions(t *testing.T) {
	mod := ecs_passrole_starttask.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	expectedDiscoverable := map[string]bool{
		"ROLE_ARN":               true,
		"CLUSTER_NAME":           true,
		"CONTAINER_INSTANCE_ARN": true,
		"TASK_DEFINITION":        true,
	}

	for _, opt := range options {
		if !expectedDiscoverable[opt] {
			t.Errorf("Unexpected discoverable option: %s", opt)
		}
		delete(expectedDiscoverable, opt)
	}
	for opt := range expectedDiscoverable {
		t.Errorf("Missing discoverable option: %s", opt)
	}
}

func TestEcsPassroleStarttaskRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-009")
	if err != nil {
		t.Fatalf("Expected module 'ecs-009' to be registered: %v", err)
	}
	if mod.Name() != "ecs-009" {
		t.Errorf("Expected name 'ecs-009', got '%s'", mod.Name())
	}
}

func TestEcsPassroleStarttaskAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-passrole-starttask")
	if err != nil {
		t.Fatalf("Expected alias 'ecs-passrole-starttask' to be registered: %v", err)
	}
	if mod.Name() != "ecs-009" {
		t.Errorf("Expected name 'ecs-009' via alias, got '%s'", mod.Name())
	}
}

func TestEcsPassroleStarttaskPayloadCompatible(t *testing.T) {
	mod := ecs_passrole_starttask.NewModule()

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

func TestEcsPassroleStarttaskExecuteInvalidPayload(t *testing.T) {
	mod := ecs_passrole_starttask.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN":               "arn:aws:iam::123456789012:role/admin",
			"CLUSTER_NAME":           "test-cluster",
			"CONTAINER_INSTANCE_ARN": "arn:aws:ecs:us-east-1:123456789012:container-instance/test-cluster/abc123",
			"TASK_DEFINITION":        "test-task-family",
			"CONTAINER_NAME":         "test-container",
			"PAYLOAD":                "nonexistent/payload",
		},
		AttackerIdentity: nil,
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error with invalid payload type")
	}
	if err != nil && !containsStr(err.Error(), "unknown payload type") {
		t.Errorf("Expected error about unknown payload type, got: %v", err)
	}
}

func TestEcsPassroleStarttaskMITRE(t *testing.T) {
	mod := ecs_passrole_starttask.NewModule()
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

func TestEcsPassroleStarttaskReferences(t *testing.T) {
	mod := ecs_passrole_starttask.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if containsStr(ref.URL, "pathfinding.cloud/paths/ecs-009") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for ecs-009")
	}
}

func TestEcsPassroleStarttaskPrerequisites(t *testing.T) {
	mod := ecs_passrole_starttask.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected admin prerequisites")
	}
	if len(pathInfo.Prerequisites.Lateral) == 0 {
		t.Error("Expected lateral prerequisites")
	}

	// Should mention existing container instance requirement
	foundContainerInstanceReq := false
	for _, prereq := range pathInfo.Prerequisites.Admin {
		if containsStr(prereq, "container instance") {
			foundContainerInstanceReq = true
		}
	}
	if !foundContainerInstanceReq {
		t.Error("Expected admin prerequisites to mention existing container instance")
	}

	// Should mention existing task definition requirement
	foundTaskDefReq := false
	for _, prereq := range pathInfo.Prerequisites.Admin {
		if containsStr(prereq, "task definition") {
			foundTaskDefReq = true
		}
	}
	if !foundTaskDefReq {
		t.Error("Expected admin prerequisites to mention existing task definition")
	}
}

// containsStr checks if s contains substr.
func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
