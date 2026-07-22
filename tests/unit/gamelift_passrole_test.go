// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/gamelift_passrole"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/gamelift"
	"testing"
)

func TestGameLiftPassRoleModuleInit(t *testing.T) {
	mod := gamelift_passrole.NewModule()

	if mod.Name() != "gamelift-001" {
		t.Errorf("Expected name 'gamelift-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "gamelift-001" {
		t.Errorf("Expected ID 'gamelift-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestGameLiftPassRoleDescription(t *testing.T) {
	mod := gamelift_passrole.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestGameLiftPassRoleServices(t *testing.T) {
	mod := gamelift_passrole.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "gamelift": true}
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

func TestGameLiftPassRoleOptions(t *testing.T) {
	mod := gamelift_passrole.NewModule()
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
	expectedOptional := []string{"TARGET_USER", "REGION", "BUILD_NAME", "FLEET_NAME", "INSTANCE_TYPE", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestGameLiftPassRoleCleanupDefaultsFalse(t *testing.T) {
	mod := gamelift_passrole.NewModule()

	for _, opt := range mod.Options() {
		if opt.Name == "CLEANUP" {
			if opt.Default != "false" {
				t.Errorf("Expected CLEANUP default to be 'false', got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("CLEANUP option not found")
}

func TestGameLiftPassRolePermissions(t *testing.T) {
	mod := gamelift_passrole.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "gamelift:CreateBuild", "gamelift:CreateFleet", "gamelift:RequestUploadCredentials"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestGameLiftPassRoleAliases(t *testing.T) {
	mod := gamelift_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["gamelift-passrole"] {
		t.Error("Expected alias 'gamelift-passrole'")
	}
}

func TestGameLiftPassRoleDiscoverableOptions(t *testing.T) {
	mod := gamelift_passrole.NewModule()

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

func TestGameLiftPassRoleRegistration(t *testing.T) {
	// Module should be registered via init()
	mod, err := modules.LoadModule("gamelift-001")
	if err != nil {
		t.Fatalf("Expected module 'gamelift-001' to be registered: %v", err)
	}
	if mod.Name() != "gamelift-001" {
		t.Errorf("Expected name 'gamelift-001', got '%s'", mod.Name())
	}
}

func TestGameLiftPassRoleAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("gamelift-passrole")
	if err != nil {
		t.Fatalf("Expected alias 'gamelift-passrole' to be registered: %v", err)
	}
	if mod.Name() != "gamelift-001" {
		t.Errorf("Expected name 'gamelift-001' via alias, got '%s'", mod.Name())
	}
}

func TestGameLiftPassRoleMITRE(t *testing.T) {
	mod := gamelift_passrole.NewModule()
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

func TestGameLiftPassRoleReferences(t *testing.T) {
	mod := gamelift_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if containsGameLift(ref.URL, "pathfinding.cloud/paths/gamelift-001") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for gamelift-001")
	}
}

func TestGameLiftPassRolePayloadCompatible(t *testing.T) {
	mod := gamelift_passrole.NewModule()

	payloadCompatible, ok := interface{}(mod).(modules.PayloadCompatible)
	if !ok {
		t.Fatal("Expected module to implement PayloadCompatible interface")
	}

	compatibleTags := payloadCompatible.GetCompatibleTags()
	if len(compatibleTags) == 0 {
		t.Error("Expected non-empty compatible tags")
	}

	context := payloadCompatible.GetPayloadContext()
	if context == "" {
		t.Error("Expected non-empty payload context")
	}
}

func TestGameLiftPassRoleExecuteRequiresIdentity(t *testing.T) {
	mod := gamelift_passrole.NewModule()

	ectx := modules.ExecutionContext{
		Identity: nil,
		Options: map[string]string{
			"ROLE_ARN":    "arn:aws:iam::123456789012:role/AdminRole",
			"PAYLOAD":     "backdoor/attach-policy",
			"TARGET_USER": "test-user",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when identity is nil")
	}
}

func containsGameLift(s, substr string) bool {
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
