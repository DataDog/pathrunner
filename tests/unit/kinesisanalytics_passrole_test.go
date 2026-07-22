// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/kinesisanalytics_passrole"
	"github.com/DataDog/pathrunner/pkg/modules"
	"testing"
)

func TestKinesisAnalyticsPassroleModuleInit(t *testing.T) {
	mod := kinesisanalytics_passrole.NewModule()

	if mod.Name() != "kinesisanalytics-001" {
		t.Errorf("Expected name 'kinesisanalytics-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "kinesisanalytics-001" {
		t.Errorf("Expected ID 'kinesisanalytics-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestKinesisAnalyticsPassroleDescription(t *testing.T) {
	mod := kinesisanalytics_passrole.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestKinesisAnalyticsPassroleServices(t *testing.T) {
	mod := kinesisanalytics_passrole.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "kinesisanalytics": true}
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

func TestKinesisAnalyticsPassroleOptions(t *testing.T) {
	mod := kinesisanalytics_passrole.NewModule()
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

	// ROLE_ARN, CODE_BUCKET, CODE_KEY are required
	for _, required := range []string{"ROLE_ARN", "CODE_BUCKET", "CODE_KEY"} {
		if !requiredOptions[required] {
			t.Errorf("Expected %s to be required", required)
		}
	}

	// These should be optional
	for _, optional := range []string{"TARGET_USER", "APP_NAME", "REGION", "CLEANUP"} {
		if !optionalOptions[optional] {
			t.Errorf("Expected %s to be optional", optional)
		}
	}

	// CLEANUP should default to false (starting user lacks delete permissions)
	for _, opt := range options {
		if opt.Name == "CLEANUP" && opt.Default != "false" {
			t.Errorf("Expected CLEANUP default to be 'false', got '%s'", opt.Default)
		}
	}
}

func TestKinesisAnalyticsPassrolePermissions(t *testing.T) {
	mod := kinesisanalytics_passrole.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "kinesisanalytics:CreateApplication", "kinesisanalytics:StartApplication"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestKinesisAnalyticsPassroleAliases(t *testing.T) {
	mod := kinesisanalytics_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["kinesisanalytics-passrole"] {
		t.Error("Expected alias 'kinesisanalytics-passrole'")
	}
}

func TestKinesisAnalyticsPassroleDiscoverableOptions(t *testing.T) {
	mod := kinesisanalytics_passrole.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	if len(options) != 1 || options[0] != "ROLE_ARN" {
		t.Errorf("Expected DiscoverableOptions to return ['ROLE_ARN'], got %v", options)
	}
}

func TestKinesisAnalyticsPassroleRegistration(t *testing.T) {
	mod, err := modules.LoadModule("kinesisanalytics-001")
	if err != nil {
		t.Fatalf("Expected module 'kinesisanalytics-001' to be registered: %v", err)
	}
	if mod.Name() != "kinesisanalytics-001" {
		t.Errorf("Expected name 'kinesisanalytics-001', got '%s'", mod.Name())
	}
}

func TestKinesisAnalyticsPassroleAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("kinesisanalytics-passrole")
	if err != nil {
		t.Fatalf("Expected alias 'kinesisanalytics-passrole' to be registered: %v", err)
	}
	if mod.Name() != "kinesisanalytics-001" {
		t.Errorf("Expected name 'kinesisanalytics-001' via alias, got '%s'", mod.Name())
	}
}

func TestKinesisAnalyticsPassroleMITRE(t *testing.T) {
	mod := kinesisanalytics_passrole.NewModule()
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

func TestKinesisAnalyticsPassroleReferences(t *testing.T) {
	mod := kinesisanalytics_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if containsKA(ref.URL, "pathfinding.cloud/paths/kinesisanalytics-001") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for kinesisanalytics-001")
	}
}

func TestKinesisAnalyticsPassroleExecuteMissingRoleARN(t *testing.T) {
	mod := kinesisanalytics_passrole.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"CODE_BUCKET": "my-attacker-bucket",
			"CODE_KEY":    "exploit/malicious-flink-app.jar",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when ROLE_ARN is not set")
	}
}

func TestKinesisAnalyticsPassroleDoesNotImplementPayloadCompatible(t *testing.T) {
	mod := kinesisanalytics_passrole.NewModule()

	// This module uses a pre-built JAR, not a generated payload — PayloadCompatible should NOT be implemented.
	_, ok := interface{}(mod).(modules.PayloadCompatible)
	if ok {
		t.Error("kinesisanalytics_passrole should NOT implement PayloadCompatible (JAR is pre-built, not generated)")
	}
}

// containsKA is a helper to avoid importing strings in test file.
func containsKA(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
