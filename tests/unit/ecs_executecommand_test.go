// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/ecs_executecommand"
	"github.com/DataDog/pathrunner/pkg/modules"
	"testing"
)

func TestEcsExecutecommandModuleInit(t *testing.T) {
	mod := ecs_executecommand.NewModule()

	if mod.Name() != "ecs-006" {
		t.Errorf("Expected name 'ecs-006', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ecs-006" {
		t.Errorf("Expected ID 'ecs-006', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestEcsExecutecommandDescription(t *testing.T) {
	mod := ecs_executecommand.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestEcsExecutecommandServices(t *testing.T) {
	mod := ecs_executecommand.NewModule()
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

func TestEcsExecutecommandOptions(t *testing.T) {
	mod := ecs_executecommand.NewModule()
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

	// CLUSTER_NAME is required
	if !requiredOptions["CLUSTER_NAME"] {
		t.Error("Expected CLUSTER_NAME to be required")
	}

	// These should be optional
	expectedOptional := []string{"TASK_ARN", "CONTAINER_NAME", "REGION"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}

	// This module does not use payloads
	if requiredOptions["PAYLOAD"] {
		t.Error("ecs-006 should not have a PAYLOAD option (no payloads needed)")
	}
}

func TestEcsExecutecommandPermissions(t *testing.T) {
	mod := ecs_executecommand.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"ecs:ExecuteCommand", "ecs:DescribeTasks"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}

	// Should NOT have iam:PassRole since this is existing-passrole
	if requiredPerms["iam:PassRole"] {
		t.Error("ecs-006 should not require iam:PassRole (existing-passrole category)")
	}
}

func TestEcsExecutecommandAliases(t *testing.T) {
	mod := ecs_executecommand.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["ecs-executecommand"] {
		t.Error("Expected alias 'ecs-executecommand'")
	}
}

func TestEcsExecutecommandDiscoverableOptions(t *testing.T) {
	mod := ecs_executecommand.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	optionSet := map[string]bool{}
	for _, opt := range options {
		optionSet[opt] = true
	}

	if !optionSet["CLUSTER_NAME"] {
		t.Error("Expected CLUSTER_NAME in discoverable options")
	}
	if !optionSet["TASK_ARN"] {
		t.Error("Expected TASK_ARN in discoverable options")
	}
}

func TestEcsExecutecommandRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-006")
	if err != nil {
		t.Fatalf("Expected module 'ecs-006' to be registered: %v", err)
	}
	if mod.Name() != "ecs-006" {
		t.Errorf("Expected name 'ecs-006', got '%s'", mod.Name())
	}
}

func TestEcsExecutecommandAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ecs-executecommand")
	if err != nil {
		t.Fatalf("Expected alias 'ecs-executecommand' to be registered: %v", err)
	}
	if mod.Name() != "ecs-006" {
		t.Errorf("Expected name 'ecs-006' via alias, got '%s'", mod.Name())
	}
}

func TestEcsExecutecommandNoPayloads(t *testing.T) {
	mod := ecs_executecommand.NewModule()

	// This module does not use payloads -- it directly steals credentials
	payloadList := mod.ListPayloads()
	if len(payloadList) != 0 {
		t.Errorf("Expected no payloads for ecs-006 (credential theft module), got %d", len(payloadList))
	}
}

func TestEcsExecutecommandMITRE(t *testing.T) {
	mod := ecs_executecommand.NewModule()
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

	// Check for credential access tactic (unique to this module)
	hasCredAccess := false
	for _, tactic := range pathInfo.MITRE.Tactics {
		if contains(tactic, "Credential Access") {
			hasCredAccess = true
		}
	}
	if !hasCredAccess {
		t.Error("Expected MITRE tactics to include Credential Access")
	}
}

func TestEcsExecutecommandReferences(t *testing.T) {
	mod := ecs_executecommand.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/ecs-006") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference")
	}
}

func TestEcsExecutecommandPrerequisites(t *testing.T) {
	mod := ecs_executecommand.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected admin prerequisites")
	}
	if len(pathInfo.Prerequisites.Lateral) == 0 {
		t.Error("Expected lateral prerequisites")
	}
}

func TestEcsExecutecommandRelatedPaths(t *testing.T) {
	mod := ecs_executecommand.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.RelatedPaths) == 0 {
		t.Error("Expected related paths")
	}
}

func TestEcsExecutecommandExtractCredentialJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantJSON string
		wantOK   bool
	}{
		{
			name:     "clean JSON with RoleArn",
			input:    `{"RoleArn":"arn:aws:iam::123456789012:role/admin","AccessKeyId":"ASIA...","SecretAccessKey":"secret","Token":"token","Expiration":"2026-01-01T00:00:00Z"}`,
			wantJSON: `{"RoleArn":"arn:aws:iam::123456789012:role/admin","AccessKeyId":"ASIA...","SecretAccessKey":"secret","Token":"token","Expiration":"2026-01-01T00:00:00Z"}`,
			wantOK:   true,
		},
		{
			name:     "JSON embedded in SSM session output",
			input:    "Starting session...\n{\"RoleArn\":\"arn:aws:iam::123456789012:role/admin\",\"AccessKeyId\":\"ASIAXXX\",\"SecretAccessKey\":\"secret\",\"Token\":\"tok\",\"Expiration\":\"2026-01-01T00:00:00Z\"}\nExiting session...\n",
			wantJSON: `{"RoleArn":"arn:aws:iam::123456789012:role/admin","AccessKeyId":"ASIAXXX","SecretAccessKey":"secret","Token":"tok","Expiration":"2026-01-01T00:00:00Z"}`,
			wantOK:   true,
		},
		{
			name:     "JSON with AccessKeyId but no RoleArn prefix",
			input:    `some garbage {"AccessKeyId":"ASIAXXX","SecretAccessKey":"secret"} more garbage`,
			wantJSON: `{"AccessKeyId":"ASIAXXX","SecretAccessKey":"secret"}`,
			wantOK:   true,
		},
		{
			name:   "no JSON at all",
			input:  "just some text without any json",
			wantOK: false,
		},
		{
			name:   "empty input",
			input:  "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ecs_executecommand.ExtractCredentialJSON(tt.input)
			if tt.wantOK {
				if got == "" {
					t.Error("Expected credential JSON to be extracted, got empty string")
					return
				}
				if got != tt.wantJSON {
					t.Errorf("Expected JSON:\n  %s\nGot:\n  %s", tt.wantJSON, got)
				}
			} else {
				if got != "" {
					t.Errorf("Expected empty string, got: %s", got)
				}
			}
		})
	}
}
