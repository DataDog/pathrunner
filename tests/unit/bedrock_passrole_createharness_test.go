// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/bedrock_passrole_createharness"
	"github.com/DataDog/pathrunner/pkg/modules"
	"testing"
)

func TestBedrockPassroleCreateHarnessModuleInit(t *testing.T) {
	mod := bedrock_passrole_createharness.NewModule()

	if mod.Name() != "bedrock-005" {
		t.Errorf("Expected name 'bedrock-005', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "bedrock-005" {
		t.Errorf("Expected ID 'bedrock-005', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestBedrockPassroleCreateHarnessDescription(t *testing.T) {
	mod := bedrock_passrole_createharness.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestBedrockPassroleCreateHarnessServices(t *testing.T) {
	mod := bedrock_passrole_createharness.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "bedrock-agentcore": true}
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

func TestBedrockPassroleCreateHarnessOptions(t *testing.T) {
	mod := bedrock_passrole_createharness.NewModule()
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

	// ROLE_ARN is required (named ROLE_ARN so test-module.sh can auto-map it)
	if !requiredOptions["ROLE_ARN"] {
		t.Error("Expected ROLE_ARN to be required")
	}

	// REGION, MODEL_ID, HARNESS_NAME, CLEANUP are optional
	for _, opt := range []string{"REGION", "MODEL_ID", "HARNESS_NAME", "CLEANUP"} {
		if !optionalOptions[opt] {
			t.Errorf("Expected %s to be optional", opt)
		}
	}
}

func TestBedrockPassroleCreateHarnessOptionDefaults(t *testing.T) {
	mod := bedrock_passrole_createharness.NewModule()
	options := mod.Options()

	defaults := map[string]string{}
	for _, opt := range options {
		if opt.Default != "" {
			defaults[opt.Name] = opt.Default
		}
	}

	if defaults["REGION"] != "us-east-1" {
		t.Errorf("Expected REGION default 'us-east-1', got '%s'", defaults["REGION"])
	}
	if defaults["MODEL_ID"] != "amazon.nova-micro-v1:0" {
		t.Errorf("Expected MODEL_ID default 'amazon.nova-micro-v1:0', got '%s'", defaults["MODEL_ID"])
	}
	// CLEANUP should default to false to avoid accidental harness deletion
	if defaults["CLEANUP"] != "false" {
		t.Errorf("Expected CLEANUP default 'false', got '%s'", defaults["CLEANUP"])
	}
}

func TestBedrockPassroleCreateHarnessPermissions(t *testing.T) {
	mod := bedrock_passrole_createharness.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	// Must require iam:PassRole — this is new-passrole category
	if !requiredPerms["iam:PassRole"] {
		t.Error("Missing required permission: iam:PassRole")
	}

	// Must require bedrock-agentcore permissions
	if !requiredPerms["bedrock-agentcore:CreateHarness"] {
		t.Error("Missing required permission: bedrock-agentcore:CreateHarness")
	}
	if !requiredPerms["bedrock-agentcore:InvokeAgentRuntimeCommand"] {
		t.Error("Missing required permission: bedrock-agentcore:InvokeAgentRuntimeCommand")
	}
}

func TestBedrockPassroleCreateHarnessAliases(t *testing.T) {
	mod := bedrock_passrole_createharness.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["bedrock-passrole-createharness"] {
		t.Error("Expected alias 'bedrock-passrole-createharness'")
	}
}

func TestBedrockPassroleCreateHarnessRegistration(t *testing.T) {
	mod, err := modules.LoadModule("bedrock-005")
	if err != nil {
		t.Fatalf("Expected module 'bedrock-005' to be registered: %v", err)
	}
	if mod.Name() != "bedrock-005" {
		t.Errorf("Expected name 'bedrock-005', got '%s'", mod.Name())
	}
}

func TestBedrockPassroleCreateHarnessAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("bedrock-passrole-createharness")
	if err != nil {
		t.Fatalf("Expected alias 'bedrock-passrole-createharness' to be registered: %v", err)
	}
	if mod.Name() != "bedrock-005" {
		t.Errorf("Expected name 'bedrock-005' via alias, got '%s'", mod.Name())
	}
}

func TestBedrockPassroleCreateHarnessPayloadCompatible(t *testing.T) {
	mod := bedrock_passrole_createharness.NewModule()

	_, isPayloadCompatible := interface{}(mod).(modules.PayloadCompatible)
	if !isPayloadCompatible {
		t.Error("bedrock-005 should implement PayloadCompatible")
	}
}

func TestBedrockPassroleCreateHarnessMITRE(t *testing.T) {
	mod := bedrock_passrole_createharness.NewModule()
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

	// bedrock-005 is both privesc and credential access
	hasPrivEsc := false
	hasCredAccess := false
	for _, tactic := range pathInfo.MITRE.Tactics {
		if contains(tactic, "Privilege Escalation") {
			hasPrivEsc = true
		}
		if contains(tactic, "Credential Access") {
			hasCredAccess = true
		}
	}
	if !hasPrivEsc {
		t.Error("Expected MITRE tactics to include Privilege Escalation")
	}
	if !hasCredAccess {
		t.Error("Expected MITRE tactics to include Credential Access")
	}
}

func TestBedrockPassroleCreateHarnessReferences(t *testing.T) {
	mod := bedrock_passrole_createharness.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/bedrock-005") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for bedrock-005")
	}
}

func TestBedrockPassroleCreateHarnessPrerequisites(t *testing.T) {
	mod := bedrock_passrole_createharness.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected admin prerequisites")
	}
	if len(pathInfo.Prerequisites.Lateral) == 0 {
		t.Error("Expected lateral prerequisites")
	}
}

func TestBedrockPassroleCreateHarnessRelatedPaths(t *testing.T) {
	mod := bedrock_passrole_createharness.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.RelatedPaths) == 0 {
		t.Error("Expected related paths")
	}

	relatedSet := map[string]bool{}
	for _, rp := range pathInfo.RelatedPaths {
		relatedSet[rp] = true
	}

	// bedrock-004 is the existing-passrole sibling
	if !relatedSet["bedrock-004"] {
		t.Error("Expected bedrock-004 in related paths")
	}
}

