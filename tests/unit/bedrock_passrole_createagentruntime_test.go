// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/bedrock_passrole_createagentruntime"
	"github.com/DataDog/pathrunner/pkg/modules"
	"testing"
)

func TestBedrockPassroleCreateAgentRuntimeModuleInit(t *testing.T) {
	mod := bedrock_passrole_createagentruntime.NewModule()

	if mod.Name() != "bedrock-003" {
		t.Errorf("Expected name 'bedrock-003', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "bedrock-003" {
		t.Errorf("Expected ID 'bedrock-003', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestBedrockPassroleCreateAgentRuntimeDescription(t *testing.T) {
	mod := bedrock_passrole_createagentruntime.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestBedrockPassroleCreateAgentRuntimeServices(t *testing.T) {
	mod := bedrock_passrole_createagentruntime.NewModule()
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

func TestBedrockPassroleCreateAgentRuntimeOptions(t *testing.T) {
	mod := bedrock_passrole_createagentruntime.NewModule()
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

	// EXECUTION_ROLE_ARN is required; CONTAINER_URI is optional (auto-finds/creates ECR repo)
	if !requiredOptions["EXECUTION_ROLE_ARN"] {
		t.Error("Expected EXECUTION_ROLE_ARN to be required")
	}

	// CONTAINER_URI, REGION, RUNTIME_NAME, CLEANUP are optional
	for _, opt := range []string{"CONTAINER_URI", "REGION", "RUNTIME_NAME", "CLEANUP"} {
		if !optionalOptions[opt] {
			t.Errorf("Expected %s to be optional", opt)
		}
	}
}

func TestBedrockPassroleCreateAgentRuntimeOptionDefaults(t *testing.T) {
	mod := bedrock_passrole_createagentruntime.NewModule()
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
	// CLEANUP should default to false to avoid accidental runtime deletion
	if defaults["CLEANUP"] != "false" {
		t.Errorf("Expected CLEANUP default 'false', got '%s'", defaults["CLEANUP"])
	}
}

func TestBedrockPassroleCreateAgentRuntimePermissions(t *testing.T) {
	mod := bedrock_passrole_createagentruntime.NewModule()
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
	if !requiredPerms["bedrock-agentcore:CreateAgentRuntime"] {
		t.Error("Missing required permission: bedrock-agentcore:CreateAgentRuntime")
	}
	if !requiredPerms["bedrock-agentcore:InvokeAgentRuntimeCommand"] {
		t.Error("Missing required permission: bedrock-agentcore:InvokeAgentRuntimeCommand")
	}
	if !requiredPerms["bedrock-agentcore:CreateAgentRuntimeEndpoint"] {
		t.Error("Missing required permission: bedrock-agentcore:CreateAgentRuntimeEndpoint")
	}
	if !requiredPerms["bedrock-agentcore:CreateWorkloadIdentity"] {
		t.Error("Missing required permission: bedrock-agentcore:CreateWorkloadIdentity")
	}
}

func TestBedrockPassroleCreateAgentRuntimeAliases(t *testing.T) {
	mod := bedrock_passrole_createagentruntime.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["bedrock-passrole-createagentruntime"] {
		t.Error("Expected alias 'bedrock-passrole-createagentruntime'")
	}
}

func TestBedrockPassroleCreateAgentRuntimeRegistration(t *testing.T) {
	mod, err := modules.LoadModule("bedrock-003")
	if err != nil {
		t.Fatalf("Expected module 'bedrock-003' to be registered: %v", err)
	}
	if mod.Name() != "bedrock-003" {
		t.Errorf("Expected name 'bedrock-003', got '%s'", mod.Name())
	}
}

func TestBedrockPassroleCreateAgentRuntimeAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("bedrock-passrole-createagentruntime")
	if err != nil {
		t.Fatalf("Expected alias 'bedrock-passrole-createagentruntime' to be registered: %v", err)
	}
	if mod.Name() != "bedrock-003" {
		t.Errorf("Expected name 'bedrock-003' via alias, got '%s'", mod.Name())
	}
}

func TestBedrockPassroleCreateAgentRuntimePayloadCompatible(t *testing.T) {
	mod := bedrock_passrole_createagentruntime.NewModule()

	_, isPayloadCompatible := interface{}(mod).(modules.PayloadCompatible)
	if !isPayloadCompatible {
		t.Error("bedrock-003 should implement PayloadCompatible")
	}
}

func TestBedrockPassroleCreateAgentRuntimeMITRE(t *testing.T) {
	mod := bedrock_passrole_createagentruntime.NewModule()
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

	// bedrock-003 is both privesc and credential access
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

func TestBedrockPassroleCreateAgentRuntimeReferences(t *testing.T) {
	mod := bedrock_passrole_createagentruntime.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/bedrock-003") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for bedrock-003")
	}
}

func TestBedrockPassroleCreateAgentRuntimePrerequisites(t *testing.T) {
	mod := bedrock_passrole_createagentruntime.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected admin prerequisites")
	}
	if len(pathInfo.Prerequisites.Lateral) == 0 {
		t.Error("Expected lateral prerequisites")
	}
}

func TestBedrockPassroleCreateAgentRuntimeRelatedPaths(t *testing.T) {
	mod := bedrock_passrole_createagentruntime.NewModule()
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
	// bedrock-005 is the CreateHarness variant of the same shape
	if !relatedSet["bedrock-005"] {
		t.Error("Expected bedrock-005 in related paths")
	}
}

