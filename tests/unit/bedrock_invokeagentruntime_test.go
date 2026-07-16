package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/bedrock_invokeagentruntime"
	"github.com/DataDog/pathrunner/pkg/modules"
	"testing"
)

func TestBedrockInvokeAgentRuntimeModuleInit(t *testing.T) {
	mod := bedrock_invokeagentruntime.NewModule()

	if mod.Name() != "bedrock-004" {
		t.Errorf("Expected name 'bedrock-004', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "bedrock-004" {
		t.Errorf("Expected ID 'bedrock-004', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestBedrockInvokeAgentRuntimeDescription(t *testing.T) {
	mod := bedrock_invokeagentruntime.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestBedrockInvokeAgentRuntimeServices(t *testing.T) {
	mod := bedrock_invokeagentruntime.NewModule()
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

func TestBedrockInvokeAgentRuntimeOptions(t *testing.T) {
	mod := bedrock_invokeagentruntime.NewModule()
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

	// TARGET_RUNTIME_ARN is required
	if !requiredOptions["TARGET_RUNTIME_ARN"] {
		t.Error("Expected TARGET_RUNTIME_ARN to be required")
	}

	// REGION is optional with a default
	if !optionalOptions["REGION"] {
		t.Error("Expected REGION to be optional")
	}

	// This module does not use payloads
	if requiredOptions["PAYLOAD"] {
		t.Error("bedrock-004 should not have a PAYLOAD option (credential theft module)")
	}
}

func TestBedrockInvokeAgentRuntimePermissions(t *testing.T) {
	mod := bedrock_invokeagentruntime.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	if !requiredPerms["bedrock-agentcore:InvokeAgentRuntimeCommand"] {
		t.Error("Missing required permission: bedrock-agentcore:InvokeAgentRuntimeCommand")
	}

	// Should NOT require iam:PassRole — this is existing-passrole (role already attached)
	if requiredPerms["iam:PassRole"] {
		t.Error("bedrock-004 should not require iam:PassRole (existing-passrole category)")
	}
}

func TestBedrockInvokeAgentRuntimeAliases(t *testing.T) {
	mod := bedrock_invokeagentruntime.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["bedrock-invokeagentruntime"] {
		t.Error("Expected alias 'bedrock-invokeagentruntime'")
	}
}

func TestBedrockInvokeAgentRuntimeRegistration(t *testing.T) {
	mod, err := modules.LoadModule("bedrock-004")
	if err != nil {
		t.Fatalf("Expected module 'bedrock-004' to be registered: %v", err)
	}
	if mod.Name() != "bedrock-004" {
		t.Errorf("Expected name 'bedrock-004', got '%s'", mod.Name())
	}
}

func TestBedrockInvokeAgentRuntimeAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("bedrock-invokeagentruntime")
	if err != nil {
		t.Fatalf("Expected alias 'bedrock-invokeagentruntime' to be registered: %v", err)
	}
	if mod.Name() != "bedrock-004" {
		t.Errorf("Expected name 'bedrock-004' via alias, got '%s'", mod.Name())
	}
}

func TestBedrockInvokeAgentRuntimeNoPayloads(t *testing.T) {
	mod := bedrock_invokeagentruntime.NewModule()

	// This module does not use payloads — it directly steals credentials
	payloadList := mod.ListPayloads()
	if len(payloadList) != 0 {
		t.Errorf("Expected no payloads for bedrock-004 (credential theft module), got %d", len(payloadList))
	}
}

func TestBedrockInvokeAgentRuntimeMITRE(t *testing.T) {
	mod := bedrock_invokeagentruntime.NewModule()
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

	// This module is both privesc and credential access
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

func TestBedrockInvokeAgentRuntimeReferences(t *testing.T) {
	mod := bedrock_invokeagentruntime.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/bedrock-004") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for bedrock-004")
	}
}

func TestBedrockInvokeAgentRuntimePrerequisites(t *testing.T) {
	mod := bedrock_invokeagentruntime.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected admin prerequisites")
	}
	if len(pathInfo.Prerequisites.Lateral) == 0 {
		t.Error("Expected lateral prerequisites")
	}
}

func TestBedrockInvokeAgentRuntimeRelatedPaths(t *testing.T) {
	mod := bedrock_invokeagentruntime.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.RelatedPaths) == 0 {
		t.Error("Expected related paths")
	}

	relatedSet := map[string]bool{}
	for _, rp := range pathInfo.RelatedPaths {
		relatedSet[rp] = true
	}

	// bedrock-003 is the new-passrole sibling of this existing-passrole path
	if !relatedSet["bedrock-003"] {
		t.Error("Expected bedrock-003 in related paths")
	}
}

