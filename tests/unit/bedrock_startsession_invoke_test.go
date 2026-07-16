package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/bedrock_startsession_invoke"
	"github.com/DataDog/pathrunner/pkg/modules"
	"testing"
)

func TestBedrockStartSessionInvokeModuleInit(t *testing.T) {
	mod := bedrock_startsession_invoke.NewModule()

	if mod.Name() != "bedrock-002" {
		t.Errorf("Expected name 'bedrock-002', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "bedrock-002" {
		t.Errorf("Expected ID 'bedrock-002', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestBedrockStartSessionInvokeDescription(t *testing.T) {
	mod := bedrock_startsession_invoke.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestBedrockStartSessionInvokeServices(t *testing.T) {
	mod := bedrock_startsession_invoke.NewModule()
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

func TestBedrockStartSessionInvokeOptions(t *testing.T) {
	mod := bedrock_startsession_invoke.NewModule()
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

	// INTERPRETER_ID is required
	if !requiredOptions["INTERPRETER_ID"] {
		t.Error("Expected INTERPRETER_ID to be required")
	}

	// REGION is optional with a default
	if !optionalOptions["REGION"] {
		t.Error("Expected REGION to be optional")
	}

	// This module does not use payloads — it's a credential theft module
	if requiredOptions["PAYLOAD"] {
		t.Error("bedrock-002 should not have a PAYLOAD option (credential theft module)")
	}
}

func TestBedrockStartSessionInvokePermissions(t *testing.T) {
	mod := bedrock_startsession_invoke.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	if !requiredPerms["bedrock-agentcore:StartCodeInterpreterSession"] {
		t.Error("Missing required permission: bedrock-agentcore:StartCodeInterpreterSession")
	}
	if !requiredPerms["bedrock-agentcore:InvokeCodeInterpreter"] {
		t.Error("Missing required permission: bedrock-agentcore:InvokeCodeInterpreter")
	}

	// Should NOT require iam:PassRole — this is existing-passrole (role already attached)
	if requiredPerms["iam:PassRole"] {
		t.Error("bedrock-002 should not require iam:PassRole (existing-passrole category)")
	}
}

func TestBedrockStartSessionInvokeAliases(t *testing.T) {
	mod := bedrock_startsession_invoke.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["bedrock-startsession-invoke"] {
		t.Error("Expected alias 'bedrock-startsession-invoke'")
	}
}

func TestBedrockStartSessionInvokeRegistration(t *testing.T) {
	mod, err := modules.LoadModule("bedrock-002")
	if err != nil {
		t.Fatalf("Expected module 'bedrock-002' to be registered: %v", err)
	}
	if mod.Name() != "bedrock-002" {
		t.Errorf("Expected name 'bedrock-002', got '%s'", mod.Name())
	}
}

func TestBedrockStartSessionInvokeAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("bedrock-startsession-invoke")
	if err != nil {
		t.Fatalf("Expected alias 'bedrock-startsession-invoke' to be registered: %v", err)
	}
	if mod.Name() != "bedrock-002" {
		t.Errorf("Expected name 'bedrock-002' via alias, got '%s'", mod.Name())
	}
}

func TestBedrockStartSessionInvokeNoPayloads(t *testing.T) {
	mod := bedrock_startsession_invoke.NewModule()

	// This module does not use payloads — it directly steals credentials via MMDS
	payloadList := mod.ListPayloads()
	if len(payloadList) != 0 {
		t.Errorf("Expected no payloads for bedrock-002 (credential theft module), got %d", len(payloadList))
	}
}

func TestBedrockStartSessionInvokeMITRE(t *testing.T) {
	mod := bedrock_startsession_invoke.NewModule()
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

func TestBedrockStartSessionInvokeReferences(t *testing.T) {
	mod := bedrock_startsession_invoke.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/bedrock-002") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for bedrock-002")
	}
}

func TestBedrockStartSessionInvokePrerequisites(t *testing.T) {
	mod := bedrock_startsession_invoke.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected admin prerequisites")
	}
	if len(pathInfo.Prerequisites.Lateral) == 0 {
		t.Error("Expected lateral prerequisites")
	}
}

func TestBedrockStartSessionInvokeRelatedPaths(t *testing.T) {
	mod := bedrock_startsession_invoke.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.RelatedPaths) == 0 {
		t.Error("Expected related paths")
	}

	relatedSet := map[string]bool{}
	for _, rp := range pathInfo.RelatedPaths {
		relatedSet[rp] = true
	}

	// bedrock-001 is the new-passrole sibling of this existing-passrole path
	if !relatedSet["bedrock-001"] {
		t.Error("Expected bedrock-001 in related paths")
	}
}

