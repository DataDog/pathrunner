package unit

import (
	"pathrunner/pkg/exploits/bedrock_startbrowsersession_cdp"
	"testing"
)

func TestBedrockStartBrowserSessionCDPModuleInit(t *testing.T) {
	mod := bedrock_startbrowsersession_cdp.NewModule()

	if mod.Name() != "bedrock-007" {
		t.Errorf("Expected name 'bedrock-007', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "bedrock-007" {
		t.Errorf("Expected ID 'bedrock-007', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestBedrockStartBrowserSessionCDPDescription(t *testing.T) {
	mod := bedrock_startbrowsersession_cdp.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestBedrockStartBrowserSessionCDPServices(t *testing.T) {
	mod := bedrock_startbrowsersession_cdp.NewModule()
	pathInfo := mod.PathInfo()

	found := false
	for _, svc := range pathInfo.Services {
		if svc == "bedrock-agentcore" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected service 'bedrock-agentcore' in services list, got: %v", pathInfo.Services)
	}
}

func TestBedrockStartBrowserSessionCDPOptions(t *testing.T) {
	mod := bedrock_startbrowsersession_cdp.NewModule()
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

	// BROWSER_ID is the only required option
	if !requiredOptions["BROWSER_ID"] {
		t.Error("Expected BROWSER_ID to be required")
	}

	// These are optional
	expectedOptional := []string{"REGION", "IDENTITY_NAME", "AUTO_SWITCH"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected '%s' to be optional", name)
		}
	}
}

func TestBedrockStartBrowserSessionCDPPermissions(t *testing.T) {
	mod := bedrock_startbrowsersession_cdp.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{
		"bedrock-agentcore:StartBrowserSession",
		"bedrock-agentcore:ConnectBrowserAutomationStream",
	}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestBedrockStartBrowserSessionCDPAliases(t *testing.T) {
	mod := bedrock_startbrowsersession_cdp.NewModule()
	pathInfo := mod.PathInfo()

	aliasSet := map[string]bool{}
	for _, alias := range pathInfo.Aliases {
		aliasSet[alias] = true
	}

	expectedAliases := []string{
		"bedrock-startbrowsersession-cdp",
		"exploit/bedrock_startbrowsersession_cdp",
	}
	for _, alias := range expectedAliases {
		if !aliasSet[alias] {
			t.Errorf("Missing expected alias: %s", alias)
		}
	}
}

func TestBedrockStartBrowserSessionCDPMITRE(t *testing.T) {
	mod := bedrock_startbrowsersession_cdp.NewModule()
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

func TestBedrockStartBrowserSessionCDPAutoSwitchDefault(t *testing.T) {
	mod := bedrock_startbrowsersession_cdp.NewModule()
	options := mod.Options()

	for _, opt := range options {
		if opt.Name == "AUTO_SWITCH" {
			if opt.Default != "true" {
				t.Errorf("Expected AUTO_SWITCH default to be 'true', got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("AUTO_SWITCH option not found")
}

func TestBedrockStartBrowserSessionCDPRegionDefault(t *testing.T) {
	mod := bedrock_startbrowsersession_cdp.NewModule()
	options := mod.Options()

	for _, opt := range options {
		if opt.Name == "REGION" {
			if opt.Default == "" {
				t.Error("Expected REGION to have a default value")
			}
			return
		}
	}
	t.Error("REGION option not found")
}

func TestBedrockStartBrowserSessionCDPDiscoverableOptions(t *testing.T) {
	mod := bedrock_startbrowsersession_cdp.NewModule()

	discoverableOpts := mod.DiscoverableOptions()
	found := false
	for _, opt := range discoverableOpts {
		if opt == "BROWSER_ID" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected BROWSER_ID in discoverable options, got: %v", discoverableOpts)
	}
}
