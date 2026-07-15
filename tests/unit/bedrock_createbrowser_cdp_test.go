package unit

import (
	"pathrunner/pkg/exploits/bedrock_createbrowser_cdp"
	"strings"
	"testing"
)

func TestBedrockCreateBrowserCDPModuleInit(t *testing.T) {
	mod := bedrock_createbrowser_cdp.NewModule()

	if mod.Name() != "bedrock-006" {
		t.Errorf("Expected name 'bedrock-006', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "bedrock-006" {
		t.Errorf("Expected ID 'bedrock-006', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestBedrockCreateBrowserCDPDescription(t *testing.T) {
	mod := bedrock_createbrowser_cdp.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestBedrockCreateBrowserCDPServices(t *testing.T) {
	mod := bedrock_createbrowser_cdp.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := []string{"iam", "bedrock-agentcore"}
	serviceSet := map[string]bool{}
	for _, svc := range pathInfo.Services {
		serviceSet[svc] = true
	}

	for _, expected := range expectedServices {
		if !serviceSet[expected] {
			t.Errorf("Expected service '%s' in services list, got: %v", expected, pathInfo.Services)
		}
	}
}

func TestBedrockCreateBrowserCDPOptions(t *testing.T) {
	mod := bedrock_createbrowser_cdp.NewModule()
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

	// ROLE_ARN is the only required option
	if !requiredOptions["ROLE_ARN"] {
		t.Error("Expected ROLE_ARN to be required")
	}

	// These are optional
	expectedOptional := []string{"REGION", "BROWSER_NAME", "WAIT_TIMEOUT", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected '%s' to be optional", name)
		}
	}
}

func TestBedrockCreateBrowserCDPPermissions(t *testing.T) {
	mod := bedrock_createbrowser_cdp.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{
		"iam:PassRole",
		"bedrock-agentcore:CreateBrowser",
		"bedrock-agentcore:StartBrowserSession",
		"bedrock-agentcore:ConnectBrowserAutomationStream",
	}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestBedrockCreateBrowserCDPAliases(t *testing.T) {
	mod := bedrock_createbrowser_cdp.NewModule()
	pathInfo := mod.PathInfo()

	aliasSet := map[string]bool{}
	for _, alias := range pathInfo.Aliases {
		aliasSet[alias] = true
	}

	expectedAliases := []string{
		"bedrock-createbrowser-cdp",
		"exploit/bedrock_createbrowser_cdp",
	}
	for _, alias := range expectedAliases {
		if !aliasSet[alias] {
			t.Errorf("Missing expected alias: %s", alias)
		}
	}
}

func TestBedrockCreateBrowserCDPMITRE(t *testing.T) {
	mod := bedrock_createbrowser_cdp.NewModule()
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

func TestBedrockCreateBrowserCDPWaitTimeoutDefault(t *testing.T) {
	mod := bedrock_createbrowser_cdp.NewModule()
	options := mod.Options()

	for _, opt := range options {
		if opt.Name == "WAIT_TIMEOUT" {
			if opt.Default != "300" {
				t.Errorf("Expected WAIT_TIMEOUT default to be '300', got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("WAIT_TIMEOUT option not found")
}

func TestBedrockCreateBrowserCDPCleanupDefault(t *testing.T) {
	mod := bedrock_createbrowser_cdp.NewModule()
	options := mod.Options()

	for _, opt := range options {
		if opt.Name == "CLEANUP" {
			// CLEANUP defaults to false because the starting user typically lacks DeleteBrowser
			if opt.Default != "false" {
				t.Errorf("Expected CLEANUP default to be 'false', got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("CLEANUP option not found")
}

func TestBedrockCreateBrowserCDPRegionDefault(t *testing.T) {
	mod := bedrock_createbrowser_cdp.NewModule()
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

func TestBedrockCreateBrowserCDPRelatedPaths(t *testing.T) {
	mod := bedrock_createbrowser_cdp.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.RelatedPaths) == 0 {
		t.Error("Expected at least one related path")
	}

	// bedrock-007 is the existing-passrole sibling (target existing browser instead of creating one)
	relatedSet := map[string]bool{}
	for _, related := range pathInfo.RelatedPaths {
		relatedSet[related] = true
	}
	if !relatedSet["bedrock-007"] {
		t.Errorf("Expected bedrock-007 in related paths, got: %v", pathInfo.RelatedPaths)
	}
}

func TestBedrockCreateBrowserCDPExtractCredentialJSON(t *testing.T) {
	// Valid credentials JSON from MMDS (possibly preceded by info lines)
	input := "INFO: connecting to MMDS\n" +
		`{"AccessKeyId":"ASIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Token":"AQoXnyc4lcK4w","Expiration":"2024-01-15T18:30:00Z"}`

	result := bedrock_createbrowser_cdp.ExtractCredentialJSON(input)
	if result == "" {
		t.Fatal("ExtractCredentialJSON returned empty string for valid input")
	}
	if !strings.Contains(result, "ASIAIOSFODNN7EXAMPLE") {
		t.Errorf("Expected AccessKeyId in result, got: %s", result)
	}
}

func TestBedrockCreateBrowserCDPExtractCredentialJSONNotFound(t *testing.T) {
	result := bedrock_createbrowser_cdp.ExtractCredentialJSON("no credentials here")
	if result != "" {
		t.Errorf("Expected empty string when no credentials found, got: %s", result)
	}
}
