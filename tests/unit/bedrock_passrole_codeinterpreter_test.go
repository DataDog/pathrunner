package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/bedrock_passrole_codeinterpreter"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/bedrock" // Register bedrock payloads for ListPayloads tests
	"testing"
)

func TestBedrockPassroleCodeInterpreterModuleInit(t *testing.T) {
	mod := bedrock_passrole_codeinterpreter.NewModule()

	if mod.Name() != "bedrock-001" {
		t.Errorf("Expected name 'bedrock-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "bedrock-001" {
		t.Errorf("Expected ID 'bedrock-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestBedrockPassroleCodeInterpreterDescription(t *testing.T) {
	mod := bedrock_passrole_codeinterpreter.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestBedrockPassroleCodeInterpreterServices(t *testing.T) {
	mod := bedrock_passrole_codeinterpreter.NewModule()
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

func TestBedrockPassroleCodeInterpreterOptions(t *testing.T) {
	mod := bedrock_passrole_codeinterpreter.NewModule()
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

	// ROLE_ARN is required (standard option name for passrole modules, enables auto-mapping in test-module.sh)
	if !requiredOptions["ROLE_ARN"] {
		t.Error("Expected ROLE_ARN to be required")
	}

	// PAYLOAD is required
	if !requiredOptions["PAYLOAD"] {
		t.Error("Expected PAYLOAD to be required")
	}

	// REGION is optional with a default
	if !optionalOptions["REGION"] {
		t.Error("Expected REGION to be optional")
	}

	// CLEANUP is optional and defaults to false (starting user typically lacks delete permission)
	if !optionalOptions["CLEANUP"] {
		t.Error("Expected CLEANUP to be optional")
	}

	// INIT_WAIT_SECONDS is optional (defaults to 15 s from demo_attack.sh calibration)
	if !optionalOptions["INIT_WAIT_SECONDS"] {
		t.Error("Expected INIT_WAIT_SECONDS to be optional")
	}
}

func TestBedrockPassroleCodeInterpreterPayloadDefaults(t *testing.T) {
	mod := bedrock_passrole_codeinterpreter.NewModule()
	options := mod.Options()

	for _, opt := range options {
		switch opt.Name {
		case "PAYLOAD":
			if opt.Default != "exfil/response" {
				t.Errorf("Expected PAYLOAD default to be 'exfil/response', got '%s'", opt.Default)
			}
		case "REGION":
			if opt.Default != "us-east-1" {
				t.Errorf("Expected REGION default to be 'us-east-1', got '%s'", opt.Default)
			}
		case "CLEANUP":
			// Should default to false — starting identity typically lacks DeleteCodeInterpreter
			if opt.Default != "false" {
				t.Errorf("Expected CLEANUP default to be 'false' (starting user lacks delete permission), got '%s'", opt.Default)
			}
		case "INIT_WAIT_SECONDS":
			// Calibrated from demo_attack.sh: sleep 15
			if opt.Default != "15" {
				t.Errorf("Expected INIT_WAIT_SECONDS default to be '15' (calibrated from demo_attack.sh), got '%s'", opt.Default)
			}
		}
	}
}

func TestBedrockPassroleCodeInterpreterRegisteredByPrimaryID(t *testing.T) {
	mod, err := modules.LoadModule("bedrock-001")
	if err != nil {
		t.Fatalf("bedrock-001 was not registered in the global module registry: %v", err)
	}

	pathInfo := mod.PathInfo()
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestBedrockPassroleCodeInterpreterRegisteredByAlias(t *testing.T) {
	mod, err := modules.LoadModule("bedrock-passrole")
	if err != nil {
		t.Fatalf("bedrock-passrole alias was not registered in the global module registry: %v", err)
	}
	if mod.Name() != "bedrock-001" {
		t.Errorf("Expected module name 'bedrock-001' via alias, got '%s'", mod.Name())
	}
}

func TestBedrockPassroleCodeInterpreterMITRE(t *testing.T) {
	mod := bedrock_passrole_codeinterpreter.NewModule()
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

func TestBedrockPassroleCodeInterpreterPermissions(t *testing.T) {
	mod := bedrock_passrole_codeinterpreter.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := make(map[string]bool)
	for _, p := range pathInfo.Permissions.Required {
		requiredPerms[p.Permission] = true
	}

	expectedPerms := []string{
		"iam:PassRole",
		"bedrock-agentcore:CreateCodeInterpreter",
		"bedrock-agentcore:StartCodeInterpreterSession",
		"bedrock-agentcore:InvokeCodeInterpreter",
	}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Expected required permission '%s' not found", perm)
		}
	}
}

func TestBedrockPassroleCodeInterpreterListPayloads(t *testing.T) {
	mod := bedrock_passrole_codeinterpreter.NewModule()
	payloadInfos := mod.ListPayloads()

	// Should list at least the exfil/response and backdoor/attach-policy payloads.
	if len(payloadInfos) == 0 {
		t.Error("Expected at least one payload to be listed")
	}

	payloadNames := make(map[string]bool)
	for _, p := range payloadInfos {
		payloadNames[p.Name] = true
	}

	if !payloadNames["exfil/response"] {
		t.Error("Expected exfil/response payload to be listed")
	}

	if !payloadNames["backdoor/attach-policy"] {
		t.Error("Expected backdoor/attach-policy payload to be listed")
	}
}
