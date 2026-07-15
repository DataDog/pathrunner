package unit

import (
	"pathrunner/pkg/exploits/braket_passrole"
	"pathrunner/pkg/modules"
	_ "pathrunner/pkg/payloads/braket"
	"testing"
)

func TestBraketPassroleModuleInit(t *testing.T) {
	mod := braket_passrole.NewModule()

	if mod.Name() != "braket-001" {
		t.Errorf("Expected name 'braket-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "braket-001" {
		t.Errorf("Expected ID 'braket-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestBraketPassroleDescription(t *testing.T) {
	mod := braket_passrole.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestBraketPassroleServices(t *testing.T) {
	mod := braket_passrole.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "braket": true}
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

func TestBraketPassroleOptions(t *testing.T) {
	mod := braket_passrole.NewModule()
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
	expectedOptional := []string{"SCRIPT_S3_URI", "OUTPUT_S3_PATH", "REGION", "JOB_NAME", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestBraketPassrolePermissions(t *testing.T) {
	mod := braket_passrole.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "braket:CreateJob"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestBraketPassroleAliases(t *testing.T) {
	mod := braket_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["braket-passrole"] {
		t.Error("Expected alias 'braket-passrole'")
	}
}

func TestBraketPassroleDiscoverableOptions(t *testing.T) {
	mod := braket_passrole.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	if len(options) != 1 || options[0] != "ROLE_ARN" {
		t.Errorf("Expected DiscoverableOptions to return ['ROLE_ARN'], got %v", options)
	}
}

func TestBraketPassroleRegistration(t *testing.T) {
	mod, err := modules.LoadModule("braket-001")
	if err != nil {
		t.Fatalf("Expected module 'braket-001' to be registered: %v", err)
	}
	if mod.Name() != "braket-001" {
		t.Errorf("Expected name 'braket-001', got '%s'", mod.Name())
	}
}

func TestBraketPassroleAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("braket-passrole")
	if err != nil {
		t.Fatalf("Expected alias 'braket-passrole' to be registered: %v", err)
	}
	if mod.Name() != "braket-001" {
		t.Errorf("Expected name 'braket-001' via alias, got '%s'", mod.Name())
	}
}

func TestBraketPassrolePayloadCompatible(t *testing.T) {
	mod := braket_passrole.NewModule()

	payloadList := mod.ListPayloads()
	if len(payloadList) == 0 {
		t.Error("Expected at least one Braket payload registered")
	}

	compatible, ok := interface{}(mod).(modules.PayloadCompatible)
	if !ok {
		t.Fatal("Expected module to implement PayloadCompatible interface")
	}

	tags := compatible.GetCompatibleTags()
	hasBraket := false
	for _, tag := range tags {
		if tag == "braket" {
			hasBraket = true
		}
	}
	if !hasBraket {
		t.Error("Expected compatible tags to include 'braket'")
	}

	ctx := compatible.GetPayloadContext()
	if ctx != "braket" {
		t.Errorf("Expected payload context 'braket', got '%s'", ctx)
	}
}

func TestBraketPassroleExecuteInvalidPayload(t *testing.T) {
	mod := braket_passrole.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN": "arn:aws:iam::123456789012:role/admin",
			"PAYLOAD":  "nonexistent/payload",
		},
		AttackerIdentity: nil,
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error with invalid payload type")
	}
	if err != nil && !containsBraket(err.Error(), "unknown payload type") {
		t.Errorf("Expected error about unknown payload type, got: %v", err)
	}
}

func TestBraketPassroleExecuteNoAttackerNoS3(t *testing.T) {
	mod := braket_passrole.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN":    "arn:aws:iam::123456789012:role/admin",
			"PAYLOAD":     "backdoor/attach-policy",
			"TARGET_USER": "victim-user",
		},
		AttackerIdentity: nil,
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when executing without attacker identity or SCRIPT_S3_URI")
	}
	if err != nil && !containsBraket(err.Error(), "no SCRIPT_S3_URI") && !containsBraket(err.Error(), "no attacker code bucket") {
		t.Errorf("Expected error about missing SCRIPT_S3_URI or code bucket, got: %v", err)
	}
}

func TestBraketPassroleMITRE(t *testing.T) {
	mod := braket_passrole.NewModule()
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

func TestBraketPassroleReferences(t *testing.T) {
	mod := braket_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if containsBraket(ref.URL, "pathfinding.cloud/paths/braket-001") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for braket-001")
	}
}

func containsBraket(s, substr string) bool {
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
