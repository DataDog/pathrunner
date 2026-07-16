package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/emr_passrole"
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/payloads/emr"
)

func TestEMRPassroleModuleInit(t *testing.T) {
	mod := emr_passrole.NewModule()

	if mod.Name() != "emr-001" {
		t.Errorf("Expected name 'emr-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "emr-001" {
		t.Errorf("Expected ID 'emr-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestEMRPassroleDescription(t *testing.T) {
	mod := emr_passrole.NewModule()
	desc := mod.Description()
	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestEMRPassroleServices(t *testing.T) {
	mod := emr_passrole.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "emr": true}
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

func TestEMRPassroleOptions(t *testing.T) {
	mod := emr_passrole.NewModule()
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

	// INSTANCE_PROFILE, SERVICE_ROLE, PAYLOAD are required
	for _, name := range []string{"INSTANCE_PROFILE", "SERVICE_ROLE", "PAYLOAD"} {
		if !requiredOptions[name] {
			t.Errorf("Expected %s to be required", name)
		}
	}

	// REGION, RELEASE_LABEL, INSTANCE_TYPE, CLUSTER_NAME, TARGET_ARN, CLEANUP are optional
	for _, name := range []string{"REGION", "RELEASE_LABEL", "INSTANCE_TYPE", "CLUSTER_NAME", "TARGET_ARN", "CLEANUP"} {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestEMRPassroleDefaultValues(t *testing.T) {
	mod := emr_passrole.NewModule()
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
	if defaults["RELEASE_LABEL"] != "emr-7.0.0" {
		t.Errorf("Expected RELEASE_LABEL default 'emr-7.0.0', got '%s'", defaults["RELEASE_LABEL"])
	}
	if defaults["INSTANCE_TYPE"] != "m5.xlarge" {
		t.Errorf("Expected INSTANCE_TYPE default 'm5.xlarge', got '%s'", defaults["INSTANCE_TYPE"])
	}
	if defaults["CLEANUP"] != "false" {
		t.Errorf("Expected CLEANUP default 'false', got '%s'", defaults["CLEANUP"])
	}
}

func TestEMRPassrolePathInfo(t *testing.T) {
	mod := emr_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if pathInfo.Author != "Seth Art" {
		t.Errorf("Expected author 'Seth Art', got '%s'", pathInfo.Author)
	}

	if len(pathInfo.Permissions.Required) == 0 {
		t.Error("Expected at least one required permission")
	}

	// Verify iam:PassRole and elasticmapreduce:RunJobFlow are required
	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}
	if !requiredPerms["iam:PassRole"] {
		t.Error("Expected iam:PassRole in required permissions")
	}
	if !requiredPerms["elasticmapreduce:RunJobFlow"] {
		t.Error("Expected elasticmapreduce:RunJobFlow in required permissions")
	}
}

func TestEMRPassroleAliases(t *testing.T) {
	mod := emr_passrole.NewModule()
	pathInfo := mod.PathInfo()

	aliases := map[string]bool{}
	for _, alias := range pathInfo.Aliases {
		aliases[alias] = true
	}

	if !aliases["emr-passrole"] {
		t.Error("Expected 'emr-passrole' alias")
	}
	if !aliases["exploit/emr_passrole"] {
		t.Error("Expected 'exploit/emr_passrole' alias")
	}
}

func TestEMRPassrolePayloads(t *testing.T) {
	mod := emr_passrole.NewModule()

	// Module should list available payloads
	payloadList := mod.ListPayloads()
	if len(payloadList) == 0 {
		t.Error("Expected at least one payload")
	}

	// backdoor/attach-policy should be available
	found := false
	for _, p := range payloadList {
		if p.Name == "backdoor/attach-policy" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected backdoor/attach-policy payload to be available")
	}
}

func TestEMRPassroleDiscoverableOptions(t *testing.T) {
	mod := emr_passrole.NewModule()

	// Verify DiscoverableOptions are set
	discoverableOpts := mod.DiscoverableOptions()
	if len(discoverableOpts) == 0 {
		t.Error("Expected at least one discoverable option")
	}

	// Should support INSTANCE_PROFILE and SERVICE_ROLE discovery
	found := map[string]bool{}
	for _, opt := range discoverableOpts {
		found[opt] = true
	}
	if !found["INSTANCE_PROFILE"] {
		t.Error("Expected INSTANCE_PROFILE to be discoverable")
	}
	if !found["SERVICE_ROLE"] {
		t.Error("Expected SERVICE_ROLE to be discoverable")
	}
}

func TestEMRPassroleMITRE(t *testing.T) {
	mod := emr_passrole.NewModule()
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
