package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/ec2_passrole_requestspotinstances"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/ec2"
	"testing"
)

func TestEc2PassroleRequestSpotInstancesModuleInit(t *testing.T) {
	mod := ec2_passrole_requestspotinstances.NewModule()

	if mod.Name() != "ec2-004" {
		t.Errorf("Expected name 'ec2-004', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ec2-004" {
		t.Errorf("Expected ID 'ec2-004', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestEc2PassroleRequestSpotInstancesDescription(t *testing.T) {
	mod := ec2_passrole_requestspotinstances.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestEc2PassroleRequestSpotInstancesServices(t *testing.T) {
	mod := ec2_passrole_requestspotinstances.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "ec2": true}
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

func TestEc2PassroleRequestSpotInstancesOptions(t *testing.T) {
	mod := ec2_passrole_requestspotinstances.NewModule()
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

	// INSTANCE_PROFILE and PAYLOAD are required.
	if !requiredOptions["INSTANCE_PROFILE"] {
		t.Error("Expected INSTANCE_PROFILE to be required")
	}
	if !requiredOptions["PAYLOAD"] {
		t.Error("Expected PAYLOAD to be required")
	}

	// These should be optional.
	expectedOptional := []string{"REGION", "AMI_ID", "INSTANCE_TYPE", "SPOT_PRICE", "SUBNET_ID", "SPOT_WAIT_TIMEOUT", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestEc2PassroleRequestSpotInstancesPermissions(t *testing.T) {
	mod := ec2_passrole_requestspotinstances.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "ec2:RequestSpotInstances"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestEc2PassroleRequestSpotInstancesAliases(t *testing.T) {
	mod := ec2_passrole_requestspotinstances.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["ec2-passrole-spot"] {
		t.Error("Expected alias 'ec2-passrole-spot'")
	}
}

func TestEc2PassroleRequestSpotInstancesDiscoverableOptions(t *testing.T) {
	mod := ec2_passrole_requestspotinstances.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	optionSet := map[string]bool{}
	for _, opt := range options {
		optionSet[opt] = true
	}

	if !optionSet["INSTANCE_PROFILE"] {
		t.Error("Expected INSTANCE_PROFILE in discoverable options")
	}
	if !optionSet["SUBNET_ID"] {
		t.Error("Expected SUBNET_ID in discoverable options")
	}
}

func TestEc2PassroleRequestSpotInstancesRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ec2-004")
	if err != nil {
		t.Fatalf("Expected module 'ec2-004' to be registered: %v", err)
	}
	if mod.Name() != "ec2-004" {
		t.Errorf("Expected name 'ec2-004', got '%s'", mod.Name())
	}
}

func TestEc2PassroleRequestSpotInstancesAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ec2-passrole-spot")
	if err != nil {
		t.Fatalf("Expected alias 'ec2-passrole-spot' to be registered: %v", err)
	}
	if mod.Name() != "ec2-004" {
		t.Errorf("Expected name 'ec2-004' via alias, got '%s'", mod.Name())
	}
}

func TestEc2PassroleRequestSpotInstancesPayloadCompatible(t *testing.T) {
	mod := ec2_passrole_requestspotinstances.NewModule()

	payloadList := mod.ListPayloads()
	if len(payloadList) == 0 {
		t.Error("Expected at least one EC2 payload registered")
	}

	compatible, ok := interface{}(mod).(modules.PayloadCompatible)
	if !ok {
		t.Fatal("Expected module to implement PayloadCompatible interface")
	}

	tags := compatible.GetCompatibleTags()
	hasEC2 := false
	for _, tag := range tags {
		if tag == "ec2" {
			hasEC2 = true
		}
	}
	if !hasEC2 {
		t.Error("Expected compatible tags to include 'ec2'")
	}

	ctx := compatible.GetPayloadContext()
	if ctx != "ec2" {
		t.Errorf("Expected payload context 'ec2', got '%s'", ctx)
	}
}

func TestEc2PassroleRequestSpotInstancesExecuteInvalidPayload(t *testing.T) {
	mod := ec2_passrole_requestspotinstances.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"INSTANCE_PROFILE": "some-instance-profile",
			"PAYLOAD":          "nonexistent/payload",
		},
		AttackerIdentity: nil,
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error with invalid payload type")
	}
	if err != nil && !contains(err.Error(), "unknown payload type") {
		t.Errorf("Expected error about unknown payload type, got: %v", err)
	}
}

func TestEc2PassroleRequestSpotInstancesMITRE(t *testing.T) {
	mod := ec2_passrole_requestspotinstances.NewModule()
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

func TestEc2PassroleRequestSpotInstancesReferences(t *testing.T) {
	mod := ec2_passrole_requestspotinstances.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/ec2-004") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for ec2-004")
	}
}

func TestEc2PassroleRequestSpotInstancesCleanupDefaultFalse(t *testing.T) {
	mod := ec2_passrole_requestspotinstances.NewModule()
	options := mod.Options()

	for _, opt := range options {
		if opt.Name == "CLEANUP" {
			if opt.Default != "false" {
				t.Errorf("Expected CLEANUP default to be 'false' (starting user lacks termination permissions), got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("Expected CLEANUP option to be present")
}
