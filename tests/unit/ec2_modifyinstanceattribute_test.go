package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/ec2_modifyinstanceattribute"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/ec2"
	"testing"
)

func TestEC2ModifyInstanceAttributeModuleInit(t *testing.T) {
	mod := ec2_modifyinstanceattribute.NewModule()

	if mod.Name() != "ec2-002" {
		t.Errorf("Expected name 'ec2-002', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ec2-002" {
		t.Errorf("Expected ID 'ec2-002', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestEC2ModifyInstanceAttributeDescription(t *testing.T) {
	mod := ec2_modifyinstanceattribute.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestEC2ModifyInstanceAttributeServices(t *testing.T) {
	mod := ec2_modifyinstanceattribute.NewModule()
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

func TestEC2ModifyInstanceAttributeOptions(t *testing.T) {
	mod := ec2_modifyinstanceattribute.NewModule()
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

	// INSTANCE_ID and PAYLOAD are required
	if !requiredOptions["INSTANCE_ID"] {
		t.Error("Expected INSTANCE_ID to be required")
	}
	if !requiredOptions["PAYLOAD"] {
		t.Error("Expected PAYLOAD to be required")
	}

	// These should be optional
	expectedOptional := []string{"REGION", "WAIT_SECONDS", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestEC2ModifyInstanceAttributePermissions(t *testing.T) {
	mod := ec2_modifyinstanceattribute.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{
		"ec2:ModifyInstanceAttribute",
		"ec2:StopInstances",
		"ec2:StartInstances",
	}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestEC2ModifyInstanceAttributeAliases(t *testing.T) {
	mod := ec2_modifyinstanceattribute.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["ec2-modifyinstanceattribute"] {
		t.Error("Expected alias 'ec2-modifyinstanceattribute'")
	}
}

func TestEC2ModifyInstanceAttributeDiscoverableOptions(t *testing.T) {
	mod := ec2_modifyinstanceattribute.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	optionSet := map[string]bool{}
	for _, opt := range options {
		optionSet[opt] = true
	}

	if !optionSet["INSTANCE_ID"] {
		t.Error("Expected INSTANCE_ID in discoverable options")
	}
}

func TestEC2ModifyInstanceAttributeRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ec2-002")
	if err != nil {
		t.Fatalf("Expected module 'ec2-002' to be registered: %v", err)
	}
	if mod.Name() != "ec2-002" {
		t.Errorf("Expected name 'ec2-002', got '%s'", mod.Name())
	}
}

func TestEC2ModifyInstanceAttributeAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ec2-modifyinstanceattribute")
	if err != nil {
		t.Fatalf("Expected alias 'ec2-modifyinstanceattribute' to be registered: %v", err)
	}
	if mod.Name() != "ec2-002" {
		t.Errorf("Expected name 'ec2-002' via alias, got '%s'", mod.Name())
	}
}

func TestEC2ModifyInstanceAttributePayloadCompatible(t *testing.T) {
	mod := ec2_modifyinstanceattribute.NewModule()

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

func TestEC2ModifyInstanceAttributeExecuteInvalidPayload(t *testing.T) {
	mod := ec2_modifyinstanceattribute.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"INSTANCE_ID": "i-0abc1234567890def",
			"PAYLOAD":     "nonexistent/payload",
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

func TestEC2ModifyInstanceAttributeMITRE(t *testing.T) {
	mod := ec2_modifyinstanceattribute.NewModule()
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

func TestEC2ModifyInstanceAttributeReferences(t *testing.T) {
	mod := ec2_modifyinstanceattribute.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/ec2-002") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference")
	}
}
