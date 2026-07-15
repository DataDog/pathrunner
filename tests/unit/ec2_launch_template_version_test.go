package unit

import (
	"pathrunner/pkg/exploits/ec2_launch_template_version"
	"pathrunner/pkg/modules"
	_ "pathrunner/pkg/payloads/ec2"
	"testing"
)

func TestEC2LaunchTemplateVersionModuleInit(t *testing.T) {
	mod := ec2_launch_template_version.NewModule()

	if mod.Name() != "ec2-005" {
		t.Errorf("Expected name 'ec2-005', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ec2-005" {
		t.Errorf("Expected ID 'ec2-005', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestEC2LaunchTemplateVersionDescription(t *testing.T) {
	mod := ec2_launch_template_version.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestEC2LaunchTemplateVersionServices(t *testing.T) {
	mod := ec2_launch_template_version.NewModule()
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

func TestEC2LaunchTemplateVersionOptions(t *testing.T) {
	mod := ec2_launch_template_version.NewModule()
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

	// LAUNCH_TEMPLATE_NAME, ASG_NAME, INSTANCE_PROFILE, and PAYLOAD are required
	for _, name := range []string{"LAUNCH_TEMPLATE_NAME", "ASG_NAME", "INSTANCE_PROFILE", "PAYLOAD"} {
		if !requiredOptions[name] {
			t.Errorf("Expected %s to be required", name)
		}
	}

	// These should be optional
	expectedOptional := []string{"TARGET_ARN", "REGION", "WAIT_FOR_POLICY", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestEC2LaunchTemplateVersionCleanupDefaultFalse(t *testing.T) {
	mod := ec2_launch_template_version.NewModule()

	for _, opt := range mod.Options() {
		if opt.Name == "CLEANUP" {
			if opt.Default != "false" {
				t.Errorf("Expected CLEANUP default to be 'false', got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("CLEANUP option not found")
}

func TestEC2LaunchTemplateVersionPermissions(t *testing.T) {
	mod := ec2_launch_template_version.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"ec2:CreateLaunchTemplateVersion", "ec2:ModifyLaunchTemplate", "autoscaling:SetDesiredCapacity"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestEC2LaunchTemplateVersionAliases(t *testing.T) {
	mod := ec2_launch_template_version.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["ec2-launch-template-version"] {
		t.Error("Expected alias 'ec2-launch-template-version'")
	}
}

func TestEC2LaunchTemplateVersionDiscoverableOptions(t *testing.T) {
	mod := ec2_launch_template_version.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	optionSet := map[string]bool{}
	for _, opt := range options {
		optionSet[opt] = true
	}

	if !optionSet["LAUNCH_TEMPLATE_NAME"] {
		t.Error("Expected LAUNCH_TEMPLATE_NAME in discoverable options")
	}
	if !optionSet["ASG_NAME"] {
		t.Error("Expected ASG_NAME in discoverable options")
	}
}

func TestEC2LaunchTemplateVersionRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ec2-005")
	if err != nil {
		t.Fatalf("Expected module 'ec2-005' to be registered: %v", err)
	}
	if mod.Name() != "ec2-005" {
		t.Errorf("Expected name 'ec2-005', got '%s'", mod.Name())
	}
}

func TestEC2LaunchTemplateVersionAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ec2-launch-template-version")
	if err != nil {
		t.Fatalf("Expected alias 'ec2-launch-template-version' to be registered: %v", err)
	}
	if mod.Name() != "ec2-005" {
		t.Errorf("Expected name 'ec2-005' via alias, got '%s'", mod.Name())
	}
}

func TestEC2LaunchTemplateVersionPayloadCompatible(t *testing.T) {
	mod := ec2_launch_template_version.NewModule()

	// Module should list ec2 payloads from the registry
	payloadList := mod.ListPayloads()
	if len(payloadList) == 0 {
		t.Error("Expected at least one EC2 payload registered")
	}

	// Verify compatible tags
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

func TestEC2LaunchTemplateVersionExecuteInvalidPayload(t *testing.T) {
	mod := ec2_launch_template_version.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"LAUNCH_TEMPLATE_NAME": "test-template",
			"PAYLOAD":              "nonexistent/payload",
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

func TestEC2LaunchTemplateVersionMITRE(t *testing.T) {
	mod := ec2_launch_template_version.NewModule()
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

func TestEC2LaunchTemplateVersionReferences(t *testing.T) {
	mod := ec2_launch_template_version.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/ec2-005") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for ec2-005")
	}
}

func TestEC2LaunchTemplateVersionRelatedPaths(t *testing.T) {
	mod := ec2_launch_template_version.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.RelatedPaths) == 0 {
		t.Error("Expected related paths to be set")
	}

	hasEC2002 := false
	for _, p := range pathInfo.RelatedPaths {
		if p == "ec2-002" {
			hasEC2002 = true
		}
	}
	if !hasEC2002 {
		t.Error("Expected 'ec2-002' in related paths")
	}
}

func TestEC2LaunchTemplateVersionWaitForPolicyDefault(t *testing.T) {
	mod := ec2_launch_template_version.NewModule()

	for _, opt := range mod.Options() {
		if opt.Name == "WAIT_FOR_POLICY" {
			if opt.Default != "true" {
				t.Errorf("Expected WAIT_FOR_POLICY default to be 'true', got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("WAIT_FOR_POLICY option not found")
}
