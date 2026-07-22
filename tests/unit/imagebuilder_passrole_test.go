// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/imagebuilder_passrole"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/imagebuilder"
	"testing"
)

func TestImagebuilderPassroleModuleInit(t *testing.T) {
	mod := imagebuilder_passrole.NewModule()

	if mod.Name() != "imagebuilder-001" {
		t.Errorf("Expected name 'imagebuilder-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "imagebuilder-001" {
		t.Errorf("Expected ID 'imagebuilder-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestImagebuilderPassroleDescription(t *testing.T) {
	mod := imagebuilder_passrole.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestImagebuilderPassroleServices(t *testing.T) {
	mod := imagebuilder_passrole.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "imagebuilder": true, "ec2": true}
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

func TestImagebuilderPassroleOptions(t *testing.T) {
	mod := imagebuilder_passrole.NewModule()
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

	// INSTANCE_PROFILE and PAYLOAD are required
	expectedRequired := []string{"INSTANCE_PROFILE", "PAYLOAD"}
	for _, name := range expectedRequired {
		if !requiredOptions[name] {
			t.Errorf("Expected %s to be required", name)
		}
	}

	// REGION, SUBNET_ID, SECURITY_GROUP_ID, TARGET_USER, POLICY_ARN, CLEANUP are optional
	expectedOptional := []string{"REGION", "SUBNET_ID", "SECURITY_GROUP_ID", "TARGET_USER", "POLICY_ARN", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestImagebuilderPassrolePermissions(t *testing.T) {
	mod := imagebuilder_passrole.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{
		"iam:PassRole",
		"imagebuilder:CreateComponent",
		"imagebuilder:CreateImageRecipe",
		"imagebuilder:CreateInfrastructureConfiguration",
		"imagebuilder:CreateImage",
	}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestImagebuilderPassroleAliases(t *testing.T) {
	mod := imagebuilder_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["imagebuilder-passrole"] {
		t.Error("Expected alias 'imagebuilder-passrole'")
	}
	if !aliasSet["exploit/imagebuilder_passrole"] {
		t.Error("Expected alias 'exploit/imagebuilder_passrole'")
	}
}

func TestImagebuilderPassroleDiscoverableOptions(t *testing.T) {
	mod := imagebuilder_passrole.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	expectedDiscoverable := map[string]bool{
		"INSTANCE_PROFILE":  true,
		"SUBNET_ID":         true,
		"SECURITY_GROUP_ID": true,
	}

	for _, opt := range options {
		if !expectedDiscoverable[opt] {
			t.Errorf("Unexpected discoverable option: %s", opt)
		}
		delete(expectedDiscoverable, opt)
	}
	for opt := range expectedDiscoverable {
		t.Errorf("Missing discoverable option: %s", opt)
	}
}

func TestImagebuilderPassroleRegistration(t *testing.T) {
	mod, err := modules.LoadModule("imagebuilder-001")
	if err != nil {
		t.Fatalf("Expected module 'imagebuilder-001' to be registered: %v", err)
	}
	if mod.Name() != "imagebuilder-001" {
		t.Errorf("Expected name 'imagebuilder-001', got '%s'", mod.Name())
	}
}

func TestImagebuilderPassroleAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("imagebuilder-passrole")
	if err != nil {
		t.Fatalf("Expected alias 'imagebuilder-passrole' to be registered: %v", err)
	}
	if mod.Name() != "imagebuilder-001" {
		t.Errorf("Expected name 'imagebuilder-001' via alias, got '%s'", mod.Name())
	}
}

func TestImagebuilderPassrolePayloadCompatible(t *testing.T) {
	mod := imagebuilder_passrole.NewModule()

	payloadList := mod.ListPayloads()
	if len(payloadList) == 0 {
		t.Error("Expected at least one imagebuilder payload registered")
	}

	compatible, ok := interface{}(mod).(modules.PayloadCompatible)
	if !ok {
		t.Fatal("Expected module to implement PayloadCompatible interface")
	}

	tags := compatible.GetCompatibleTags()
	hasImageBuilder := false
	for _, tag := range tags {
		if tag == "imagebuilder" {
			hasImageBuilder = true
		}
	}
	if !hasImageBuilder {
		t.Error("Expected compatible tags to include 'imagebuilder'")
	}

	ctx := compatible.GetPayloadContext()
	if ctx != "imagebuilder" {
		t.Errorf("Expected payload context 'imagebuilder', got '%s'", ctx)
	}
}

func TestImagebuilderPassroleExecuteInvalidPayload(t *testing.T) {
	mod := imagebuilder_passrole.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"INSTANCE_PROFILE": "admin-instance-profile",
			"PAYLOAD":          "nonexistent/payload",
			"TARGET_USER":      "test-user",
		},
		AttackerIdentity: nil,
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error with invalid payload type")
	}
	if err != nil && !containsStr(err.Error(), "unknown payload type") {
		t.Errorf("Expected error about unknown payload type, got: %v", err)
	}
}

func TestImagebuilderPassroleMITRE(t *testing.T) {
	mod := imagebuilder_passrole.NewModule()
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

func TestImagebuilderPassroleReferences(t *testing.T) {
	mod := imagebuilder_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if containsStr(ref.URL, "pathfinding.cloud/paths/imagebuilder-001") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for imagebuilder-001")
	}
}

func TestImagebuilderPassrolePrerequisites(t *testing.T) {
	mod := imagebuilder_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected admin prerequisites")
	}
	if len(pathInfo.Prerequisites.Lateral) == 0 {
		t.Error("Expected lateral prerequisites")
	}

	// Should mention instance profile requirement
	foundInstanceProfileReq := false
	for _, prereq := range pathInfo.Prerequisites.Admin {
		if containsStr(prereq, "instance profile") {
			foundInstanceProfileReq = true
		}
	}
	if !foundInstanceProfileReq {
		t.Error("Expected admin prerequisites to mention instance profile requirement")
	}
}

func TestImagebuilderBackdoorPayloadGeneration(t *testing.T) {
	// Verify the payload generates valid component YAML containing the target user
	mod := imagebuilder_passrole.NewModule()
	payloads := mod.ListPayloads()

	found := false
	for _, p := range payloads {
		if p.Name == "backdoor/attach-policy" {
			found = true
		}
	}
	if !found {
		t.Error("Expected backdoor/attach-policy in imagebuilder payload list")
	}
}
