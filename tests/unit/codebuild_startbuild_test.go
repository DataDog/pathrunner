// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/codebuild_startbuild"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/codebuild"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"testing"
)

func TestCodeBuildStartBuildModuleInit(t *testing.T) {
	mod := codebuild_startbuild.NewModule()

	if mod.Name() != "codebuild-002" {
		t.Errorf("Expected name 'codebuild-002', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "codebuild-002" {
		t.Errorf("Expected ID 'codebuild-002', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestCodeBuildStartBuildDescription(t *testing.T) {
	mod := codebuild_startbuild.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestCodeBuildStartBuildServices(t *testing.T) {
	mod := codebuild_startbuild.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"codebuild": true, "iam": true}
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

func TestCodeBuildStartBuildOptions(t *testing.T) {
	mod := codebuild_startbuild.NewModule()
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

	// PROJECT_NAME and PAYLOAD are required
	if !requiredOptions["PROJECT_NAME"] {
		t.Error("Expected PROJECT_NAME to be required")
	}
	if !requiredOptions["PAYLOAD"] {
		t.Error("Expected PAYLOAD to be required")
	}

	// These should be optional
	expectedOptional := []string{"TARGET_USER", "REGION", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestCodeBuildStartBuildCleanupDefaultFalse(t *testing.T) {
	mod := codebuild_startbuild.NewModule()
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

func TestCodeBuildStartBuildPermissions(t *testing.T) {
	mod := codebuild_startbuild.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	if !requiredPerms["codebuild:StartBuild"] {
		t.Error("Missing required permission: codebuild:StartBuild")
	}
}

func TestCodeBuildStartBuildAliases(t *testing.T) {
	mod := codebuild_startbuild.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["codebuild-startbuild"] {
		t.Error("Expected alias 'codebuild-startbuild'")
	}
}

func TestCodeBuildStartBuildDiscoverableOptions(t *testing.T) {
	mod := codebuild_startbuild.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	opts := discoverable.DiscoverableOptions()
	if len(opts) != 1 || opts[0] != "PROJECT_NAME" {
		t.Errorf("Expected DiscoverableOptions to return ['PROJECT_NAME'], got %v", opts)
	}
}

func TestCodeBuildStartBuildRegistration(t *testing.T) {
	mod, err := modules.LoadModule("codebuild-002")
	if err != nil {
		t.Fatalf("Expected module 'codebuild-002' to be registered: %v", err)
	}
	if mod.Name() != "codebuild-002" {
		t.Errorf("Expected name 'codebuild-002', got '%s'", mod.Name())
	}
}

func TestCodeBuildStartBuildAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("codebuild-startbuild")
	if err != nil {
		t.Fatalf("Expected alias 'codebuild-startbuild' to be registered: %v", err)
	}
	if mod.Name() != "codebuild-002" {
		t.Errorf("Expected name 'codebuild-002' via alias, got '%s'", mod.Name())
	}
}

func TestCodeBuildStartBuildPayloadCompatible(t *testing.T) {
	mod := codebuild_startbuild.NewModule()

	// Module should list CodeBuild payloads from the registry
	payloadList := mod.ListPayloads()
	if len(payloadList) == 0 {
		t.Error("Expected at least one CodeBuild payload registered")
	}

	// Verify compatible tags
	compatible, ok := interface{}(mod).(modules.PayloadCompatible)
	if !ok {
		t.Fatal("Expected module to implement PayloadCompatible interface")
	}

	tags := compatible.GetCompatibleTags()
	hasCodeBuild := false
	for _, tag := range tags {
		if tag == "codebuild" {
			hasCodeBuild = true
		}
	}
	if !hasCodeBuild {
		t.Error("Expected compatible tags to include 'codebuild'")
	}

	ctx := compatible.GetPayloadContext()
	if ctx != "codebuild" {
		t.Errorf("Expected payload context 'codebuild', got '%s'", ctx)
	}
}

func TestCodeBuildStartBuildExecuteUnknownPayload(t *testing.T) {
	mod := codebuild_startbuild.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"PROJECT_NAME": "my-project",
			"PAYLOAD":      "nonexistent/payload",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error with unknown payload type")
	}
	if err != nil && !contains(err.Error(), "unknown payload type") {
		t.Errorf("Expected error about unknown payload type, got: %v", err)
	}
}

func TestCodeBuildStartBuildMITRE(t *testing.T) {
	mod := codebuild_startbuild.NewModule()
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

func TestCodeBuildStartBuildReferences(t *testing.T) {
	mod := codebuild_startbuild.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/codebuild-002") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for codebuild-002")
	}
}

func TestCodeBuildBackdoorAttachPolicyPayload(t *testing.T) {
	pl, err := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceCodeBuild)
	if err != nil {
		t.Fatalf("Expected backdoor/attach-policy payload to be registered: %v", err)
	}

	opts := map[string]string{
		"TARGET_USER": "test-user",
		"POLICY_ARN":  "arn:aws:iam::aws:policy/AdministratorAccess",
	}

	if err := pl.Validate(opts); err != nil {
		t.Fatalf("Expected payload validation to pass: %v", err)
	}

	code, err := pl.GenerateCode(opts)
	if err != nil {
		t.Fatalf("Expected code generation to succeed: %v", err)
	}

	// The generated code should be a buildspec YAML.
	if !contains(code, "test-user") {
		t.Error("Expected buildspec to contain TARGET_USER")
	}
	if !contains(code, "arn:aws:iam::aws:policy/AdministratorAccess") {
		t.Error("Expected buildspec to contain POLICY_ARN")
	}
	if !contains(code, "version: 0.2") {
		t.Error("Expected buildspec to contain 'version: 0.2'")
	}
	if !contains(code, "attach-user-policy") {
		t.Error("Expected buildspec to contain 'attach-user-policy' command")
	}
}

func TestCodeBuildBackdoorAttachPolicyDefaultPolicyArn(t *testing.T) {
	pl, err := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceCodeBuild)
	if err != nil {
		t.Fatalf("Expected backdoor/attach-policy payload to be registered: %v", err)
	}

	// Empty POLICY_ARN should default to AdministratorAccess.
	opts := map[string]string{
		"TARGET_USER": "test-user",
		"POLICY_ARN":  "",
	}

	code, err := pl.GenerateCode(opts)
	if err != nil {
		t.Fatalf("Expected code generation to succeed: %v", err)
	}

	if !contains(code, "AdministratorAccess") {
		t.Error("Expected buildspec to default to AdministratorAccess policy")
	}
}

func TestCodeBuildBackdoorAttachPolicyValidateMissingUser(t *testing.T) {
	pl, err := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceCodeBuild)
	if err != nil {
		t.Fatalf("Expected backdoor/attach-policy payload to be registered: %v", err)
	}

	if err := pl.Validate(map[string]string{"TARGET_USER": ""}); err == nil {
		t.Error("Expected validation to fail when TARGET_USER is empty")
	}
}

func TestCodeBuildBackdoorAttachPolicySideEffects(t *testing.T) {
	pl, err := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceCodeBuild)
	if err != nil {
		t.Fatalf("Expected backdoor/attach-policy payload to be registered: %v", err)
	}

	reporter, ok := pl.(payloads.SideEffectReporter)
	if !ok {
		t.Fatal("Expected backdoor/attach-policy to implement SideEffectReporter")
	}

	opts := map[string]string{
		"TARGET_USER": "test-user",
		"POLICY_ARN":  "arn:aws:iam::aws:policy/AdministratorAccess",
	}

	effects := reporter.ReportSideEffects(opts)
	if len(effects) == 0 {
		t.Error("Expected at least one side effect")
	}

	found := false
	for _, effect := range effects {
		if effect.Type == "iam:attached-policy" {
			found = true
			if effect.CleanupMethod != "iam:DetachUserPolicy" {
				t.Errorf("Expected cleanup method 'iam:DetachUserPolicy', got '%s'", effect.CleanupMethod)
			}
		}
	}
	if !found {
		t.Error("Expected side effect of type 'iam:attached-policy'")
	}
}

func TestCodeBuildBackdoorAttachPolicyVerifiable(t *testing.T) {
	pl, err := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceCodeBuild)
	if err != nil {
		t.Fatalf("Expected backdoor/attach-policy payload to be registered: %v", err)
	}

	_, ok := pl.(payloads.Verifiable)
	if !ok {
		t.Error("Expected backdoor/attach-policy to implement Verifiable interface")
	}
}
