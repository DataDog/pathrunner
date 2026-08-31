// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/codebuild_passrole_startbuildbatch"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/codebuild"
	"testing"
)

func TestCodeBuildPassroleStartBuildBatchModuleInit(t *testing.T) {
	mod := codebuild_passrole_startbuildbatch.NewModule()

	if mod.Name() != "codebuild-004" {
		t.Errorf("Expected name 'codebuild-004', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "codebuild-004" {
		t.Errorf("Expected ID 'codebuild-004', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestCodeBuildPassroleStartBuildBatchDescription(t *testing.T) {
	mod := codebuild_passrole_startbuildbatch.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestCodeBuildPassroleStartBuildBatchServices(t *testing.T) {
	mod := codebuild_passrole_startbuildbatch.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "codebuild": true}
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

func TestCodeBuildPassroleStartBuildBatchOptions(t *testing.T) {
	mod := codebuild_passrole_startbuildbatch.NewModule()
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
	expectedOptional := []string{"TARGET_ARN", "REGION", "PROJECT_NAME", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestCodeBuildPassroleStartBuildBatchPermissions(t *testing.T) {
	mod := codebuild_passrole_startbuildbatch.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuildBatch"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestCodeBuildPassroleStartBuildBatchAliases(t *testing.T) {
	mod := codebuild_passrole_startbuildbatch.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["codebuild-passrole-startbuildbatch"] {
		t.Error("Expected alias 'codebuild-passrole-startbuildbatch'")
	}
}

func TestCodeBuildPassroleStartBuildBatchDiscoverableOptions(t *testing.T) {
	mod := codebuild_passrole_startbuildbatch.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	if len(options) != 1 || options[0] != "ROLE_ARN" {
		t.Errorf("Expected DiscoverableOptions to return ['ROLE_ARN'], got %v", options)
	}
}

func TestCodeBuildPassroleStartBuildBatchRegistration(t *testing.T) {
	mod, err := modules.LoadModule("codebuild-004")
	if err != nil {
		t.Fatalf("Expected module 'codebuild-004' to be registered: %v", err)
	}
	if mod.Name() != "codebuild-004" {
		t.Errorf("Expected name 'codebuild-004', got '%s'", mod.Name())
	}
}

func TestCodeBuildPassroleStartBuildBatchAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("codebuild-passrole-startbuildbatch")
	if err != nil {
		t.Fatalf("Expected alias 'codebuild-passrole-startbuildbatch' to be registered: %v", err)
	}
	if mod.Name() != "codebuild-004" {
		t.Errorf("Expected name 'codebuild-004' via alias, got '%s'", mod.Name())
	}
}

func TestCodeBuildPassroleStartBuildBatchPayloadCompatible(t *testing.T) {
	mod := codebuild_passrole_startbuildbatch.NewModule()

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

func TestCodeBuildPassroleStartBuildBatchExecuteInvalidPayload(t *testing.T) {
	mod := codebuild_passrole_startbuildbatch.NewModule()

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
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error with invalid payload type")
	}
	if err != nil && !containsSBB(err.Error(), "unknown payload type") {
		t.Errorf("Expected error about unknown payload type, got: %v", err)
	}
}

func TestCodeBuildPassroleStartBuildBatchMITRE(t *testing.T) {
	mod := codebuild_passrole_startbuildbatch.NewModule()
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

func TestCodeBuildPassroleStartBuildBatchReferences(t *testing.T) {
	mod := codebuild_passrole_startbuildbatch.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if containsSBB(ref.URL, "pathfinding.cloud/paths/codebuild-004") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for codebuild-004")
	}
}

func TestCodeBuildPassroleStartBuildBatchRelatedPaths(t *testing.T) {
	mod := codebuild_passrole_startbuildbatch.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.RelatedPaths) == 0 {
		t.Error("Expected at least one related path")
	}

	relatedSet := map[string]bool{}
	for _, rp := range pathInfo.RelatedPaths {
		relatedSet[rp] = true
	}

	if !relatedSet["codebuild-001"] {
		t.Error("Expected codebuild-001 in related paths")
	}
}

func containsSBB(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
