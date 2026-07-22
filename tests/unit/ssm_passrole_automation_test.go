// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/ssm_passrole_automation"
	"github.com/DataDog/pathrunner/pkg/modules"
	"strings"
	"testing"
)

func TestSSMPassroleAutomationModuleInit(t *testing.T) {
	mod := ssm_passrole_automation.NewModule()

	if mod.Name() != "ssm-003" {
		t.Errorf("Expected name 'ssm-003', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ssm-003" {
		t.Errorf("Expected ID 'ssm-003', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestSSMPassroleAutomationDescription(t *testing.T) {
	mod := ssm_passrole_automation.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
	if !strings.Contains(desc, "AutomationAssumeRole") {
		t.Error("Expected description to mention AutomationAssumeRole")
	}
}

func TestSSMPassroleAutomationServices(t *testing.T) {
	mod := ssm_passrole_automation.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "ssm": true}
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

func TestSSMPassroleAutomationOptions(t *testing.T) {
	mod := ssm_passrole_automation.NewModule()
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

	// ROLE_ARN and PAYLOAD are required.
	for _, name := range []string{"ROLE_ARN", "PAYLOAD"} {
		if !requiredOptions[name] {
			t.Errorf("Expected %s to be required", name)
		}
	}

	// These should be optional.
	expectedOptional := []string{"DOCUMENT_NAME", "REGION", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestSSMPassroleAutomationCleanupDefaultFalse(t *testing.T) {
	mod := ssm_passrole_automation.NewModule()
	options := mod.Options()

	for _, opt := range options {
		if opt.Name == "CLEANUP" {
			if opt.Default != "false" {
				t.Errorf("Expected CLEANUP default to be 'false', got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("Expected CLEANUP option to exist")
}

func TestSSMPassroleAutomationPermissions(t *testing.T) {
	mod := ssm_passrole_automation.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "ssm:CreateDocument", "ssm:StartAutomationExecution"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestSSMPassroleAutomationAliases(t *testing.T) {
	mod := ssm_passrole_automation.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["ssm-passrole-automation"] {
		t.Error("Expected alias 'ssm-passrole-automation'")
	}
	if !aliasSet["exploit/ssm_passrole_automation"] {
		t.Error("Expected alias 'exploit/ssm_passrole_automation'")
	}
}

func TestSSMPassroleAutomationRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ssm-003")
	if err != nil {
		t.Fatalf("Expected module 'ssm-003' to be registered: %v", err)
	}
	if mod.Name() != "ssm-003" {
		t.Errorf("Expected name 'ssm-003', got '%s'", mod.Name())
	}
}

func TestSSMPassroleAutomationAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("ssm-passrole-automation")
	if err != nil {
		t.Fatalf("Expected alias 'ssm-passrole-automation' to be registered: %v", err)
	}
	if mod.Name() != "ssm-003" {
		t.Errorf("Expected name 'ssm-003' via alias, got '%s'", mod.Name())
	}
}

func TestSSMPassroleAutomationMITRE(t *testing.T) {
	mod := ssm_passrole_automation.NewModule()
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

func TestSSMPassroleAutomationReferences(t *testing.T) {
	mod := ssm_passrole_automation.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if strings.Contains(ref.URL, "pathfinding.cloud/paths/ssm-003") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for ssm-003")
	}
}

func TestSSMPassroleAutomationRelatedPaths(t *testing.T) {
	mod := ssm_passrole_automation.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.RelatedPaths) == 0 {
		t.Error("Expected at least one related path")
	}

	relatedSet := map[string]bool{}
	for _, p := range pathInfo.RelatedPaths {
		relatedSet[p] = true
	}

	if !relatedSet["ssm-001"] {
		t.Error("Expected 'ssm-001' in related paths")
	}
	if !relatedSet["ssm-002"] {
		t.Error("Expected 'ssm-002' in related paths")
	}
}

func TestSSMPassroleAutomationExecuteMissingRoleARN(t *testing.T) {
	mod := ssm_passrole_automation.NewModule()

	// Execute without ROLE_ARN should fail since it has no default. In practice
	// the module will try to call GetCallerIdentity and fail on network, but
	// validation happens before that.
	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			// ROLE_ARN intentionally omitted
			"PAYLOAD": "backdoor/attach-policy",
		},
	}

	// An empty ROLE_ARN will cause the SSM API call to fail.
	// The test verifies the module does not panic.
	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected an error when ROLE_ARN is empty (should fail on AWS API call)")
	}
}
