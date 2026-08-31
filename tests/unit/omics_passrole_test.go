// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/omics_passrole"
	"github.com/DataDog/pathrunner/pkg/modules"
	"strings"
	"testing"
)

func TestOmicsPassroleModuleInit(t *testing.T) {
	mod := omics_passrole.NewModule()

	if mod.Name() != "omics-001" {
		t.Errorf("Expected name 'omics-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "omics-001" {
		t.Errorf("Expected ID 'omics-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestOmicsPassroleDescription(t *testing.T) {
	mod := omics_passrole.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestOmicsPassroleServices(t *testing.T) {
	mod := omics_passrole.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "omics": true, "s3": true}
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

func TestOmicsPassroleOptions(t *testing.T) {
	mod := omics_passrole.NewModule()
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

	// ROLE_ARN and CONTAINER_URI are required
	if !requiredOptions["ROLE_ARN"] {
		t.Error("Expected ROLE_ARN to be required")
	}
	if !requiredOptions["CONTAINER_URI"] {
		t.Error("Expected CONTAINER_URI to be required")
	}

	// These should be optional
	expectedOptional := []string{"EXFIL_BUCKET", "EXFIL_KEY", "TARGET_ARN", "REGION", "WORKFLOW_NAME", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestOmicsPassrolePermissions(t *testing.T) {
	mod := omics_passrole.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "omics:CreateWorkflow", "omics:StartRun", "s3:GetObject"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestOmicsPassroleAliases(t *testing.T) {
	mod := omics_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["omics-passrole"] {
		t.Error("Expected alias 'omics-passrole'")
	}
	if !aliasSet["exploit/omics_passrole"] {
		t.Error("Expected alias 'exploit/omics_passrole'")
	}
}

func TestOmicsPassroleDiscoverableOptions(t *testing.T) {
	mod := omics_passrole.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	if len(options) != 1 || options[0] != "ROLE_ARN" {
		t.Errorf("Expected DiscoverableOptions to return ['ROLE_ARN'], got %v", options)
	}
}

func TestOmicsPassroleRegistration(t *testing.T) {
	mod, err := modules.LoadModule("omics-001")
	if err != nil {
		t.Fatalf("Expected module 'omics-001' to be registered: %v", err)
	}
	if mod.Name() != "omics-001" {
		t.Errorf("Expected name 'omics-001', got '%s'", mod.Name())
	}
}

func TestOmicsPassroleAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("omics-passrole")
	if err != nil {
		t.Fatalf("Expected alias 'omics-passrole' to be registered: %v", err)
	}
	if mod.Name() != "omics-001" {
		t.Errorf("Expected name 'omics-001' via alias, got '%s'", mod.Name())
	}
}

func TestOmicsPassroleMITRE(t *testing.T) {
	mod := omics_passrole.NewModule()
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

func TestOmicsPassroleReferences(t *testing.T) {
	mod := omics_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if strings.Contains(ref.URL, "pathfinding.cloud/paths/omics-001") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for omics-001")
	}
}

func TestOmicsPassroleExecuteRequiresConfig(t *testing.T) {
	mod := omics_passrole.NewModule()

	// Execute with minimal config and no real AWS credentials should fail.
	// The module may fail at EXFIL_BUCKET resolution (if no attacker infra deployed)
	// or at an AWS API call (empty credentials). Both are valid failure modes.
	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN":      "arn:aws:iam::123456789012:role/admin",
			"CONTAINER_URI": "123456789012.dkr.ecr.us-east-1.amazonaws.com/aws-cli:latest",
			"TARGET_ARN":   "victim-user",
			"EXFIL_BUCKET":  "test-bucket",
		},
		AttackerIdentity: nil,
	}

	// With mock identity (no real credentials), execution should fail at the AWS API layer.
	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when executing with mock (empty) credentials")
	}
}

func TestOmicsPassrolePrerequisites(t *testing.T) {
	mod := omics_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected at least one admin prerequisite")
	}

	// Check for key prerequisites about the execution role and ECR image.
	foundRolePre := false
	foundECRPre := false
	for _, prereq := range pathInfo.Prerequisites.Admin {
		if strings.Contains(prereq, "omics.amazonaws.com") {
			foundRolePre = true
		}
		if strings.Contains(strings.ToLower(prereq), "ecr") {
			foundECRPre = true
		}
	}
	if !foundRolePre {
		t.Error("Expected prerequisite mentioning omics.amazonaws.com trust relationship")
	}
	if !foundECRPre {
		t.Error("Expected prerequisite mentioning ECR container image")
	}
}
