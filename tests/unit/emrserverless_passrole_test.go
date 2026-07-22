// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/emrserverless_passrole"
	"github.com/DataDog/pathrunner/pkg/modules"
	"strings"
	"testing"
)

func TestEMRServerlessPassroleModuleInit(t *testing.T) {
	mod := emrserverless_passrole.NewModule()

	if mod.Name() != "emrserverless-001" {
		t.Errorf("Expected name 'emrserverless-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "emrserverless-001" {
		t.Errorf("Expected ID 'emrserverless-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestEMRServerlessPassroleDescription(t *testing.T) {
	mod := emrserverless_passrole.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestEMRServerlessPassroleServices(t *testing.T) {
	mod := emrserverless_passrole.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "emrserverless": true}
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

func TestEMRServerlessPassroleOptions(t *testing.T) {
	mod := emrserverless_passrole.NewModule()
	options := mod.Options()

	requiredOptions := map[string]bool{}
	optionalOptions := map[string]bool{}
	defaultValues := map[string]string{}

	for _, opt := range options {
		if opt.Required {
			requiredOptions[opt.Name] = true
		} else {
			optionalOptions[opt.Name] = true
		}
		if opt.Default != "" {
			defaultValues[opt.Name] = opt.Default
		}
	}

	// EXECUTION_ROLE_ARN is the only required option.
	if !requiredOptions["EXECUTION_ROLE_ARN"] {
		t.Error("Expected EXECUTION_ROLE_ARN to be required")
	}

	// Optional options.
	expectedOptional := []string{"TARGET_USER", "REGION", "APP_NAME", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}

	// REGION defaults to us-east-1.
	if defaultValues["REGION"] != "us-east-1" {
		t.Errorf("Expected REGION default 'us-east-1', got '%s'", defaultValues["REGION"])
	}

	// CLEANUP defaults to false because the starting user typically lacks DeleteApplication.
	if defaultValues["CLEANUP"] != "false" {
		t.Errorf("Expected CLEANUP default 'false', got '%s'", defaultValues["CLEANUP"])
	}
}

func TestEMRServerlessPassrolePermissions(t *testing.T) {
	mod := emrserverless_passrole.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "emr-serverless:CreateApplication", "emr-serverless:StartJobRun"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestEMRServerlessPassroleAliases(t *testing.T) {
	mod := emrserverless_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["emrserverless-passrole"] {
		t.Error("Expected alias 'emrserverless-passrole'")
	}
}

func TestEMRServerlessPassroleDiscoverableOptions(t *testing.T) {
	mod := emrserverless_passrole.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	if len(options) != 1 || options[0] != "EXECUTION_ROLE_ARN" {
		t.Errorf("Expected DiscoverableOptions to return ['EXECUTION_ROLE_ARN'], got %v", options)
	}
}

func TestEMRServerlessPassroleRegistration(t *testing.T) {
	mod, err := modules.LoadModule("emrserverless-001")
	if err != nil {
		t.Fatalf("Expected module 'emrserverless-001' to be registered: %v", err)
	}
	if mod.Name() != "emrserverless-001" {
		t.Errorf("Expected name 'emrserverless-001', got '%s'", mod.Name())
	}
}

func TestEMRServerlessPassroleAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("emrserverless-passrole")
	if err != nil {
		t.Fatalf("Expected alias 'emrserverless-passrole' to be registered: %v", err)
	}
	if mod.Name() != "emrserverless-001" {
		t.Errorf("Expected name 'emrserverless-001' via alias, got '%s'", mod.Name())
	}
}

func TestEMRServerlessPassroleMITRE(t *testing.T) {
	mod := emrserverless_passrole.NewModule()
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

func TestEMRServerlessPassroleReferences(t *testing.T) {
	mod := emrserverless_passrole.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if strings.Contains(ref.URL, "pathfinding.cloud/paths/emrserverless-001") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for emrserverless-001")
	}
}

func TestEMRServerlessPassroleExecuteMissingExecutionRole(t *testing.T) {
	mod := emrserverless_passrole.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options:          map[string]string{},
		AttackerIdentity: nil,
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when EXECUTION_ROLE_ARN is not set")
	}
}

func TestEMRServerlessPassroleExecuteMissingScriptBucket(t *testing.T) {
	mod := emrserverless_passrole.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"EXECUTION_ROLE_ARN": "arn:aws:iam::123456789012:role/admin",
			// No SCRIPT_BUCKET, no attacker identity (no code bucket)
		},
		AttackerIdentity: nil,
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when SCRIPT_BUCKET not set and no attacker identity")
	}
}

func TestEMRServerlessPassroleNotPayloadCompatible(t *testing.T) {
	mod := emrserverless_passrole.NewModule()

	// This module embeds the exploit script directly; it does NOT use the payload system.
	_, ok := interface{}(mod).(modules.PayloadCompatible)
	if ok {
		t.Error("emrserverless_passrole should NOT implement PayloadCompatible (script is embedded, not payload-driven)")
	}
}
