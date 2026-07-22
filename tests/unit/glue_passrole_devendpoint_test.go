// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/glue_passrole_devendpoint"
	"github.com/DataDog/pathrunner/pkg/modules"
	"testing"
)

func TestGluePassroleDevEndpointModuleInit(t *testing.T) {
	mod := glue_passrole_devendpoint.NewModule()

	if mod.Name() != "glue-001" {
		t.Errorf("Expected name 'glue-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "glue-001" {
		t.Errorf("Expected ID 'glue-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestGluePassroleDevEndpointDescription(t *testing.T) {
	mod := glue_passrole_devendpoint.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestGluePassroleDevEndpointServices(t *testing.T) {
	mod := glue_passrole_devendpoint.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "glue": true}
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

func TestGluePassroleDevEndpointOptions(t *testing.T) {
	mod := glue_passrole_devendpoint.NewModule()
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

	// ROLE_ARN is the only required option
	if !requiredOptions["ROLE_ARN"] {
		t.Error("Expected ROLE_ARN to be required")
	}

	// These should be optional
	expectedOptional := []string{"SSH_PUBLIC_KEY", "ENDPOINT_NAME", "GLUE_VERSION", "NUMBER_OF_NODES", "REGION", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestGluePassroleDevEndpointCleanupDefaultFalse(t *testing.T) {
	mod := glue_passrole_devendpoint.NewModule()
	options := mod.Options()

	for _, opt := range options {
		if opt.Name == "CLEANUP" {
			if opt.Default != "false" {
				t.Errorf("Expected CLEANUP default to be 'false' (dev endpoints bill by the hour), got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("CLEANUP option not found")
}

func TestGluePassroleDevEndpointPermissions(t *testing.T) {
	mod := glue_passrole_devendpoint.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "glue:CreateDevEndpoint"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestGluePassroleDevEndpointAliases(t *testing.T) {
	mod := glue_passrole_devendpoint.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}
	if !aliasSet["glue-passrole-devendpoint"] {
		t.Error("Expected alias 'glue-passrole-devendpoint'")
	}
}

func TestGluePassroleDevEndpointDiscoverableOptions(t *testing.T) {
	mod := glue_passrole_devendpoint.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	if len(options) != 1 || options[0] != "ROLE_ARN" {
		t.Errorf("Expected DiscoverableOptions to return ['ROLE_ARN'], got %v", options)
	}
}

func TestGluePassroleDevEndpointRegistration(t *testing.T) {
	// Module should be registered via init()
	mod, err := modules.LoadModule("glue-001")
	if err != nil {
		t.Fatalf("Expected module 'glue-001' to be registered: %v", err)
	}
	if mod.Name() != "glue-001" {
		t.Errorf("Expected name 'glue-001', got '%s'", mod.Name())
	}
}

func TestGluePassroleDevEndpointAliasRegistration(t *testing.T) {
	// Aliases should also be registered
	mod, err := modules.LoadModule("glue-passrole-devendpoint")
	if err != nil {
		t.Fatalf("Expected alias 'glue-passrole-devendpoint' to be registered: %v", err)
	}
	if mod.Name() != "glue-001" {
		t.Errorf("Expected name 'glue-001' via alias, got '%s'", mod.Name())
	}
}

func TestGluePassroleDevEndpointMITRE(t *testing.T) {
	mod := glue_passrole_devendpoint.NewModule()
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

func TestGluePassroleDevEndpointReferences(t *testing.T) {
	mod := glue_passrole_devendpoint.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/glue-001") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud/paths/glue-001 reference")
	}
}

func TestGluePassroleDevEndpointExecuteMissingSSHKey(t *testing.T) {
	// Run with a temp HOME that has no SSH keys to trigger the key-resolution error.
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	mod := glue_passrole_devendpoint.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN": "arn:aws:iam::123456789012:role/admin",
			"REGION":   "us-east-1",
			// SSH_PUBLIC_KEY intentionally omitted and no ~/.ssh/*.pub in tempDir
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when SSH public key is not available")
	}
	if err != nil && !containsAny(err.Error(), "SSH public key", "no SSH public key") {
		t.Errorf("Expected error about missing SSH public key, got: %v", err)
	}
}

func TestGluePassroleDevEndpointExecuteExplicitSSHKey(t *testing.T) {
	// Providing SSH_PUBLIC_KEY should pass key resolution without touching the filesystem.
	// The actual AWS call will still fail (no real credentials), but validation should pass.
	mod := glue_passrole_devendpoint.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN":        "arn:aws:iam::123456789012:role/admin",
			"SSH_PUBLIC_KEY":  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC test@example",
			"REGION":          "us-east-1",
		},
	}

	// The execute will fail because there are no real AWS credentials, but the error
	// should be from the AWS API call, not from key resolution.
	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error because no real AWS credentials are available")
	}
	// Confirm the error is NOT about missing SSH public key
	if containsAny(err.Error(), "no SSH public key", "resolve SSH public key") {
		t.Errorf("Unexpected SSH key resolution error: %v", err)
	}
}

// containsAny reports whether s contains any of the given substrings.
func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if contains(s, sub) {
			return true
		}
	}
	return false
}
