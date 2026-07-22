// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"os"
	"github.com/DataDog/pathrunner/pkg/exploits/glue_passrole_job"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/glue"
	"testing"
)

func TestGluePassroleJobModuleInit(t *testing.T) {
	mod := glue_passrole_job.NewModule()

	if mod.Name() != "glue-003" {
		t.Errorf("Expected name 'glue-003', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "glue-003" {
		t.Errorf("Expected ID 'glue-003', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestGluePassroleJobDescription(t *testing.T) {
	mod := glue_passrole_job.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestGluePassroleJobServices(t *testing.T) {
	mod := glue_passrole_job.NewModule()
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

func TestGluePassroleJobOptions(t *testing.T) {
	mod := glue_passrole_job.NewModule()
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
	expectedOptional := []string{"SCRIPT_S3_URI", "REGION", "JOB_NAME", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestGluePassroleJobPermissions(t *testing.T) {
	mod := glue_passrole_job.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "glue:CreateJob", "glue:StartJobRun"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestGluePassroleJobAliases(t *testing.T) {
	mod := glue_passrole_job.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["glue-passrole-job"] {
		t.Error("Expected alias 'glue-passrole-job'")
	}
}

func TestGluePassroleJobDiscoverableOptions(t *testing.T) {
	mod := glue_passrole_job.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	if len(options) != 1 || options[0] != "ROLE_ARN" {
		t.Errorf("Expected DiscoverableOptions to return ['ROLE_ARN'], got %v", options)
	}
}

func TestGluePassroleJobRegistration(t *testing.T) {
	// Module should be registered via init()
	mod, err := modules.LoadModule("glue-003")
	if err != nil {
		t.Fatalf("Expected module 'glue-003' to be registered: %v", err)
	}
	if mod.Name() != "glue-003" {
		t.Errorf("Expected name 'glue-003', got '%s'", mod.Name())
	}
}

func TestGluePassroleJobAliasRegistration(t *testing.T) {
	// Aliases should also be registered
	mod, err := modules.LoadModule("glue-passrole-job")
	if err != nil {
		t.Fatalf("Expected alias 'glue-passrole-job' to be registered: %v", err)
	}
	if mod.Name() != "glue-003" {
		t.Errorf("Expected name 'glue-003' via alias, got '%s'", mod.Name())
	}
}

func TestGluePassroleJobPayloadCompatible(t *testing.T) {
	mod := glue_passrole_job.NewModule()

	// Module should list Glue payloads from the registry
	payloadList := mod.ListPayloads()
	if len(payloadList) == 0 {
		t.Error("Expected at least one Glue payload registered")
	}

	// Verify compatible tags
	compatible, ok := interface{}(mod).(modules.PayloadCompatible)
	if !ok {
		t.Fatal("Expected module to implement PayloadCompatible interface")
	}

	tags := compatible.GetCompatibleTags()
	hasGlue := false
	for _, tag := range tags {
		if tag == "glue" {
			hasGlue = true
		}
	}
	if !hasGlue {
		t.Error("Expected compatible tags to include 'glue'")
	}

	ctx := compatible.GetPayloadContext()
	if ctx != "glue" {
		t.Errorf("Expected payload context 'glue', got '%s'", ctx)
	}
}

func TestGluePassroleJobExecuteNoIdentity(t *testing.T) {
	mod := glue_passrole_job.NewModule()

	// Execute with invalid payload should fail with unknown payload error
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

func TestGluePassroleJobExecuteNoAttackerNoS3(t *testing.T) {
	// Use temp HOME to ensure no deploy state interferes
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	mod := glue_passrole_job.NewModule()

	// Execute with valid payload but no attacker identity and no SCRIPT_S3_URI should fail
	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN": "arn:aws:iam::123456789012:role/admin",
			"PAYLOAD":  "exfil/cloudwatch",
		},
		AttackerIdentity: nil,
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when executing without attacker identity or SCRIPT_S3_URI")
	}
	if err != nil && !contains(err.Error(), "no SCRIPT_S3_URI") && !contains(err.Error(), "no attacker code bucket") {
		t.Errorf("Expected error about missing SCRIPT_S3_URI or code bucket, got: %v", err)
	}
}

func TestGluePassroleJobMITRE(t *testing.T) {
	mod := glue_passrole_job.NewModule()
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

func TestGluePassroleJobReferences(t *testing.T) {
	mod := glue_passrole_job.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/glue-003") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
