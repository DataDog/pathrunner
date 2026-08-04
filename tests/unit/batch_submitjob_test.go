// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"testing"

	"github.com/DataDog/pathrunner/pkg/exploits/batch_submitjob"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/batch"
)

func TestBatchSubmitJobModuleInit(t *testing.T) {
	mod := batch_submitjob.NewModule()

	if mod.Name() != "batch-002" {
		t.Errorf("Expected name 'batch-002', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "batch-002" {
		t.Errorf("Expected ID 'batch-002', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestBatchSubmitJobDescription(t *testing.T) {
	mod := batch_submitjob.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestBatchSubmitJobServices(t *testing.T) {
	mod := batch_submitjob.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "batch": true}
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

func TestBatchSubmitJobOptions(t *testing.T) {
	mod := batch_submitjob.NewModule()
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

	// JOB_DEFINITION and JOB_QUEUE are required
	if !requiredOptions["JOB_DEFINITION"] {
		t.Error("Expected JOB_DEFINITION to be required")
	}
	if !requiredOptions["JOB_QUEUE"] {
		t.Error("Expected JOB_QUEUE to be required")
	}

	// These should be optional
	expectedOptional := []string{"TARGET_USER", "REGION", "CLEANUP", "CONTAINER_RUNTIME"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestBatchSubmitJobCleanupDefaultsFalse(t *testing.T) {
	mod := batch_submitjob.NewModule()

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

func TestBatchSubmitJobPermissions(t *testing.T) {
	mod := batch_submitjob.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	if !requiredPerms["batch:SubmitJob"] {
		t.Error("Missing required permission: batch:SubmitJob")
	}
}

func TestBatchSubmitJobAliases(t *testing.T) {
	mod := batch_submitjob.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["batch-submitjob"] {
		t.Error("Expected alias 'batch-submitjob'")
	}
}

func TestBatchSubmitJobDiscoverableOptions(t *testing.T) {
	mod := batch_submitjob.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	discoverySet := map[string]bool{}
	for _, opt := range options {
		discoverySet[opt] = true
	}

	if !discoverySet["JOB_DEFINITION"] {
		t.Error("Expected JOB_DEFINITION to be discoverable")
	}
	if !discoverySet["JOB_QUEUE"] {
		t.Error("Expected JOB_QUEUE to be discoverable")
	}
}

func TestBatchSubmitJobRegistration(t *testing.T) {
	// Module should be registered via init()
	mod, err := modules.LoadModule("batch-002")
	if err != nil {
		t.Fatalf("Expected module 'batch-002' to be registered: %v", err)
	}
	if mod.Name() != "batch-002" {
		t.Errorf("Expected name 'batch-002', got '%s'", mod.Name())
	}
}

func TestBatchSubmitJobAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("batch-submitjob")
	if err != nil {
		t.Fatalf("Expected alias 'batch-submitjob' to be registered: %v", err)
	}
	if mod.Name() != "batch-002" {
		t.Errorf("Expected name 'batch-002' via alias, got '%s'", mod.Name())
	}
}

func TestBatchSubmitJobMITRE(t *testing.T) {
	mod := batch_submitjob.NewModule()
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

func TestBatchSubmitJobReferences(t *testing.T) {
	mod := batch_submitjob.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if containsBatch(ref.URL, "pathfinding.cloud/paths/batch-002") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for batch-002")
	}
}

func TestBatchSubmitJobPayloadCompatible(t *testing.T) {
	mod := batch_submitjob.NewModule()

	_, isPayloadCompatible := interface{}(mod).(modules.PayloadCompatible)
	if !isPayloadCompatible {
		t.Error("batch-002 should implement PayloadCompatible")
	}
}

func TestBatchSubmitJobExecuteRequiresJobDefinition(t *testing.T) {
	mod := batch_submitjob.NewModule()

	// JOB_DEFINITION is required — module validation should reject missing options before Execute,
	// but if Execute is called directly without JOB_DEFINITION, SubmitJob will fail
	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"JOB_QUEUE":   "my-queue",
			"TARGET_USER": "test-user",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when JOB_DEFINITION is missing")
	}
}

func TestBatchSubmitJobRelatedPaths(t *testing.T) {
	mod := batch_submitjob.NewModule()
	pathInfo := mod.PathInfo()

	foundBatch001 := false
	for _, path := range pathInfo.RelatedPaths {
		if path == "batch-001" {
			foundBatch001 = true
		}
	}
	if !foundBatch001 {
		t.Error("Expected batch-001 in related paths")
	}
}

func TestBatchSubmitJobContainerRuntimeDefaultsToAWSCLI(t *testing.T) {
	mod := batch_submitjob.NewModule()

	for _, opt := range mod.Options() {
		if opt.Name == "CONTAINER_RUNTIME" {
			if opt.Default != "aws-cli" {
				t.Errorf("Expected CONTAINER_RUNTIME default to be 'aws-cli', got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("CONTAINER_RUNTIME option not found")
}

func TestBatchSubmitJobExfilHTTPSPayloadAvailable(t *testing.T) {
	mod := batch_submitjob.NewModule()

	payloads := mod.ListPayloads()
	found := false
	for _, p := range payloads {
		if p.Name == "exfil/https" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected exfil/https to be available for batch-002")
	}
}

func containsBatch(s, substr string) bool {
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
