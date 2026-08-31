// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"testing"

	"github.com/DataDog/pathrunner/pkg/exploits/batch_passrole_registerjobdefinition_submitjob"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/batch"
)

func TestBatchPassroleRegisterJobDefinitionSubmitJobModuleInit(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()

	if mod.Name() != "batch-001" {
		t.Errorf("Expected name 'batch-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "batch-001" {
		t.Errorf("Expected ID 'batch-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobDescription(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobServices(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()
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

func TestBatchPassroleRegisterJobDefinitionSubmitJobOptions(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()
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

	// ADMIN_ROLE_ARN, EXECUTION_ROLE_ARN, and JOB_QUEUE are required
	if !requiredOptions["ADMIN_ROLE_ARN"] {
		t.Error("Expected ADMIN_ROLE_ARN to be required")
	}
	if !requiredOptions["EXECUTION_ROLE_ARN"] {
		t.Error("Expected EXECUTION_ROLE_ARN to be required")
	}
	if !requiredOptions["JOB_QUEUE"] {
		t.Error("Expected JOB_QUEUE to be required")
	}

	// These should be optional
	expectedOptional := []string{"TARGET_PRINCIPAL", "REGION", "CLEANUP", "JOB_DEF_NAME", "CONTAINER_RUNTIME", "IMAGE"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobCleanupDefaultsFalse(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()

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

func TestBatchPassroleRegisterJobDefinitionSubmitJobPermissions(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	if !requiredPerms["iam:PassRole"] {
		t.Error("Missing required permission: iam:PassRole")
	}
	if !requiredPerms["batch:RegisterJobDefinition"] {
		t.Error("Missing required permission: batch:RegisterJobDefinition")
	}
	if !requiredPerms["batch:SubmitJob"] {
		t.Error("Missing required permission: batch:SubmitJob")
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobAliases(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["batch-passrole"] {
		t.Error("Expected alias 'batch-passrole'")
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobDiscoverableOptions(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	discoverySet := map[string]bool{}
	for _, opt := range options {
		discoverySet[opt] = true
	}

	if !discoverySet["JOB_QUEUE"] {
		t.Error("Expected JOB_QUEUE to be discoverable")
	}
	if !discoverySet["ADMIN_ROLE_ARN"] {
		t.Error("Expected ADMIN_ROLE_ARN to be discoverable")
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobRegistration(t *testing.T) {
	// Module should be registered via init()
	mod, err := modules.LoadModule("batch-001")
	if err != nil {
		t.Fatalf("Expected module 'batch-001' to be registered: %v", err)
	}
	if mod.Name() != "batch-001" {
		t.Errorf("Expected name 'batch-001', got '%s'", mod.Name())
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("batch-passrole")
	if err != nil {
		t.Fatalf("Expected alias 'batch-passrole' to be registered: %v", err)
	}
	if mod.Name() != "batch-001" {
		t.Errorf("Expected name 'batch-001' via alias, got '%s'", mod.Name())
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobMITRE(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()
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

func TestBatchPassroleRegisterJobDefinitionSubmitJobReferences(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if containsBatchPassrole(ref.URL, "pathfinding.cloud/paths/batch-001") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for batch-001")
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobRelatedPaths(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()
	pathInfo := mod.PathInfo()

	foundBatch002 := false
	for _, path := range pathInfo.RelatedPaths {
		if path == "batch-002" {
			foundBatch002 = true
		}
	}
	if !foundBatch002 {
		t.Error("Expected batch-002 in related paths")
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobPayloadCompatible(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()

	_, isPayloadCompatible := interface{}(mod).(modules.PayloadCompatible)
	if !isPayloadCompatible {
		t.Error("batch-001 should implement PayloadCompatible — it uses the payload registry for container commands")
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobExecuteRequiresAdminRoleArn(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"EXECUTION_ROLE_ARN": "arn:aws:iam::123456789012:role/exec-role",
			"JOB_QUEUE":          "my-queue",
			"TARGET_PRINCIPAL":        "test-user",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when ADMIN_ROLE_ARN is missing")
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobExecuteRequiresExecutionRoleArn(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ADMIN_ROLE_ARN": "arn:aws:iam::123456789012:role/admin-role",
			"JOB_QUEUE":      "my-queue",
			"TARGET_PRINCIPAL":    "test-user",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when EXECUTION_ROLE_ARN is missing")
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobExecuteRequiresJobQueue(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ADMIN_ROLE_ARN":     "arn:aws:iam::123456789012:role/admin-role",
			"EXECUTION_ROLE_ARN": "arn:aws:iam::123456789012:role/exec-role",
			"TARGET_PRINCIPAL":        "test-user",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when JOB_QUEUE is missing")
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobContainerRuntimeDefaultsToAWSCLI(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()

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

func TestBatchPassroleRegisterJobDefinitionSubmitJobImageOptionPresent(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()

	found := false
	for _, opt := range mod.Options() {
		if opt.Name == "IMAGE" {
			found = true
			if opt.Required {
				t.Error("Expected IMAGE to be optional")
			}
		}
	}
	if !found {
		t.Error("Expected IMAGE option to be present")
	}
}

func TestBatchPassroleRegisterJobDefinitionSubmitJobPayloadsAvailable(t *testing.T) {
	mod := batch_passrole_registerjobdefinition_submitjob.NewModule()

	payloadList := mod.ListPayloads()
	available := map[string]bool{}
	for _, p := range payloadList {
		available[p.Name] = true
	}

	expected := []string{
		"backdoor/attach-policy",
		"backdoor/create-access-key",
		"backdoor/create-user",
		"backdoor/create-role",
		"backdoor/update-role-trust",
		"exfil/https",
	}

	for _, name := range expected {
		if !available[name] {
			t.Errorf("Expected payload '%s' to be available for batch-001", name)
		}
	}

	if len(payloadList) < len(expected) {
		t.Errorf("Expected at least %d payloads, got %d", len(expected), len(payloadList))
	}
}

func containsBatchPassrole(s, substr string) bool {
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
