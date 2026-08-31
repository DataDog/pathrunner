// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"strings"
	"testing"

	"github.com/DataDog/pathrunner/pkg/exploits/batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/batch"
)

func TestBatch003ModuleInit(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()

	if mod.Name() != "batch-003" {
		t.Errorf("Expected name 'batch-003', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "batch-003" {
		t.Errorf("Expected ID 'batch-003', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestBatch003Description(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
	if !strings.Contains(desc, "CreateComputeEnvironment") {
		t.Error("Description should mention CreateComputeEnvironment")
	}
}

func TestBatch003Services(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()
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

func TestBatch003Options(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()
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

	// These should be required
	for _, name := range []string{"ADMIN_ROLE_ARN", "EXECUTION_ROLE_ARN", "SUBNET_ID", "SECURITY_GROUP_ID"} {
		if !requiredOptions[name] {
			t.Errorf("Expected %s to be required", name)
		}
	}

	// These should be optional
	for _, name := range []string{"TARGET_PRINCIPAL", "REGION", "CLEANUP", "JOB_DEF_NAME", "COMPUTE_ENV_NAME", "JOB_QUEUE_NAME", "CONTAINER_RUNTIME", "IMAGE"} {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestBatch003Permissions(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{
		"iam:PassRole",
		"batch:CreateComputeEnvironment",
		"batch:CreateJobQueue",
		"batch:RegisterJobDefinition",
		"batch:SubmitJob",
	}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestBatch003Aliases(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["batch-full-pipeline"] {
		t.Error("Expected alias 'batch-full-pipeline'")
	}
}

func TestBatch003DiscoverableOptions(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()

	discoverable, ok := any(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	discoverySet := map[string]bool{}
	for _, opt := range options {
		discoverySet[opt] = true
	}

	for _, name := range []string{"ADMIN_ROLE_ARN", "EXECUTION_ROLE_ARN", "SUBNET_ID", "SECURITY_GROUP_ID"} {
		if !discoverySet[name] {
			t.Errorf("Expected %s to be discoverable", name)
		}
	}
}

func TestBatch003Registration(t *testing.T) {
	mod, err := modules.LoadModule("batch-003")
	if err != nil {
		t.Fatalf("Expected module 'batch-003' to be registered: %v", err)
	}
	if mod.Name() != "batch-003" {
		t.Errorf("Expected name 'batch-003', got '%s'", mod.Name())
	}
}

func TestBatch003AliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("batch-full-pipeline")
	if err != nil {
		t.Fatalf("Expected alias 'batch-full-pipeline' to be registered: %v", err)
	}
	if mod.Name() != "batch-003" {
		t.Errorf("Expected name 'batch-003' via alias, got '%s'", mod.Name())
	}
}

func TestBatch003MITRE(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()
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

func TestBatch003References(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if strings.Contains(ref.URL, "pathfinding.cloud/paths/batch-003") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for batch-003")
	}
}

func TestBatch003RelatedPaths(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()
	pathInfo := mod.PathInfo()

	expectedPaths := map[string]bool{"batch-001": false, "batch-002": false}
	for _, path := range pathInfo.RelatedPaths {
		expectedPaths[path] = true
	}
	for path, found := range expectedPaths {
		if !found {
			t.Errorf("Expected %s in related paths", path)
		}
	}
}

func TestBatch003PayloadCompatible(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()

	_, isPayloadCompatible := any(mod).(modules.PayloadCompatible)
	if !isPayloadCompatible {
		t.Error("batch-003 should implement PayloadCompatible")
	}
}

func TestBatch003ExecuteRequiresAdminRoleArn(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"EXECUTION_ROLE_ARN": "arn:aws:iam::123456789012:role/exec-role",
			"SUBNET_ID":         "subnet-12345",
			"SECURITY_GROUP_ID": "sg-12345",
			"TARGET_PRINCIPAL":       "test-user",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when ADMIN_ROLE_ARN is missing")
	}
}

func TestBatch003ExecuteRequiresExecutionRoleArn(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ADMIN_ROLE_ARN":    "arn:aws:iam::123456789012:role/admin-role",
			"SUBNET_ID":        "subnet-12345",
			"SECURITY_GROUP_ID": "sg-12345",
			"TARGET_PRINCIPAL":       "test-user",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when EXECUTION_ROLE_ARN is missing")
	}
}

func TestBatch003ExecuteRequiresSubnetID(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ADMIN_ROLE_ARN":     "arn:aws:iam::123456789012:role/admin-role",
			"EXECUTION_ROLE_ARN": "arn:aws:iam::123456789012:role/exec-role",
			"SECURITY_GROUP_ID":  "sg-12345",
			"TARGET_PRINCIPAL":        "test-user",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when SUBNET_ID is missing")
	}
}

func TestBatch003ExecuteRequiresSecurityGroupID(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ADMIN_ROLE_ARN":     "arn:aws:iam::123456789012:role/admin-role",
			"EXECUTION_ROLE_ARN": "arn:aws:iam::123456789012:role/exec-role",
			"SUBNET_ID":         "subnet-12345",
			"TARGET_PRINCIPAL":       "test-user",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when SECURITY_GROUP_ID is missing")
	}
}

func TestBatch003CleanupDefaultsFalse(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()

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

func TestBatch003ContainerRuntimeDefaultsToAWSCLI(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()

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

func TestBatch003PayloadsAvailable(t *testing.T) {
	mod := batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob.NewModule()

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
			t.Errorf("Expected payload '%s' to be available for batch-003", name)
		}
	}
}
