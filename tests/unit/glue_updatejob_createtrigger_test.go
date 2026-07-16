package unit

import (
	"os"
	"github.com/DataDog/pathrunner/pkg/exploits/glue_updatejob_createtrigger"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/glue"
	"testing"
)

func TestGlueUpdatejobCreateTriggerModuleInit(t *testing.T) {
	mod := glue_updatejob_createtrigger.NewModule()

	if mod.Name() != "glue-006" {
		t.Errorf("Expected name 'glue-006', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "glue-006" {
		t.Errorf("Expected ID 'glue-006', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "new-passrole" {
		t.Errorf("Expected category 'new-passrole', got '%s'", pathInfo.Category)
	}
}

func TestGlueUpdatejobCreateTriggerDescription(t *testing.T) {
	mod := glue_updatejob_createtrigger.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestGlueUpdatejobCreateTriggerServices(t *testing.T) {
	mod := glue_updatejob_createtrigger.NewModule()
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

func TestGlueUpdatejobCreateTriggerOptions(t *testing.T) {
	mod := glue_updatejob_createtrigger.NewModule()
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

	// ROLE_ARN, JOB_NAME, and PAYLOAD are required.
	if !requiredOptions["ROLE_ARN"] {
		t.Error("Expected ROLE_ARN to be required")
	}
	if !requiredOptions["JOB_NAME"] {
		t.Error("Expected JOB_NAME to be required")
	}
	if !requiredOptions["PAYLOAD"] {
		t.Error("Expected PAYLOAD to be required")
	}

	// These should be optional.
	expectedOptional := []string{"SCRIPT_S3_URI", "REGION", "TRIGGER_NAME", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestGlueUpdatejobCreateTriggerPermissions(t *testing.T) {
	mod := glue_updatejob_createtrigger.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "glue:UpdateJob", "glue:CreateTrigger"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestGlueUpdatejobCreateTriggerAliases(t *testing.T) {
	mod := glue_updatejob_createtrigger.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["glue-updatejob-createtrigger"] {
		t.Error("Expected alias 'glue-updatejob-createtrigger'")
	}
}

func TestGlueUpdatejobCreateTriggerDiscoverableOptions(t *testing.T) {
	mod := glue_updatejob_createtrigger.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	if len(options) != 2 {
		t.Errorf("Expected 2 discoverable options (ROLE_ARN, JOB_NAME), got %d: %v", len(options), options)
	}

	optionSet := map[string]bool{}
	for _, o := range options {
		optionSet[o] = true
	}
	if !optionSet["ROLE_ARN"] {
		t.Error("Expected ROLE_ARN to be discoverable")
	}
	if !optionSet["JOB_NAME"] {
		t.Error("Expected JOB_NAME to be discoverable")
	}
}

func TestGlueUpdatejobCreateTriggerRegistration(t *testing.T) {
	mod, err := modules.LoadModule("glue-006")
	if err != nil {
		t.Fatalf("Expected module 'glue-006' to be registered: %v", err)
	}
	if mod.Name() != "glue-006" {
		t.Errorf("Expected name 'glue-006', got '%s'", mod.Name())
	}
}

func TestGlueUpdatejobCreateTriggerAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("glue-updatejob-createtrigger")
	if err != nil {
		t.Fatalf("Expected alias 'glue-updatejob-createtrigger' to be registered: %v", err)
	}
	if mod.Name() != "glue-006" {
		t.Errorf("Expected name 'glue-006' via alias, got '%s'", mod.Name())
	}
}

func TestGlueUpdatejobCreateTriggerPayloadCompatible(t *testing.T) {
	mod := glue_updatejob_createtrigger.NewModule()

	payloadList := mod.ListPayloads()
	if len(payloadList) == 0 {
		t.Error("Expected at least one Glue payload registered")
	}

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

func TestGlueUpdatejobCreateTriggerExecuteUnknownPayload(t *testing.T) {
	mod := glue_updatejob_createtrigger.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN": "arn:aws:iam::123456789012:role/admin",
			"JOB_NAME": "existing-glue-job",
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

func TestGlueUpdatejobCreateTriggerExecuteNoAttackerNoS3(t *testing.T) {
	// Use temp HOME to ensure no deploy state interferes.
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	mod := glue_updatejob_createtrigger.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"ROLE_ARN": "arn:aws:iam::123456789012:role/admin",
			"JOB_NAME": "existing-glue-job",
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

func TestGlueUpdatejobCreateTriggerMITRE(t *testing.T) {
	mod := glue_updatejob_createtrigger.NewModule()
	pathInfo := mod.PathInfo()

	if pathInfo.MITRE == nil {
		t.Fatal("Expected MITRE mapping to be set")
	}

	if len(pathInfo.MITRE.Tactics) == 0 {
		t.Error("Expected at least one MITRE tactic")
	}

	// glue-006 includes both Privilege Escalation and Persistence tactics.
	foundPrivesc := false
	foundPersistence := false
	for _, tactic := range pathInfo.MITRE.Tactics {
		if tactic == "TA0004 - Privilege Escalation" {
			foundPrivesc = true
		}
		if tactic == "TA0003 - Persistence" {
			foundPersistence = true
		}
	}
	if !foundPrivesc {
		t.Error("Expected MITRE tactics to include TA0004 - Privilege Escalation")
	}
	if !foundPersistence {
		t.Error("Expected MITRE tactics to include TA0003 - Persistence (trigger-based persistence)")
	}

	if len(pathInfo.MITRE.Techniques) == 0 {
		t.Error("Expected at least one MITRE technique")
	}
}

func TestGlueUpdatejobCreateTriggerReferences(t *testing.T) {
	mod := glue_updatejob_createtrigger.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/glue-006") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for glue-006")
	}
}
