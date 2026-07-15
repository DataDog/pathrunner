package unit

import (
	"os"
	"pathrunner/pkg/exploits/glue_updatejob_startjobrun"
	"pathrunner/pkg/modules"
	_ "pathrunner/pkg/payloads/glue"
	"testing"
)

func TestGlueUpdatejobStartjobrunModuleInit(t *testing.T) {
	mod := glue_updatejob_startjobrun.NewModule()

	if mod.Name() != "glue-005" {
		t.Errorf("Expected name 'glue-005', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "glue-005" {
		t.Errorf("Expected ID 'glue-005', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestGlueUpdatejobStartjobrunDescription(t *testing.T) {
	mod := glue_updatejob_startjobrun.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestGlueUpdatejobStartjobrunServices(t *testing.T) {
	mod := glue_updatejob_startjobrun.NewModule()
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

func TestGlueUpdatejobStartjobrunOptions(t *testing.T) {
	mod := glue_updatejob_startjobrun.NewModule()
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

	// JOB_NAME, ROLE_ARN, and PAYLOAD are required
	if !requiredOptions["JOB_NAME"] {
		t.Error("Expected JOB_NAME to be required")
	}
	if !requiredOptions["ROLE_ARN"] {
		t.Error("Expected ROLE_ARN to be required")
	}
	if !requiredOptions["PAYLOAD"] {
		t.Error("Expected PAYLOAD to be required")
	}

	// These should be optional
	expectedOptional := []string{"SCRIPT_S3_URI", "REGION", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestGlueUpdatejobStartjobrunPermissions(t *testing.T) {
	mod := glue_updatejob_startjobrun.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	expectedPerms := []string{"iam:PassRole", "glue:UpdateJob", "glue:StartJobRun"}
	for _, perm := range expectedPerms {
		if !requiredPerms[perm] {
			t.Errorf("Missing required permission: %s", perm)
		}
	}
}

func TestGlueUpdatejobStartjobrunAliases(t *testing.T) {
	mod := glue_updatejob_startjobrun.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["glue-updatejob-startjobrun"] {
		t.Error("Expected alias 'glue-updatejob-startjobrun'")
	}
}

func TestGlueUpdatejobStartjobrunDiscoverableOptions(t *testing.T) {
	mod := glue_updatejob_startjobrun.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
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

func TestGlueUpdatejobStartjobrunRegistration(t *testing.T) {
	mod, err := modules.LoadModule("glue-005")
	if err != nil {
		t.Fatalf("Expected module 'glue-005' to be registered: %v", err)
	}
	if mod.Name() != "glue-005" {
		t.Errorf("Expected name 'glue-005', got '%s'", mod.Name())
	}
}

func TestGlueUpdatejobStartjobrunAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("glue-updatejob-startjobrun")
	if err != nil {
		t.Fatalf("Expected alias 'glue-updatejob-startjobrun' to be registered: %v", err)
	}
	if mod.Name() != "glue-005" {
		t.Errorf("Expected name 'glue-005' via alias, got '%s'", mod.Name())
	}
}

func TestGlueUpdatejobStartjobrunPayloadCompatible(t *testing.T) {
	mod := glue_updatejob_startjobrun.NewModule()

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

func TestGlueUpdatejobStartjobrunExecuteUnknownPayload(t *testing.T) {
	mod := glue_updatejob_startjobrun.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"JOB_NAME": "test-job",
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

func TestGlueUpdatejobStartjobrunExecuteNoAttackerNoS3(t *testing.T) {
	// Use temp HOME to ensure no deploy state interferes
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	mod := glue_updatejob_startjobrun.NewModule()

	// Valid payload but no attacker identity and no SCRIPT_S3_URI should fail after
	// validation (because it will try to hit AWS to get the job config first — but
	// with no real credentials it will fail at the GetJob call, not the script upload).
	// We can only confirm the error chain hits the "no code bucket" path when
	// SCRIPT_S3_URI is absent and there's no deploy state.
	// Here we verify the module starts executing and returns an error (not panic).
	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"JOB_NAME": "test-job",
			"ROLE_ARN": "arn:aws:iam::123456789012:role/admin",
			"PAYLOAD":  "exfil/cloudwatch",
		},
		AttackerIdentity: nil,
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when executing without attacker identity or SCRIPT_S3_URI")
	}
}

func TestGlueUpdatejobStartjobrunMITRE(t *testing.T) {
	mod := glue_updatejob_startjobrun.NewModule()
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

func TestGlueUpdatejobStartjobrunReferences(t *testing.T) {
	mod := glue_updatejob_startjobrun.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if contains(ref.URL, "pathfinding.cloud/paths/glue-005") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for glue-005")
	}
}

func TestGlueUpdatejobStartjobrunRelatedPaths(t *testing.T) {
	mod := glue_updatejob_startjobrun.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.RelatedPaths) == 0 {
		t.Error("Expected at least one related path")
	}

	relatedSet := map[string]bool{}
	for _, p := range pathInfo.RelatedPaths {
		relatedSet[p] = true
	}

	// glue-003 is the direct relative (same technique, CreateJob vs UpdateJob)
	if !relatedSet["glue-003"] {
		t.Error("Expected glue-003 in related paths")
	}
}
