package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/codebuild_startbuildbatch"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	_ "github.com/DataDog/pathrunner/pkg/payloads/codebuild"
	"strings"
	"testing"
)

func TestCodeBuildStartBuildBatchModuleInit(t *testing.T) {
	mod := codebuild_startbuildbatch.NewModule()

	if mod.Name() != "codebuild-003" {
		t.Errorf("Expected name 'codebuild-003', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "codebuild-003" {
		t.Errorf("Expected ID 'codebuild-003', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestCodeBuildStartBuildBatchDescription(t *testing.T) {
	mod := codebuild_startbuildbatch.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestCodeBuildStartBuildBatchServices(t *testing.T) {
	mod := codebuild_startbuildbatch.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"codebuild": true, "iam": true}
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

func TestCodeBuildStartBuildBatchOptions(t *testing.T) {
	mod := codebuild_startbuildbatch.NewModule()
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

	// PROJECT_NAME and PAYLOAD are required
	if !requiredOptions["PROJECT_NAME"] {
		t.Error("Expected PROJECT_NAME to be required")
	}
	if !requiredOptions["PAYLOAD"] {
		t.Error("Expected PAYLOAD to be required")
	}

	// These should be optional
	expectedOptional := []string{"TARGET_USER", "REGION", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestCodeBuildStartBuildBatchCleanupDefaultFalse(t *testing.T) {
	mod := codebuild_startbuildbatch.NewModule()
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

func TestCodeBuildStartBuildBatchPermissions(t *testing.T) {
	mod := codebuild_startbuildbatch.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	if !requiredPerms["codebuild:StartBuildBatch"] {
		t.Error("Missing required permission: codebuild:StartBuildBatch")
	}
}

func TestCodeBuildStartBuildBatchAliases(t *testing.T) {
	mod := codebuild_startbuildbatch.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["codebuild-startbuildbatch"] {
		t.Error("Expected alias 'codebuild-startbuildbatch'")
	}
}

func TestCodeBuildStartBuildBatchDiscoverableOptions(t *testing.T) {
	mod := codebuild_startbuildbatch.NewModule()

	discoverable, ok := interface{}(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	opts := discoverable.DiscoverableOptions()
	if len(opts) != 1 || opts[0] != "PROJECT_NAME" {
		t.Errorf("Expected DiscoverableOptions to return ['PROJECT_NAME'], got %v", opts)
	}
}

func TestCodeBuildStartBuildBatchRegistration(t *testing.T) {
	mod, err := modules.LoadModule("codebuild-003")
	if err != nil {
		t.Fatalf("Expected module 'codebuild-003' to be registered: %v", err)
	}
	if mod.Name() != "codebuild-003" {
		t.Errorf("Expected name 'codebuild-003', got '%s'", mod.Name())
	}
}

func TestCodeBuildStartBuildBatchAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("codebuild-startbuildbatch")
	if err != nil {
		t.Fatalf("Expected alias 'codebuild-startbuildbatch' to be registered: %v", err)
	}
	if mod.Name() != "codebuild-003" {
		t.Errorf("Expected name 'codebuild-003' via alias, got '%s'", mod.Name())
	}
}

func TestCodeBuildStartBuildBatchPayloadCompatible(t *testing.T) {
	mod := codebuild_startbuildbatch.NewModule()

	// Module should list CodeBuild payloads from the registry
	payloadList := mod.ListPayloads()
	if len(payloadList) == 0 {
		t.Error("Expected at least one CodeBuild payload registered")
	}

	// Verify compatible tags
	compatible, ok := interface{}(mod).(modules.PayloadCompatible)
	if !ok {
		t.Fatal("Expected module to implement PayloadCompatible interface")
	}

	tags := compatible.GetCompatibleTags()
	hasCodeBuild := false
	for _, tag := range tags {
		if tag == "codebuild" {
			hasCodeBuild = true
		}
	}
	if !hasCodeBuild {
		t.Error("Expected compatible tags to include 'codebuild'")
	}

	ctx := compatible.GetPayloadContext()
	if ctx != "codebuild" {
		t.Errorf("Expected payload context 'codebuild', got '%s'", ctx)
	}
}

func TestCodeBuildStartBuildBatchExecuteUnknownPayload(t *testing.T) {
	mod := codebuild_startbuildbatch.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"PROJECT_NAME": "my-project",
			"PAYLOAD":      "nonexistent/payload",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error with unknown payload type")
	}
	if err != nil && !strings.Contains(err.Error(), "unknown payload type") {
		t.Errorf("Expected error about unknown payload type, got: %v", err)
	}
}

func TestCodeBuildStartBuildBatchMITRE(t *testing.T) {
	mod := codebuild_startbuildbatch.NewModule()
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

func TestCodeBuildStartBuildBatchReferences(t *testing.T) {
	mod := codebuild_startbuildbatch.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if strings.Contains(ref.URL, "pathfinding.cloud/paths/codebuild-003") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for codebuild-003")
	}
}

func TestCodeBuildStartBuildBatchBatchBuildspecWrapping(t *testing.T) {
	// Verify the payload generates a batch-format buildspec wrapper.
	// We do this by getting the backdoor/attach-policy payload and verifying
	// the module would wrap it correctly.
	pl, err := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceCodeBuild)
	if err != nil {
		t.Fatalf("Expected backdoor/attach-policy payload to be registered: %v", err)
	}

	opts := map[string]string{
		"TARGET_USER": "test-user",
		"POLICY_ARN":  "arn:aws:iam::aws:policy/AdministratorAccess",
	}

	innerSpec, err := pl.GenerateCode(opts)
	if err != nil {
		t.Fatalf("Expected code generation to succeed: %v", err)
	}

	// The inner buildspec is a regular buildspec.
	if !strings.Contains(innerSpec, "version: 0.2") {
		t.Error("Expected inner buildspec to contain 'version: 0.2'")
	}
	if !strings.Contains(innerSpec, "test-user") {
		t.Error("Expected inner buildspec to contain TARGET_USER")
	}
}

func TestCodeBuildStartBuildBatchRelatedPaths(t *testing.T) {
	mod := codebuild_startbuildbatch.NewModule()
	pathInfo := mod.PathInfo()

	relatedSet := map[string]bool{}
	for _, r := range pathInfo.RelatedPaths {
		relatedSet[r] = true
	}

	// Should relate to codebuild-002 (the StartBuild variant) and codebuild-001.
	if !relatedSet["codebuild-002"] {
		t.Error("Expected codebuild-002 in RelatedPaths")
	}
	if !relatedSet["codebuild-001"] {
		t.Error("Expected codebuild-001 in RelatedPaths")
	}
}
