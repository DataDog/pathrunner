package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/codedeploy_createdeployment"
	"github.com/DataDog/pathrunner/pkg/modules"
	"testing"
)

func TestCodeDeployCreateDeploymentModuleInit(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()

	if mod.Name() != "codedeploy-001" {
		t.Errorf("Expected name 'codedeploy-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "codedeploy-001" {
		t.Errorf("Expected ID 'codedeploy-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestCodeDeployCreateDeploymentDescription(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestCodeDeployCreateDeploymentServices(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "codedeploy": true, "ec2": true}
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

func TestCodeDeployCreateDeploymentOptions(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()
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

	// APP_NAME, DEPLOYMENT_GROUP, and BUCKET are required
	if !requiredOptions["APP_NAME"] {
		t.Error("Expected APP_NAME to be required")
	}
	if !requiredOptions["DEPLOYMENT_GROUP"] {
		t.Error("Expected DEPLOYMENT_GROUP to be required")
	}
	if !requiredOptions["BUCKET"] {
		t.Error("Expected BUCKET to be required")
	}

	// These should be optional
	expectedOptional := []string{"REVISION_KEY", "TARGET_USER", "REGION", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestCodeDeployCreateDeploymentCleanupDefaultsFalse(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()

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

func TestCodeDeployCreateDeploymentRevisionKeyDefault(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()

	for _, opt := range mod.Options() {
		if opt.Name == "REVISION_KEY" {
			if opt.Default != "codedeploy-001-revision.zip" {
				t.Errorf("Expected REVISION_KEY default to be 'codedeploy-001-revision.zip', got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("REVISION_KEY option not found")
}

func TestCodeDeployCreateDeploymentPermissions(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()
	pathInfo := mod.PathInfo()

	requiredPerms := map[string]bool{}
	for _, perm := range pathInfo.Permissions.Required {
		requiredPerms[perm.Permission] = true
	}

	if !requiredPerms["codedeploy:CreateDeployment"] {
		t.Error("Missing required permission: codedeploy:CreateDeployment")
	}
	if !requiredPerms["codedeploy:RegisterApplicationRevision"] {
		t.Error("Missing required permission: codedeploy:RegisterApplicationRevision")
	}
	if !requiredPerms["codedeploy:GetDeploymentConfig"] {
		t.Error("Missing required permission: codedeploy:GetDeploymentConfig")
	}
}

func TestCodeDeployCreateDeploymentAliases(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}

	aliasSet := map[string]bool{}
	for _, a := range pathInfo.Aliases {
		aliasSet[a] = true
	}

	if !aliasSet["codedeploy-createdeployment"] {
		t.Error("Expected alias 'codedeploy-createdeployment'")
	}
}

func TestCodeDeployCreateDeploymentMITRE(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()
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

func TestCodeDeployCreateDeploymentReferences(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	foundPathfindingRef := false
	for _, ref := range pathInfo.References {
		if containsCodeDeploy(ref.URL, "pathfinding.cloud/paths/codedeploy-001") {
			foundPathfindingRef = true
		}
	}
	if !foundPathfindingRef {
		t.Error("Expected pathfinding.cloud reference for codedeploy-001")
	}
}

func TestCodeDeployCreateDeploymentRegistration(t *testing.T) {
	// Module should be registered via init()
	mod, err := modules.LoadModule("codedeploy-001")
	if err != nil {
		t.Fatalf("Expected module 'codedeploy-001' to be registered: %v", err)
	}
	if mod.Name() != "codedeploy-001" {
		t.Errorf("Expected name 'codedeploy-001', got '%s'", mod.Name())
	}
}

func TestCodeDeployCreateDeploymentAliasRegistration(t *testing.T) {
	mod, err := modules.LoadModule("codedeploy-createdeployment")
	if err != nil {
		t.Fatalf("Expected alias 'codedeploy-createdeployment' to be registered: %v", err)
	}
	if mod.Name() != "codedeploy-001" {
		t.Errorf("Expected name 'codedeploy-001' via alias, got '%s'", mod.Name())
	}
}

func TestCodeDeployCreateDeploymentNotPayloadCompatible(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()

	// codedeploy-001 uses a pre-staged S3 revision rather than the payload registry.
	// The revision is uploaded to S3 before the exploit runs (by the lab Terraform or
	// by the attacker manually) and referenced via BUCKET + REVISION_KEY options.
	_, isPayloadCompatible := interface{}(mod).(modules.PayloadCompatible)
	if isPayloadCompatible {
		t.Error("codedeploy-001 should not implement PayloadCompatible — it uses a pre-staged S3 revision, not the payload registry")
	}
}

func TestCodeDeployCreateDeploymentExecuteRequiresAppName(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"DEPLOYMENT_GROUP": "my-dg",
			"BUCKET":           "my-bucket",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when APP_NAME is missing")
	}
}

func TestCodeDeployCreateDeploymentExecuteRequiresDeploymentGroup(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"APP_NAME": "my-app",
			"BUCKET":   "my-bucket",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when DEPLOYMENT_GROUP is missing")
	}
}

func TestCodeDeployCreateDeploymentExecuteRequiresBucket(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()

	ectx := modules.ExecutionContext{
		Identity: &modules.Identity{
			Name:   "test-victim",
			Type:   "keys",
			Region: "us-east-1",
		},
		Options: map[string]string{
			"APP_NAME":         "my-app",
			"DEPLOYMENT_GROUP": "my-dg",
		},
	}

	_, err := mod.Execute(ectx)
	if err == nil {
		t.Error("Expected error when BUCKET is missing")
	}
}

func TestCodeDeployCreateDeploymentPrerequisites(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected at least one admin prerequisite")
	}
	if len(pathInfo.Prerequisites.Lateral) == 0 {
		t.Error("Expected at least one lateral prerequisite")
	}
}

func TestCodeDeployCreateDeploymentRelatedPaths(t *testing.T) {
	mod := codedeploy_createdeployment.NewModule()
	pathInfo := mod.PathInfo()

	foundCodebuild := false
	for _, path := range pathInfo.RelatedPaths {
		if path == "codebuild-002" {
			foundCodebuild = true
		}
	}
	if !foundCodebuild {
		t.Error("Expected codebuild-002 in related paths")
	}
}

func containsCodeDeploy(s, substr string) bool {
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
