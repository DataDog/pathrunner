package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/codedeploy_createdeployment"
)

func TestCodeDeployCreateDeploymentModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codedeploy-001"); err != nil {
		t.Fatalf("Failed to use codedeploy-001: %v", err)
	}
}

func TestCodeDeployCreateDeploymentModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codedeploy-createdeployment"); err != nil {
		t.Fatalf("Failed to use codedeploy-createdeployment alias: %v", err)
	}
}

func TestCodeDeployCreateDeploymentModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codedeploy-001"); err != nil {
		t.Fatalf("Failed to use codedeploy-001: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestCodeDeployCreateDeploymentModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codedeploy-001"); err != nil {
		t.Fatalf("Failed to use codedeploy-001: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestCodeDeployCreateDeploymentModuleSetOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codedeploy-001"); err != nil {
		t.Fatalf("Failed to use codedeploy-001: %v", err)
	}

	if err := r.ExecuteCommand("set APP_NAME pl-prod-codedeploy-001-to-admin-app"); err != nil {
		t.Fatalf("Expected set APP_NAME to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set DEPLOYMENT_GROUP pl-prod-codedeploy-001-to-admin-dg"); err != nil {
		t.Fatalf("Expected set DEPLOYMENT_GROUP to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set BUCKET pl-attacker-codedeploy-001-revision-123456789"); err != nil {
		t.Fatalf("Expected set BUCKET to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_USER test-starting-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}
}

func TestCodeDeployCreateDeploymentExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codedeploy-001"); err != nil {
		t.Fatalf("Failed to use codedeploy-001: %v", err)
	}

	if err := r.ExecuteCommand("set APP_NAME my-app"); err != nil {
		t.Fatalf("Failed to set APP_NAME: %v", err)
	}
	if err := r.ExecuteCommand("set DEPLOYMENT_GROUP my-dg"); err != nil {
		t.Fatalf("Failed to set DEPLOYMENT_GROUP: %v", err)
	}
	if err := r.ExecuteCommand("set BUCKET my-bucket"); err != nil {
		t.Fatalf("Failed to set BUCKET: %v", err)
	}
	if err := r.ExecuteCommand("set TARGET_USER some-user"); err != nil {
		t.Fatalf("Failed to set TARGET_USER: %v", err)
	}

	// Should fail because no identity is selected
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestCodeDeployCreateDeploymentSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search codedeploy"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestCodeDeployCreateDeploymentModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codedeploy-001"); err != nil {
		t.Fatalf("Failed to use codedeploy-001: %v", err)
	}

	if err := r.ExecuteCommand("set APP_NAME my-app"); err != nil {
		t.Fatalf("Failed to set APP_NAME: %v", err)
	}

	if err := r.ExecuteCommand("unset APP_NAME"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}

func TestCodeDeployCreateDeploymentRegionOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use codedeploy-001"); err != nil {
		t.Fatalf("Failed to use codedeploy-001: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-west-2"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}
