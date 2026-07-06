package integration

import (
	"os"
	"path/filepath"
	"pathrunner/pkg/attacker"
	"testing"
)

func TestDeployCommandRoutingIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// All these should succeed (help/status paths)
	commands := []string{
		"attacker infra help",
		"attacker infra ec2 help",
		"attacker infra status",
	}

	for _, cmd := range commands {
		err := r.ExecuteCommand(cmd)
		if err != nil {
			t.Errorf("Expected '%s' to succeed, got: %v", cmd, err)
		}
	}
}

func TestDeployEC2CreateRequiresAttackerIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("attacker infra ec2 create")
	if err == nil {
		t.Error("Expected error when no attacker identity is set")
	}

	// Also test the shorthand (deploy ec2 with no action defaults to create)
	err = r.ExecuteCommand("attacker infra ec2")
	if err == nil {
		t.Error("Expected error when no attacker identity is set (shorthand)")
	}
}

func TestDeployEC2DestroyRequiresAttackerIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("attacker infra ec2 destroy")
	if err == nil {
		t.Error("Expected error when no attacker identity for destroy")
	}
}

func TestDeployGlobalDestroyRequiresAttackerWhenResourcesExist(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Create a fake deploy state so destroy has something to work with
	state := &attacker.DeployState{
		EC2: &attacker.EC2DeployState{InstanceID: "i-test", Region: "us-east-1"},
	}
	attacker.SaveDeployState(state)

	err := r.ExecuteCommand("attacker infra destroy")
	if err == nil {
		t.Error("Expected error when no attacker identity but resources exist")
	}

	// Clean up
	attacker.RemoveDeployState()
}

func TestDeployEC2StatusWithSavedStateIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Save a deploy state
	state := &attacker.DeployState{
		EC2: &attacker.EC2DeployState{
			InstanceID:      "i-0abc123",
			Region:          "us-east-1",
			PublicIP:        "54.1.2.3",
			SecurityGroupID: "sg-test",
			KeyPairName:     "pathrunner-deploy",
			KeyFilePath:     "/tmp/test.pem",
		},
	}
	attacker.SaveDeployState(state)
	defer attacker.RemoveDeployState()

	// Status should show the saved state (status will say "unknown" since no attacker identity)
	err := r.ExecuteCommand("attacker infra ec2 status")
	if err != nil {
		t.Errorf("Expected ec2 status to succeed with saved state, got: %v", err)
	}

	// Global status should also work
	err = r.ExecuteCommand("attacker infra status")
	if err != nil {
		t.Errorf("Expected global status to succeed with saved state, got: %v", err)
	}
}

func TestDeployStatePersistenceIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()
	_ = r

	// Save state
	state := &attacker.DeployState{
		EC2: &attacker.EC2DeployState{
			InstanceID: "i-persist-test",
			Region:     "us-west-2",
			PublicIP:   "10.0.0.1",
		},
		Buckets: []attacker.BucketDeployState{
			{Name: "test-bucket", Type: "exfil", Region: "us-west-2"},
		},
	}
	if err := attacker.SaveDeployState(state); err != nil {
		t.Fatalf("Failed to save state: %v", err)
	}

	// Load in a new context (simulating a new session)
	loaded, err := attacker.LoadDeployState()
	if err != nil {
		t.Fatalf("Failed to load state: %v", err)
	}

	if loaded.EC2 == nil {
		t.Fatal("Expected EC2 state to persist")
	}
	if loaded.EC2.InstanceID != "i-persist-test" {
		t.Errorf("Expected instance ID i-persist-test, got %s", loaded.EC2.InstanceID)
	}
	if len(loaded.Buckets) != 1 {
		t.Fatalf("Expected 1 bucket, got %d", len(loaded.Buckets))
	}

	// Verify file is in expected location
	homeDir := os.Getenv("HOME")
	deployFile := filepath.Join(homeDir, ".pathrunner", "deploy.json")
	if _, err := os.Stat(deployFile); os.IsNotExist(err) {
		t.Error("deploy.json not found at expected path")
	}

	// Clean up
	attacker.RemoveDeployState()
}

func TestDeployBucketCommandRoutingIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Help and status should succeed without attacker identity
	commands := []string{
		"attacker infra bucket help",
		"attacker infra bucket status",
	}
	for _, cmd := range commands {
		err := r.ExecuteCommand(cmd)
		if err != nil {
			t.Errorf("Expected '%s' to succeed, got: %v", cmd, err)
		}
	}
}

func TestDeployBucketCreateRequiresAttackerIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("attacker infra bucket create --type exfil")
	if err == nil {
		t.Error("Expected error when no attacker identity for bucket create")
	}

	// Default action (no args) should also fail
	err = r.ExecuteCommand("attacker infra bucket")
	if err == nil {
		t.Error("Expected error when no attacker identity for bucket create (default)")
	}
}

func TestDeployBucketDestroyRequiresAttackerIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("attacker infra bucket destroy")
	if err == nil {
		t.Error("Expected error when no attacker identity for bucket destroy")
	}
}

func TestDeployBucketStatusWithSavedStateIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Save bucket state
	state := &attacker.DeployState{
		Buckets: []attacker.BucketDeployState{
			{Name: "test-exfil-abc123", Type: "exfil", Region: "us-east-1"},
		},
	}
	attacker.SaveDeployState(state)
	defer attacker.RemoveDeployState()

	err := r.ExecuteCommand("attacker infra bucket status")
	if err != nil {
		t.Errorf("Expected bucket status to succeed with saved state, got: %v", err)
	}
}

func TestDeployBucketUnknownActionIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("attacker infra bucket bogus")
	if err == nil {
		t.Error("Expected error for unknown deploy bucket action")
	}
}

func TestDeployUnknownResourceIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("attacker infra lambda")
	if err == nil {
		t.Error("Expected error for unknown deploy resource")
	}
}
