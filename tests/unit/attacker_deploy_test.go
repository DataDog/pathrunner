package unit

import (
	"os"
	"path/filepath"
	"pathrunner/pkg/attacker"
	"pathrunner/pkg/core/repl"
	"testing"
)

// --- Deploy state persistence tests ---

func TestDeployStateSaveLoad(t *testing.T) {
	// Use temp dir as HOME to avoid touching real state
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	state := &attacker.DeployState{
		EC2: &attacker.EC2DeployState{
			InstanceID:      "i-0abc123def456",
			Region:          "us-east-1",
			PublicIP:        "54.123.45.67",
			SecurityGroupID: "sg-12345",
			KeyPairName:     "pathrunner-deploy",
			KeyFilePath:     "/home/user/.pathrunner/keys/pathrunner-deploy.pem",
		},
		Buckets: []attacker.BucketDeployState{
			{Name: "pathrunner-exfil-abc123", Type: "exfil", Region: "us-east-1"},
			{Name: "pathrunner-code-def456", Type: "code", Region: "us-east-1"},
		},
	}

	// Save
	if err := attacker.SaveDeployState(state); err != nil {
		t.Fatalf("Failed to save deploy state: %v", err)
	}

	// Verify file exists
	deployFile := filepath.Join(tempDir, ".pathrunner", "deploy.json")
	if _, err := os.Stat(deployFile); os.IsNotExist(err) {
		t.Fatal("deploy.json was not created")
	}

	// Load
	loaded, err := attacker.LoadDeployState()
	if err != nil {
		t.Fatalf("Failed to load deploy state: %v", err)
	}

	// Verify EC2 state
	if loaded.EC2 == nil {
		t.Fatal("Expected EC2 state to be loaded")
	}
	if loaded.EC2.InstanceID != "i-0abc123def456" {
		t.Errorf("Expected instance ID i-0abc123def456, got %s", loaded.EC2.InstanceID)
	}
	if loaded.EC2.PublicIP != "54.123.45.67" {
		t.Errorf("Expected public IP 54.123.45.67, got %s", loaded.EC2.PublicIP)
	}
	if loaded.EC2.Region != "us-east-1" {
		t.Errorf("Expected region us-east-1, got %s", loaded.EC2.Region)
	}

	// Verify bucket state
	if len(loaded.Buckets) != 2 {
		t.Fatalf("Expected 2 buckets, got %d", len(loaded.Buckets))
	}
	if loaded.Buckets[0].Name != "pathrunner-exfil-abc123" {
		t.Errorf("Expected first bucket name pathrunner-exfil-abc123, got %s", loaded.Buckets[0].Name)
	}
	if loaded.Buckets[0].Type != "exfil" {
		t.Errorf("Expected first bucket type exfil, got %s", loaded.Buckets[0].Type)
	}
}

func TestDeployStateLoadNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// Load from non-existent file should return empty state
	state, err := attacker.LoadDeployState()
	if err != nil {
		t.Fatalf("Expected empty state for non-existent file, got error: %v", err)
	}
	if state.EC2 != nil {
		t.Error("Expected nil EC2 state")
	}
	if len(state.Buckets) != 0 {
		t.Error("Expected no buckets")
	}
}

func TestDeployStateRemove(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// Save a state first
	state := &attacker.DeployState{
		EC2: &attacker.EC2DeployState{InstanceID: "i-test"},
	}
	attacker.SaveDeployState(state)

	// Remove it
	if err := attacker.RemoveDeployState(); err != nil {
		t.Fatalf("Failed to remove deploy state: %v", err)
	}

	// Should be empty now
	loaded, err := attacker.LoadDeployState()
	if err != nil {
		t.Fatalf("Expected empty state after remove, got error: %v", err)
	}
	if loaded.EC2 != nil {
		t.Error("Expected nil EC2 state after remove")
	}
}

func TestDeployStateRemoveNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// Remove non-existent file should not error
	if err := attacker.RemoveDeployState(); err != nil {
		t.Fatalf("Expected no error removing non-existent state, got: %v", err)
	}
}

func TestDeployStateHasResources(t *testing.T) {
	tests := []struct {
		name     string
		state    attacker.DeployState
		expected bool
	}{
		{
			name:     "empty state",
			state:    attacker.DeployState{},
			expected: false,
		},
		{
			name:     "EC2 only",
			state:    attacker.DeployState{EC2: &attacker.EC2DeployState{InstanceID: "i-test"}},
			expected: true,
		},
		{
			name:     "buckets only",
			state:    attacker.DeployState{Buckets: []attacker.BucketDeployState{{Name: "test"}}},
			expected: true,
		},
		{
			name: "both",
			state: attacker.DeployState{
				EC2:     &attacker.EC2DeployState{InstanceID: "i-test"},
				Buckets: []attacker.BucketDeployState{{Name: "test"}},
			},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if result := tc.state.HasAnyDeployedResources(); result != tc.expected {
				t.Errorf("Expected HasAnyDeployedResources()=%v, got %v", tc.expected, result)
			}
		})
	}
}

func TestDeployStateFilePermissions(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	state := &attacker.DeployState{
		EC2: &attacker.EC2DeployState{InstanceID: "i-test"},
	}
	attacker.SaveDeployState(state)

	// Check file permissions are restrictive (0600)
	deployFile := filepath.Join(tempDir, ".pathrunner", "deploy.json")
	info, err := os.Stat(deployFile)
	if err != nil {
		t.Fatalf("Failed to stat deploy file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("Expected file permissions 0600, got %o", perm)
	}
}

func TestDeployStateSaveUpdatesExisting(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// Save initial state
	state := &attacker.DeployState{
		EC2: &attacker.EC2DeployState{InstanceID: "i-first", PublicIP: "1.2.3.4"},
	}
	attacker.SaveDeployState(state)

	// Update and save again
	state.EC2.PublicIP = "5.6.7.8"
	state.Buckets = []attacker.BucketDeployState{{Name: "new-bucket", Type: "exfil", Region: "us-west-2"}}
	attacker.SaveDeployState(state)

	// Load and verify update
	loaded, _ := attacker.LoadDeployState()
	if loaded.EC2.PublicIP != "5.6.7.8" {
		t.Errorf("Expected updated IP 5.6.7.8, got %s", loaded.EC2.PublicIP)
	}
	if len(loaded.Buckets) != 1 || loaded.Buckets[0].Name != "new-bucket" {
		t.Error("Expected updated bucket list")
	}
}

// --- REPL deploy command routing tests ---

func TestAttackerDeployHelp(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker infra help")
	if err != nil {
		t.Errorf("Expected deploy help to succeed, got: %v", err)
	}
}

func TestAttackerDeployDefault(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	// Running 'attacker infra' with no args shows help
	err := r.ExecuteCommand("attacker infra")
	if err != nil {
		t.Errorf("Expected deploy (default help) to succeed, got: %v", err)
	}
}

func TestAttackerDeployEC2Help(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker infra ec2 help")
	if err != nil {
		t.Errorf("Expected deploy ec2 help to succeed, got: %v", err)
	}
}

func TestAttackerDeployEC2CreateNoAttacker(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	// Should fail because no attacker identity is set
	err := r.ExecuteCommand("attacker infra ec2 create")
	if err == nil {
		t.Error("Expected error when no attacker identity is set")
	}
}

func TestAttackerDeployEC2StatusNoDeployment(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	// Should succeed and show "no deployment"
	err := r.ExecuteCommand("attacker infra ec2 status")
	if err != nil {
		t.Errorf("Expected ec2 status to succeed when no deployment, got: %v", err)
	}
}

func TestAttackerDeployEC2DestroyNoAttacker(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker infra ec2 destroy")
	if err == nil {
		t.Error("Expected error when no attacker identity is set for destroy")
	}
}

func TestAttackerDeployStatusNoDeployment(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	// Global status should succeed when nothing is deployed
	err := r.ExecuteCommand("attacker infra status")
	if err != nil {
		t.Errorf("Expected global deploy status to succeed, got: %v", err)
	}
}

func TestAttackerDeployDestroyNoDeployment(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	// Global destroy should succeed when nothing is deployed
	err := r.ExecuteCommand("attacker infra destroy")
	if err != nil {
		t.Errorf("Expected global deploy destroy to succeed, got: %v", err)
	}
}

func TestAttackerDeployUnknownResource(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker infra bogus")
	if err == nil {
		t.Error("Expected error for unknown deploy resource")
	}
}

func TestAttackerDeployEC2UnknownAction(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker infra ec2 bogus")
	if err == nil {
		t.Error("Expected error for unknown deploy ec2 action")
	}
}

// --- Bucket deploy REPL command routing tests ---

func TestAttackerDeployBucketHelp(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker infra bucket help")
	if err != nil {
		t.Errorf("Expected deploy bucket help to succeed, got: %v", err)
	}
}

func TestAttackerDeployBucketCreateNoAttacker(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker infra bucket create")
	if err == nil {
		t.Error("Expected error when no attacker identity is set")
	}
}

func TestAttackerDeployBucketDefaultNoAttacker(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	// Running 'attacker infra bucket' with no action defaults to create
	err := r.ExecuteCommand("attacker infra bucket")
	if err == nil {
		t.Error("Expected error when no attacker identity is set (default create)")
	}
}

func TestAttackerDeployBucketStatusNoDeployment(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker infra bucket status")
	if err != nil {
		t.Errorf("Expected bucket status to succeed with no buckets, got: %v", err)
	}
}

func TestAttackerDeployBucketDestroyNoAttacker(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker infra bucket destroy")
	if err == nil {
		t.Error("Expected error when no attacker identity for bucket destroy")
	}
}

func TestAttackerDeployBucketUnknownAction(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker infra bucket bogus")
	if err == nil {
		t.Error("Expected error for unknown deploy bucket action")
	}
}

func TestGetCodeBucket(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// No state — should return empty
	if got := attacker.GetCodeBucket(); got != "" {
		t.Errorf("Expected empty string for no state, got %s", got)
	}

	// State with only exfil bucket — should return empty
	state := &attacker.DeployState{
		Buckets: []attacker.BucketDeployState{
			{Name: "test-exfil", Type: "exfil", Region: "us-east-1"},
		},
	}
	attacker.SaveDeployState(state)

	if got := attacker.GetCodeBucket(); got != "" {
		t.Errorf("Expected empty string with only exfil bucket, got %s", got)
	}

	// State with code bucket — should return it
	state.Buckets = append(state.Buckets, attacker.BucketDeployState{
		Name: "test-code", Type: "code", Region: "us-east-1",
	})
	attacker.SaveDeployState(state)

	if got := attacker.GetCodeBucket(); got != "test-code" {
		t.Errorf("Expected test-code, got %s", got)
	}

	attacker.RemoveDeployState()
}

func TestGetExfilBucket(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// No state — should return empty
	if got := attacker.GetExfilBucket(); got != "" {
		t.Errorf("Expected empty string for no state, got %s", got)
	}

	// State with exfil bucket — should return it
	state := &attacker.DeployState{
		Buckets: []attacker.BucketDeployState{
			{Name: "test-exfil", Type: "exfil", Region: "us-east-1"},
		},
	}
	attacker.SaveDeployState(state)

	if got := attacker.GetExfilBucket(); got != "test-exfil" {
		t.Errorf("Expected test-exfil, got %s", got)
	}

	attacker.RemoveDeployState()
}

func TestHasDeployedBuckets(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// No state
	if attacker.HasDeployedBuckets() {
		t.Error("Expected false for no state")
	}

	// With buckets
	state := &attacker.DeployState{
		Buckets: []attacker.BucketDeployState{
			{Name: "test-bucket", Type: "exfil", Region: "us-east-1"},
		},
	}
	attacker.SaveDeployState(state)

	if !attacker.HasDeployedBuckets() {
		t.Error("Expected true with deployed buckets")
	}

	attacker.RemoveDeployState()
}

func TestAttackerDeployBucketStatusWithSavedBuckets(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// Save some bucket state
	state := &attacker.DeployState{
		Buckets: []attacker.BucketDeployState{
			{Name: "test-exfil-bucket", Type: "exfil", Region: "us-east-1"},
			{Name: "test-code-bucket", Type: "code", Region: "us-west-2"},
		},
	}
	attacker.SaveDeployState(state)
	defer attacker.RemoveDeployState()

	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker infra bucket status")
	if err != nil {
		t.Errorf("Expected bucket status to succeed with saved buckets, got: %v", err)
	}
}
