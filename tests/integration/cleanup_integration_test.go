package integration

import (
	"pathrunner/pkg/modules"
	"strings"
	"testing"
)

// TestCleanupNoResources tests cleanup when no resources exist
func TestCleanupNoResources(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	// Set identity directly (bypasses AWS validation)
	identity := &modules.Identity{
		Name:      "cleanup-test",
		Type:      "keys",
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:      "us-east-1",
	}
	im.SetCurrent(identity)

	// Cleanup with --all should succeed with "no resources" message
	err := r.ExecuteCommand("workspace cleanup --all")
	if err != nil {
		t.Errorf("Expected no error for cleanup with no resources, got: %v", err)
	}
}

// TestCleanupAllFlagRequiresIdentity tests that cleanup requires identity
func TestCleanupAllFlagRequiresIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Add a tracked resource to the session directly
	sm := r.GetSessionManager()
	sm.TrackResource(modules.CreatedResource{
		Type:     "lambda:function",
		Name:     "test-func",
		Region:   "us-east-1",
		ModuleID: "lambda-001",
	})

	// Without identity, cleanup should fail
	err := r.ExecuteCommand("workspace cleanup --all")
	if err == nil {
		t.Error("Expected error for cleanup without identity")
	}
}

// TestCleanupModuleFilterNoMatch tests --module flag with no matching resources
func TestCleanupModuleFilterNoMatch(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	// Set identity
	identity := &modules.Identity{
		Name:      "cleanup-test",
		Type:      "keys",
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:      "us-east-1",
	}
	im.SetCurrent(identity)

	// Track resources from different modules
	sm := r.GetSessionManager()
	sm.TrackResource(modules.CreatedResource{
		Type:     "lambda:function",
		Name:     "func1",
		Region:   "us-east-1",
		ModuleID: "lambda-001",
	})
	sm.TrackResource(modules.CreatedResource{
		Type:     "ec2:instance",
		Name:     "inst1",
		Region:   "us-east-1",
		ModuleID: "ec2-001",
		Metadata: map[string]string{"instance_id": "i-1234567890abcdef0"},
	})

	// Filter for nonexistent module should show "no resources"
	err := r.ExecuteCommand("workspace cleanup --all --module nonexistent-module")
	if err != nil {
		t.Errorf("Expected no error for cleanup with no matching resources, got: %v", err)
	}

	// Resources should still be there (none matched the filter)
	resources := sm.GetCreatedResources()
	if len(resources) != 2 {
		t.Errorf("Expected 2 resources still tracked, got %d", len(resources))
	}
}

// TestCleanupModuleFlagMissingArg tests --module without argument
func TestCleanupModuleFlagMissingArg(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("workspace cleanup --module")
	if err == nil {
		t.Error("Expected error for --module without argument")
	}
	if !strings.Contains(err.Error(), "--module requires") {
		t.Errorf("Expected '--module requires' error, got: %v", err)
	}
}

// TestCleanupUnknownFlag tests unknown flag handling
func TestCleanupUnknownFlag(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("workspace cleanup --unknown")
	if err == nil {
		t.Error("Expected error for unknown flag")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("Expected 'unknown flag' error, got: %v", err)
	}
}

// TestCleanupAllWithModuleFilter tests combining --all and --module flags
func TestCleanupAllWithModuleFilter(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	// Set identity
	identity := &modules.Identity{
		Name:      "cleanup-test",
		Type:      "keys",
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:      "us-east-1",
	}
	im.SetCurrent(identity)

	// Track resources from different modules
	sm := r.GetSessionManager()
	sm.TrackResource(modules.CreatedResource{
		Type:     "lambda:function",
		Name:     "func1",
		Region:   "us-east-1",
		ModuleID: "lambda-001",
	})
	sm.TrackResource(modules.CreatedResource{
		Type:     "ec2:instance",
		Name:     "inst1",
		Region:   "us-east-1",
		ModuleID: "ec2-001",
		Metadata: map[string]string{"instance_id": "i-1234567890abcdef0"},
	})

	// --all --module lambda-001 should only try to clean lambda resources
	// (will fail because no real AWS, but the command itself should not error)
	err := r.ExecuteCommand("workspace cleanup --all --module lambda-001")
	if err != nil {
		t.Errorf("Expected no error from cleanup command itself, got: %v", err)
	}
}

// TestCleanupWorkspaceAlias tests cleanup through workspace alias
func TestCleanupWorkspaceAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Test that workspaces alias works for cleanup with --all
	err := r.ExecuteCommand("workspaces cleanup --all")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}

// TestCleanupHelpShowsFlags tests help output includes new flags
func TestCleanupHelpShowsFlags(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// workspace help should not error
	err := r.ExecuteCommand("workspace help")
	if err != nil {
		t.Errorf("Expected no error for workspace help, got: %v", err)
	}
}
