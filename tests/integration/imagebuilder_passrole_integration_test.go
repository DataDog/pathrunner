package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/imagebuilder_passrole"
)

func TestImagebuilderPassroleModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by primary ID
	if err := r.ExecuteCommand("use imagebuilder-001"); err != nil {
		t.Fatalf("Failed to use imagebuilder-001: %v", err)
	}
}

func TestImagebuilderPassroleModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select by the canonical alias
	if err := r.ExecuteCommand("use imagebuilder-passrole"); err != nil {
		t.Fatalf("Failed to use imagebuilder-passrole alias: %v", err)
	}
}

func TestImagebuilderPassroleModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use imagebuilder-001"); err != nil {
		t.Fatalf("Failed to use imagebuilder-001: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestImagebuilderPassroleModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use imagebuilder-001"); err != nil {
		t.Fatalf("Failed to use imagebuilder-001: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestImagebuilderPassroleModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use imagebuilder-001"); err != nil {
		t.Fatalf("Failed to use imagebuilder-001: %v", err)
	}

	if err := r.ExecuteCommand("set INSTANCE_PROFILE pl-prod-imagebuilder-001-to-admin-admin-profile"); err != nil {
		t.Fatalf("Expected set INSTANCE_PROFILE to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set TARGET_USER pl-prod-imagebuilder-001-to-admin-starting-user"); err != nil {
		t.Fatalf("Expected set TARGET_USER to succeed: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestImagebuilderPassroleModuleSearch(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// search imagebuilder should find the module
	if err := r.ExecuteCommand("search imagebuilder"); err != nil {
		t.Fatalf("Expected search imagebuilder to succeed: %v", err)
	}
}

func TestImagebuilderPassroleModuleShowPayloads(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use imagebuilder-001"); err != nil {
		t.Fatalf("Failed to use imagebuilder-001: %v", err)
	}

	// show payloads should list available imagebuilder payloads
	if err := r.ExecuteCommand("show payloads"); err != nil {
		t.Fatalf("Expected show payloads to succeed: %v", err)
	}
}
