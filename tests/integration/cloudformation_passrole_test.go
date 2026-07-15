package integration

import (
	"testing"

	_ "pathrunner/pkg/exploits/cloudformation_passrole"
)

func TestCloudFormationPassRoleIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	t.Run("UseByPrimaryID", func(t *testing.T) {
		err := r.ExecuteCommand("use cloudformation-001")
		if err != nil {
			t.Fatalf("Expected no error using cloudformation-001, got: %v", err)
		}

		mod := r.GetCurrentModule()
		if mod == nil {
			t.Fatal("Expected current module to be set")
		}
		if mod.Name() != "cloudformation-001" {
			t.Errorf("Expected module name cloudformation-001, got %q", mod.Name())
		}
	})

	t.Run("UseByShortAlias", func(t *testing.T) {
		err := r.ExecuteCommand("use cloudformation-passrole")
		if err != nil {
			t.Fatalf("Expected no error using cloudformation-passrole alias, got: %v", err)
		}

		mod := r.GetCurrentModule()
		if mod == nil {
			t.Fatal("Expected current module to be set")
		}
		if mod.Name() != "cloudformation-001" {
			t.Errorf("Expected module name cloudformation-001, got %q", mod.Name())
		}
	})

	t.Run("UseByOldAlias", func(t *testing.T) {
		err := r.ExecuteCommand("use exploit/cloudformation_passrole")
		if err != nil {
			t.Fatalf("Expected no error using exploit/cloudformation_passrole alias, got: %v", err)
		}

		mod := r.GetCurrentModule()
		if mod == nil {
			t.Fatal("Expected current module to be set")
		}
		if mod.Name() != "cloudformation-001" {
			t.Errorf("Expected module name cloudformation-001, got %q", mod.Name())
		}
	})

	t.Run("UseByCFNAlias", func(t *testing.T) {
		err := r.ExecuteCommand("use cfn-001")
		if err != nil {
			t.Fatalf("Expected no error using cfn-001 alias, got: %v", err)
		}

		mod := r.GetCurrentModule()
		if mod == nil {
			t.Fatal("Expected current module to be set")
		}
		if mod.Name() != "cloudformation-001" {
			t.Errorf("Expected module name cloudformation-001, got %q", mod.Name())
		}
	})

	t.Run("ShowInfo", func(t *testing.T) {
		err := r.ExecuteCommand("use cloudformation-001")
		if err != nil {
			t.Fatalf("Failed to use cloudformation-001: %v", err)
		}

		err = r.ExecuteCommand("show info")
		if err != nil {
			t.Errorf("Expected no error from show info, got: %v", err)
		}
	})

	t.Run("ShowOptions", func(t *testing.T) {
		err := r.ExecuteCommand("use cloudformation-001")
		if err != nil {
			t.Fatalf("Failed to use cloudformation-001: %v", err)
		}

		err = r.ExecuteCommand("show options")
		if err != nil {
			t.Errorf("Expected no error from show options, got: %v", err)
		}
	})

	t.Run("SearchByID", func(t *testing.T) {
		err := r.ExecuteCommand("search cloudformation-001")
		if err != nil {
			t.Errorf("Expected no error from search cloudformation-001, got: %v", err)
		}
	})

	t.Run("SearchByService", func(t *testing.T) {
		err := r.ExecuteCommand("search cloudformation")
		if err != nil {
			t.Errorf("Expected no error from search cloudformation, got: %v", err)
		}
	})
}
