package unit

import (
	"pathrunner/pkg/modules"
	"testing"

	_ "pathrunner/pkg/exploits/cloudformation_passrole"
)

func TestCloudFormationPassRoleModule(t *testing.T) {
	const moduleID = "cloudformation-001"

	t.Run("LoadsByPrimaryID", func(t *testing.T) {
		mod, err := modules.LoadModule(moduleID)
		if err != nil {
			t.Fatalf("Failed to load %s: %v", moduleID, err)
		}
		if mod.Name() != moduleID {
			t.Errorf("Expected module name %q, got %q", moduleID, mod.Name())
		}
	})

	t.Run("LoadsByShortAlias", func(t *testing.T) {
		mod, err := modules.LoadModule("cloudformation-passrole")
		if err != nil {
			t.Fatalf("Failed to load by short alias: %v", err)
		}
		if mod.Name() != moduleID {
			t.Errorf("Expected module name %q, got %q", moduleID, mod.Name())
		}
	})

	t.Run("LoadsByOldAlias", func(t *testing.T) {
		mod, err := modules.LoadModule("exploit/cloudformation_passrole")
		if err != nil {
			t.Fatalf("Failed to load by old-format alias: %v", err)
		}
		if mod.Name() != moduleID {
			t.Errorf("Expected module name %q, got %q", moduleID, mod.Name())
		}
	})

	t.Run("LoadsByCFNAlias", func(t *testing.T) {
		mod, err := modules.LoadModule("cfn-001")
		if err != nil {
			t.Fatalf("Failed to load by cfn-001 alias: %v", err)
		}
		if mod.Name() != moduleID {
			t.Errorf("Expected module name %q, got %q", moduleID, mod.Name())
		}
	})

	t.Run("PathInfo", func(t *testing.T) {
		mod, err := modules.LoadModule(moduleID)
		if err != nil {
			t.Fatalf("Failed to load %s: %v", moduleID, err)
		}

		info := mod.PathInfo()

		if info.ID != moduleID {
			t.Errorf("Expected ID %q, got %q", moduleID, info.ID)
		}
		if info.Category != "new-passrole" {
			t.Errorf("Expected category %q, got %q", "new-passrole", info.Category)
		}

		expectedServices := []string{"iam", "cloudformation"}
		if len(info.Services) != len(expectedServices) {
			t.Errorf("Expected %d services, got %d", len(expectedServices), len(info.Services))
		} else {
			for i, svc := range expectedServices {
				if info.Services[i] != svc {
					t.Errorf("Expected service[%d]=%q, got %q", i, svc, info.Services[i])
				}
			}
		}

		if len(info.Permissions.Required) != 2 {
			t.Errorf("Expected 2 required permissions, got %d", len(info.Permissions.Required))
		}

		if info.Author != "Seth Art" {
			t.Errorf("Expected Author %q, got %q", "Seth Art", info.Author)
		}

		if info.MITRE == nil {
			t.Error("Expected MITRE mapping to be set")
		}
	})

	t.Run("Options", func(t *testing.T) {
		mod, err := modules.LoadModule(moduleID)
		if err != nil {
			t.Fatalf("Failed to load %s: %v", moduleID, err)
		}

		opts := mod.Options()
		if len(opts) == 0 {
			t.Fatal("Expected options to be non-empty")
		}

		// ROLE_ARN must be a required option.
		var roleArnRequired bool
		for _, opt := range opts {
			if opt.Name == "ROLE_ARN" && opt.Required {
				roleArnRequired = true
				break
			}
		}
		if !roleArnRequired {
			t.Error("Expected ROLE_ARN to be a required option")
		}
	})

	t.Run("Discoverable", func(t *testing.T) {
		mod, err := modules.LoadModule(moduleID)
		if err != nil {
			t.Fatalf("Failed to load %s: %v", moduleID, err)
		}

		discoverable, ok := mod.(modules.Discoverable)
		if !ok {
			t.Fatal("Expected module to implement Discoverable interface")
		}

		discOpts := discoverable.DiscoverableOptions()
		if len(discOpts) == 0 {
			t.Error("Expected at least one discoverable option")
		}

		// ROLE_ARN should be discoverable.
		found := false
		for _, opt := range discOpts {
			if opt == "ROLE_ARN" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected ROLE_ARN to be in discoverable options")
		}
	})

	t.Run("SearchFinds", func(t *testing.T) {
		results := modules.SearchModules(moduleID)
		found := false
		for _, info := range results {
			if info.ID == moduleID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected %s in search results", moduleID)
		}
	})

	t.Run("CategoryFilter", func(t *testing.T) {
		results := modules.ListModulesByCategory("new-passrole")
		found := false
		for _, info := range results {
			if info.ID == moduleID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected %s in new-passrole category results", moduleID)
		}
	})

	t.Run("ServiceFilter", func(t *testing.T) {
		results := modules.ListModulesByService("cloudformation")
		found := false
		for _, info := range results {
			if info.ID == moduleID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected %s in cloudformation service results", moduleID)
		}
	})
}
