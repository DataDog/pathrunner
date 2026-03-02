package unit

import (
	"pathrunner/pkg/modules"
	"testing"

	// Import modules to register them
	_ "pathrunner/pkg/exploits/ec2_passrole"
	_ "pathrunner/pkg/exploits/lambda_passrole"
	_ "pathrunner/pkg/exploits/sts_assume_role"
)

func TestPathInfoFields(t *testing.T) {
	t.Run("PathfindingCloudURL", func(t *testing.T) {
		info := modules.PathInfo{ID: "lambda-001"}
		expected := "https://pathfinding.cloud/paths/lambda-001"
		if got := info.PathfindingCloudURL(); got != expected {
			t.Errorf("Expected URL %q, got %q", expected, got)
		}
	})

	t.Run("PathfindingCloudURL_Empty", func(t *testing.T) {
		info := modules.PathInfo{}
		if got := info.PathfindingCloudURL(); got != "" {
			t.Errorf("Expected empty URL for empty ID, got %q", got)
		}
	})
}

func TestBaseModule(t *testing.T) {
	t.Run("DefaultMethods", func(t *testing.T) {
		base := &modules.BaseModule{
			Info: modules.PathInfo{
				ID:          "test-001",
				Description: "Test module description",
			},
		}

		if base.Name() != "test-001" {
			t.Errorf("Expected Name() = %q, got %q", "test-001", base.Name())
		}

		if base.Description() != "Test module description" {
			t.Errorf("Expected Description() = %q, got %q", "Test module description", base.Description())
		}

		if got := base.PathInfo(); got.ID != "test-001" {
			t.Errorf("Expected PathInfo().ID = %q, got %q", "test-001", got.ID)
		}
	})

	t.Run("DefaultPayloadMethods", func(t *testing.T) {
		base := &modules.BaseModule{}

		opts := base.PayloadOptions("anything")
		if len(opts) != 0 {
			t.Errorf("Expected empty PayloadOptions, got %d", len(opts))
		}

		payloads := base.ListPayloads()
		if len(payloads) != 0 {
			t.Errorf("Expected empty ListPayloads, got %d", len(payloads))
		}
	})
}

func TestRegistryAliasResolution(t *testing.T) {
	t.Run("LoadByPrimaryID", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-001")
		if err != nil {
			t.Errorf("Expected no error loading lambda-001, got: %v", err)
		}
		if mod == nil {
			t.Fatal("Expected non-nil module")
		}
		if mod.Name() != "lambda-001" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-001", mod.Name())
		}
	})

	t.Run("LoadByAlias_OldFormat", func(t *testing.T) {
		mod, err := modules.LoadModule("exploit/lambda_passrole")
		if err != nil {
			t.Errorf("Expected no error loading alias exploit/lambda_passrole, got: %v", err)
		}
		if mod == nil {
			t.Fatal("Expected non-nil module")
		}
		if mod.Name() != "lambda-001" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-001", mod.Name())
		}
	})

	t.Run("LoadByAlias_ShortForm", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-passrole")
		if err != nil {
			t.Errorf("Expected no error loading alias lambda-passrole, got: %v", err)
		}
		if mod == nil {
			t.Fatal("Expected non-nil module")
		}
		if mod.Name() != "lambda-001" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-001", mod.Name())
		}
	})

	t.Run("LoadByAlias_EC2", func(t *testing.T) {
		mod, err := modules.LoadModule("exploit/ec2_passrole")
		if err != nil {
			t.Errorf("Expected no error loading alias exploit/ec2_passrole, got: %v", err)
		}
		if mod == nil {
			t.Fatal("Expected non-nil module")
		}
		if mod.Name() != "ec2-001" {
			t.Errorf("Expected Name() = %q, got %q", "ec2-001", mod.Name())
		}
	})

	t.Run("LoadByAlias_STS", func(t *testing.T) {
		mod, err := modules.LoadModule("exploit/sts_assume_role")
		if err != nil {
			t.Errorf("Expected no error loading alias exploit/sts_assume_role, got: %v", err)
		}
		if mod == nil {
			t.Fatal("Expected non-nil module")
		}
		if mod.Name() != "sts-001" {
			t.Errorf("Expected Name() = %q, got %q", "sts-001", mod.Name())
		}
	})

	t.Run("LoadNonexistent", func(t *testing.T) {
		_, err := modules.LoadModule("nonexistent-module")
		if err == nil {
			t.Error("Expected error for nonexistent module")
		}
	})
}

func TestGetPathInfo(t *testing.T) {
	t.Run("ByPrimaryID", func(t *testing.T) {
		info, found := modules.GetPathInfo("lambda-001")
		if !found {
			t.Fatal("Expected to find PathInfo for lambda-001")
		}
		if info.ID != "lambda-001" {
			t.Errorf("Expected ID %q, got %q", "lambda-001", info.ID)
		}
		if info.Category != "new-passrole" {
			t.Errorf("Expected Category %q, got %q", "new-passrole", info.Category)
		}
	})

	t.Run("ByAlias", func(t *testing.T) {
		info, found := modules.GetPathInfo("exploit/lambda_passrole")
		if !found {
			t.Fatal("Expected to find PathInfo for alias exploit/lambda_passrole")
		}
		if info.ID != "lambda-001" {
			t.Errorf("Expected ID %q, got %q", "lambda-001", info.ID)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		_, found := modules.GetPathInfo("nonexistent")
		if found {
			t.Error("Expected not found for nonexistent module")
		}
	})
}

func TestSearchModules(t *testing.T) {
	t.Run("ByService", func(t *testing.T) {
		results := modules.SearchModules("lambda")
		if len(results) == 0 {
			t.Fatal("Expected at least one result for 'lambda'")
		}
		foundLambda := false
		for _, info := range results {
			if info.ID == "lambda-001" {
				foundLambda = true
			}
		}
		if !foundLambda {
			t.Error("Expected lambda-001 in search results for 'lambda'")
		}
	})

	t.Run("ByCategory", func(t *testing.T) {
		results := modules.SearchModules("passrole")
		if len(results) < 2 {
			t.Errorf("Expected at least 2 results for 'passrole', got %d", len(results))
		}
	})

	t.Run("ByPermission", func(t *testing.T) {
		results := modules.SearchModules("iam:PassRole")
		if len(results) < 2 {
			t.Errorf("Expected at least 2 results for 'iam:PassRole', got %d", len(results))
		}
	})

	t.Run("ByAlias", func(t *testing.T) {
		results := modules.SearchModules("ec2-passrole")
		foundEC2 := false
		for _, info := range results {
			if info.ID == "ec2-001" {
				foundEC2 = true
			}
		}
		if !foundEC2 {
			t.Error("Expected ec2-001 in search results for 'ec2-passrole'")
		}
	})

	t.Run("NoResults", func(t *testing.T) {
		results := modules.SearchModules("zzz_nonexistent_xyz")
		if len(results) != 0 {
			t.Errorf("Expected 0 results, got %d", len(results))
		}
	})

	t.Run("CaseInsensitive", func(t *testing.T) {
		results := modules.SearchModules("LAMBDA")
		if len(results) == 0 {
			t.Fatal("Expected results for case-insensitive 'LAMBDA' search")
		}
	})
}

func TestListModulesByCategory(t *testing.T) {
	t.Run("NewPassrole", func(t *testing.T) {
		results := modules.ListModulesByCategory("new-passrole")
		if len(results) < 2 {
			t.Errorf("Expected at least 2 new-passrole modules, got %d", len(results))
		}
	})

	t.Run("PrincipalAccess", func(t *testing.T) {
		results := modules.ListModulesByCategory("principal-access")
		if len(results) < 1 {
			t.Errorf("Expected at least 1 principal-access module, got %d", len(results))
		}
		foundSTS := false
		for _, info := range results {
			if info.ID == "sts-001" {
				foundSTS = true
			}
		}
		if !foundSTS {
			t.Error("Expected sts-001 in principal-access category")
		}
	})

	t.Run("Empty", func(t *testing.T) {
		results := modules.ListModulesByCategory("nonexistent-category")
		if len(results) != 0 {
			t.Errorf("Expected 0 results, got %d", len(results))
		}
	})
}

func TestListModulesByService(t *testing.T) {
	t.Run("EC2", func(t *testing.T) {
		results := modules.ListModulesByService("ec2")
		if len(results) < 1 {
			t.Errorf("Expected at least 1 ec2 module, got %d", len(results))
		}
		foundEC2 := false
		for _, info := range results {
			if info.ID == "ec2-001" {
				foundEC2 = true
			}
		}
		if !foundEC2 {
			t.Error("Expected ec2-001 in ec2 service results")
		}
	})

	t.Run("IAM", func(t *testing.T) {
		results := modules.ListModulesByService("iam")
		if len(results) < 2 {
			t.Errorf("Expected at least 2 modules involving IAM, got %d", len(results))
		}
	})

	t.Run("Empty", func(t *testing.T) {
		results := modules.ListModulesByService("nonexistent-service")
		if len(results) != 0 {
			t.Errorf("Expected 0 results, got %d", len(results))
		}
	})
}

func TestListPathInfos(t *testing.T) {
	infos := modules.ListPathInfos()
	if len(infos) < 3 {
		t.Errorf("Expected at least 3 PathInfos, got %d", len(infos))
	}

	// Verify sorted by ID
	for i := 1; i < len(infos); i++ {
		if infos[i].ID < infos[i-1].ID {
			t.Errorf("PathInfos not sorted: %q before %q", infos[i-1].ID, infos[i].ID)
		}
	}
}

func TestPathInfoCachePopulation(t *testing.T) {
	// Verify that registration populates the cache
	info, found := modules.GetPathInfo("ec2-001")
	if !found {
		t.Fatal("Expected ec2-001 in PathInfo cache")
	}

	if len(info.Services) == 0 {
		t.Error("Expected non-empty Services for ec2-001")
	}

	if len(info.Permissions.Required) == 0 {
		t.Error("Expected non-empty Required Permissions for ec2-001")
	}

	if info.MITRE == nil {
		t.Error("Expected non-nil MITRE mapping for ec2-001")
	}

	if len(info.Aliases) == 0 {
		t.Error("Expected non-empty Aliases for ec2-001")
	}
}

func TestModulePathInfoMethod(t *testing.T) {
	mod, err := modules.LoadModule("lambda-001")
	if err != nil {
		t.Fatalf("Failed to load lambda-001: %v", err)
	}

	info := mod.PathInfo()
	if info.ID != "lambda-001" {
		t.Errorf("Expected PathInfo().ID = %q, got %q", "lambda-001", info.ID)
	}
	if info.Name != "iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction" {
		t.Errorf("Unexpected PathInfo().Name: %q", info.Name)
	}
	if info.Category != "new-passrole" {
		t.Errorf("Expected Category %q, got %q", "new-passrole", info.Category)
	}
}
