package unit

import (
	"pathrunner/pkg/modules"
	"testing"

	// Import modules to register them
	_ "pathrunner/pkg/exploits/ec2_passrole"
	_ "pathrunner/pkg/exploits/iam_addusertogroup"
	_ "pathrunner/pkg/exploits/iam_attachgrouppolicy"
	_ "pathrunner/pkg/exploits/iam_attachrolepolicy"
	_ "pathrunner/pkg/exploits/iam_attachrolepolicy_assumerole"
	_ "pathrunner/pkg/exploits/iam_attachrolepolicy_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_attachuserpolicy"
	_ "pathrunner/pkg/exploits/iam_attachuserpolicy_createaccesskey"
	_ "pathrunner/pkg/exploits/iam_create_policy_version"
	_ "pathrunner/pkg/exploits/iam_createaccesskey"
	_ "pathrunner/pkg/exploits/iam_createloginprofile"
	_ "pathrunner/pkg/exploits/iam_createpolicyversion_assumerole"
	_ "pathrunner/pkg/exploits/iam_createpolicyversion_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_deleteaccesskey_createaccesskey"
	_ "pathrunner/pkg/exploits/iam_putgrouppolicy"
	_ "pathrunner/pkg/exploits/iam_putrolepolicy"
	_ "pathrunner/pkg/exploits/iam_putrolepolicy_assumerole"
	_ "pathrunner/pkg/exploits/iam_putrolepolicy_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_putuserpolicy"
	_ "pathrunner/pkg/exploits/iam_putuserpolicy_createaccesskey"
	_ "pathrunner/pkg/exploits/iam_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_updateloginprofile"
	_ "pathrunner/pkg/exploits/lambda_createfunction_addpermission"
	_ "pathrunner/pkg/exploits/lambda_passrole"
	_ "pathrunner/pkg/exploits/lambda_passrole_esm"
	_ "pathrunner/pkg/exploits/lambda_updatecode"
	_ "pathrunner/pkg/exploits/lambda_updatecode_addpermission"
	_ "pathrunner/pkg/exploits/lambda_updatecode_invoke"
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

func TestLambda002Module(t *testing.T) {
	t.Run("LoadByPrimaryID", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-002")
		if err != nil {
			t.Fatalf("Expected no error loading lambda-002, got: %v", err)
		}
		if mod == nil {
			t.Fatal("Expected non-nil module")
		}
		if mod.Name() != "lambda-002" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-002", mod.Name())
		}
	})

	t.Run("LoadByAlias_ShortForm", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-passrole-esm")
		if err != nil {
			t.Fatalf("Expected no error loading lambda-passrole-esm, got: %v", err)
		}
		if mod.Name() != "lambda-002" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-002", mod.Name())
		}
	})

	t.Run("LoadByAlias_OldFormat", func(t *testing.T) {
		mod, err := modules.LoadModule("exploit/lambda_passrole_esm")
		if err != nil {
			t.Fatalf("Expected no error loading exploit/lambda_passrole_esm, got: %v", err)
		}
		if mod.Name() != "lambda-002" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-002", mod.Name())
		}
	})

	t.Run("PathInfoFields", func(t *testing.T) {
		info, found := modules.GetPathInfo("lambda-002")
		if !found {
			t.Fatal("Expected to find PathInfo for lambda-002")
		}
		if info.ID != "lambda-002" {
			t.Errorf("Expected ID %q, got %q", "lambda-002", info.ID)
		}
		if info.Category != "new-passrole" {
			t.Errorf("Expected Category %q, got %q", "new-passrole", info.Category)
		}
		if len(info.Services) != 2 {
			t.Errorf("Expected 2 services, got %d", len(info.Services))
		}
		if len(info.Permissions.Required) != 3 {
			t.Errorf("Expected 3 required permissions, got %d", len(info.Permissions.Required))
		}
		if info.MITRE == nil {
			t.Error("Expected non-nil MITRE mapping")
		}
		if len(info.MITRE.Tactics) != 2 {
			t.Errorf("Expected 2 MITRE tactics, got %d", len(info.MITRE.Tactics))
		}
		if len(info.Aliases) != 2 {
			t.Errorf("Expected 2 aliases, got %d", len(info.Aliases))
		}
		if len(info.RelatedPaths) != 2 {
			t.Errorf("Expected 2 related paths, got %d", len(info.RelatedPaths))
		}
	})

	t.Run("SearchFindsLambda002", func(t *testing.T) {
		results := modules.SearchModules("lambda-002")
		found := false
		for _, info := range results {
			if info.ID == "lambda-002" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-002 in search results")
		}
	})

	t.Run("SearchByEventSourceMapping", func(t *testing.T) {
		results := modules.SearchModules("CreateEventSourceMapping")
		found := false
		for _, info := range results {
			if info.ID == "lambda-002" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-002 in search results for 'CreateEventSourceMapping'")
		}
	})

	t.Run("CategoryFilter", func(t *testing.T) {
		results := modules.ListModulesByCategory("new-passrole")
		found := false
		for _, info := range results {
			if info.ID == "lambda-002" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-002 in new-passrole category")
		}
	})

	t.Run("ServiceFilter", func(t *testing.T) {
		results := modules.ListModulesByService("lambda")
		found := false
		for _, info := range results {
			if info.ID == "lambda-002" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-002 in lambda service results")
		}
	})
}

func TestLambda004Module(t *testing.T) {
	t.Run("LoadByPrimaryID", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-004")
		if err != nil {
			t.Fatalf("Expected no error loading lambda-004, got: %v", err)
		}
		if mod == nil {
			t.Fatal("Expected non-nil module")
		}
		if mod.Name() != "lambda-004" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-004", mod.Name())
		}
	})

	t.Run("LoadByAlias_ShortForm", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-updatecode-invoke")
		if err != nil {
			t.Fatalf("Expected no error loading lambda-updatecode-invoke, got: %v", err)
		}
		if mod.Name() != "lambda-004" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-004", mod.Name())
		}
	})

	t.Run("LoadByAlias_OldFormat", func(t *testing.T) {
		mod, err := modules.LoadModule("exploit/lambda_updatecode_invoke")
		if err != nil {
			t.Fatalf("Expected no error loading exploit/lambda_updatecode_invoke, got: %v", err)
		}
		if mod.Name() != "lambda-004" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-004", mod.Name())
		}
	})

	t.Run("PathInfoFields", func(t *testing.T) {
		info, found := modules.GetPathInfo("lambda-004")
		if !found {
			t.Fatal("Expected to find PathInfo for lambda-004")
		}
		if info.ID != "lambda-004" {
			t.Errorf("Expected ID %q, got %q", "lambda-004", info.ID)
		}
		if info.Category != "existing-passrole" {
			t.Errorf("Expected Category %q, got %q", "existing-passrole", info.Category)
		}
		if len(info.Services) != 1 {
			t.Errorf("Expected 1 service, got %d", len(info.Services))
		}
		if info.Services[0] != "lambda" {
			t.Errorf("Expected service %q, got %q", "lambda", info.Services[0])
		}
		if len(info.Permissions.Required) != 2 {
			t.Errorf("Expected 2 required permissions, got %d", len(info.Permissions.Required))
		}
		if len(info.Permissions.Additional) != 5 {
			t.Errorf("Expected 5 additional permissions, got %d", len(info.Permissions.Additional))
		}
		if info.MITRE == nil {
			t.Error("Expected non-nil MITRE mapping")
		}
		if len(info.MITRE.Tactics) != 2 {
			t.Errorf("Expected 2 MITRE tactics, got %d", len(info.MITRE.Tactics))
		}
		if len(info.MITRE.Techniques) != 2 {
			t.Errorf("Expected 2 MITRE techniques, got %d", len(info.MITRE.Techniques))
		}
		if len(info.Aliases) != 2 {
			t.Errorf("Expected 2 aliases, got %d", len(info.Aliases))
		}
		if len(info.RelatedPaths) != 3 {
			t.Errorf("Expected 3 related paths, got %d", len(info.RelatedPaths))
		}
		if info.Author != "Seth Art" {
			t.Errorf("Expected Author %q, got %q", "Seth Art", info.Author)
		}
	})

	t.Run("SearchFindsLambda004", func(t *testing.T) {
		results := modules.SearchModules("lambda-004")
		found := false
		for _, info := range results {
			if info.ID == "lambda-004" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-004 in search results")
		}
	})

	t.Run("SearchByUpdateFunctionCode", func(t *testing.T) {
		results := modules.SearchModules("UpdateFunctionCode")
		found := false
		for _, info := range results {
			if info.ID == "lambda-004" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-004 in search results for 'UpdateFunctionCode'")
		}
	})

	t.Run("SearchByInvokeFunction", func(t *testing.T) {
		results := modules.SearchModules("InvokeFunction")
		found := false
		for _, info := range results {
			if info.ID == "lambda-004" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-004 in search results for 'InvokeFunction'")
		}
	})

	t.Run("CategoryFilter", func(t *testing.T) {
		results := modules.ListModulesByCategory("existing-passrole")
		found := false
		for _, info := range results {
			if info.ID == "lambda-004" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-004 in existing-passrole category")
		}
	})

	t.Run("ServiceFilter", func(t *testing.T) {
		results := modules.ListModulesByService("lambda")
		found := false
		for _, info := range results {
			if info.ID == "lambda-004" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-004 in lambda service results")
		}
	})

	t.Run("DiscoverableInterface", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-004")
		if err != nil {
			t.Fatalf("Failed to load lambda-004: %v", err)
		}
		discoverable, ok := mod.(modules.Discoverable)
		if !ok {
			t.Fatal("Expected lambda-004 to implement Discoverable")
		}
		opts := discoverable.DiscoverableOptions()
		if len(opts) != 1 {
			t.Errorf("Expected 1 discoverable option, got %d", len(opts))
		}
		if opts[0] != "FUNCTION_NAME" {
			t.Errorf("Expected discoverable option %q, got %q", "FUNCTION_NAME", opts[0])
		}
	})

	t.Run("PayloadCompatibleInterface", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-004")
		if err != nil {
			t.Fatalf("Failed to load lambda-004: %v", err)
		}
		compatible, ok := mod.(modules.PayloadCompatible)
		if !ok {
			t.Fatal("Expected lambda-004 to implement PayloadCompatible")
		}
		tags := compatible.GetCompatibleTags()
		if len(tags) != 2 {
			t.Errorf("Expected 2 compatible tags, got %d", len(tags))
		}
		ctx := compatible.GetPayloadContext()
		if ctx != "lambda" {
			t.Errorf("Expected payload context %q, got %q", "lambda", ctx)
		}
	})

	t.Run("ListPayloads", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-004")
		if err != nil {
			t.Fatalf("Failed to load lambda-004: %v", err)
		}
		payloadList := mod.ListPayloads()
		if len(payloadList) == 0 {
			t.Error("Expected at least one payload for lambda-004")
		}
		// Should include exfil/response since this is a direct-invoke module
		foundExfil := false
		for _, p := range payloadList {
			if p.Name == "exfil/response" {
				foundExfil = true
			}
		}
		if !foundExfil {
			t.Error("Expected exfil/response payload for direct-invoke lambda-004")
		}
	})
}

func TestLambda003Module(t *testing.T) {
	t.Run("LoadByPrimaryID", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-003")
		if err != nil {
			t.Fatalf("Expected no error loading lambda-003, got: %v", err)
		}
		if mod == nil {
			t.Fatal("Expected non-nil module")
		}
		if mod.Name() != "lambda-003" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-003", mod.Name())
		}
	})

	t.Run("LoadByAlias_ShortForm", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-updatecode")
		if err != nil {
			t.Fatalf("Expected no error loading lambda-updatecode, got: %v", err)
		}
		if mod.Name() != "lambda-003" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-003", mod.Name())
		}
	})

	t.Run("LoadByAlias_OldFormat", func(t *testing.T) {
		mod, err := modules.LoadModule("exploit/lambda_updatecode")
		if err != nil {
			t.Fatalf("Expected no error loading exploit/lambda_updatecode, got: %v", err)
		}
		if mod.Name() != "lambda-003" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-003", mod.Name())
		}
	})

	t.Run("PathInfoFields", func(t *testing.T) {
		info, found := modules.GetPathInfo("lambda-003")
		if !found {
			t.Fatal("Expected to find PathInfo for lambda-003")
		}
		if info.ID != "lambda-003" {
			t.Errorf("Expected ID %q, got %q", "lambda-003", info.ID)
		}
		if info.Category != "existing-passrole" {
			t.Errorf("Expected Category %q, got %q", "existing-passrole", info.Category)
		}
		if len(info.Services) != 1 {
			t.Errorf("Expected 1 service, got %d", len(info.Services))
		}
		if info.Services[0] != "lambda" {
			t.Errorf("Expected service %q, got %q", "lambda", info.Services[0])
		}
		if len(info.Permissions.Required) != 2 {
			t.Errorf("Expected 2 required permissions, got %d", len(info.Permissions.Required))
		}
		if len(info.Permissions.Additional) != 5 {
			t.Errorf("Expected 5 additional permissions, got %d", len(info.Permissions.Additional))
		}
		if info.MITRE == nil {
			t.Error("Expected non-nil MITRE mapping")
		}
		if len(info.MITRE.Tactics) != 2 {
			t.Errorf("Expected 2 MITRE tactics, got %d", len(info.MITRE.Tactics))
		}
		if len(info.MITRE.Techniques) != 2 {
			t.Errorf("Expected 2 MITRE techniques, got %d", len(info.MITRE.Techniques))
		}
		if len(info.Aliases) != 2 {
			t.Errorf("Expected 2 aliases, got %d", len(info.Aliases))
		}
		if len(info.RelatedPaths) != 3 {
			t.Errorf("Expected 3 related paths, got %d", len(info.RelatedPaths))
		}
		if info.Author != "Seth Art" {
			t.Errorf("Expected Author %q, got %q", "Seth Art", info.Author)
		}
	})

	t.Run("SearchFindsLambda003", func(t *testing.T) {
		results := modules.SearchModules("lambda-003")
		found := false
		for _, info := range results {
			if info.ID == "lambda-003" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-003 in search results")
		}
	})

	t.Run("SearchByUpdateFunctionCode", func(t *testing.T) {
		results := modules.SearchModules("UpdateFunctionCode")
		found := false
		for _, info := range results {
			if info.ID == "lambda-003" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-003 in search results for 'UpdateFunctionCode'")
		}
	})

	t.Run("CategoryFilter", func(t *testing.T) {
		results := modules.ListModulesByCategory("existing-passrole")
		found := false
		for _, info := range results {
			if info.ID == "lambda-003" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-003 in existing-passrole category")
		}
	})

	t.Run("ServiceFilter", func(t *testing.T) {
		results := modules.ListModulesByService("lambda")
		found := false
		for _, info := range results {
			if info.ID == "lambda-003" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-003 in lambda service results")
		}
	})

	t.Run("DiscoverableInterface", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-003")
		if err != nil {
			t.Fatalf("Failed to load lambda-003: %v", err)
		}
		discoverable, ok := mod.(modules.Discoverable)
		if !ok {
			t.Fatal("Expected lambda-003 to implement Discoverable")
		}
		opts := discoverable.DiscoverableOptions()
		if len(opts) != 1 {
			t.Errorf("Expected 1 discoverable option, got %d", len(opts))
		}
		if opts[0] != "FUNCTION_NAME" {
			t.Errorf("Expected discoverable option %q, got %q", "FUNCTION_NAME", opts[0])
		}
	})

	t.Run("PayloadCompatibleInterface", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-003")
		if err != nil {
			t.Fatalf("Failed to load lambda-003: %v", err)
		}
		compatible, ok := mod.(modules.PayloadCompatible)
		if !ok {
			t.Fatal("Expected lambda-003 to implement PayloadCompatible")
		}
		tags := compatible.GetCompatibleTags()
		if len(tags) != 2 {
			t.Errorf("Expected 2 compatible tags, got %d", len(tags))
		}
		ctx := compatible.GetPayloadContext()
		if ctx != "lambda" {
			t.Errorf("Expected payload context %q, got %q", "lambda", ctx)
		}
	})

	t.Run("ListPayloads", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-003")
		if err != nil {
			t.Fatalf("Failed to load lambda-003: %v", err)
		}
		payloadList := mod.ListPayloads()
		if len(payloadList) == 0 {
			t.Error("Expected at least one payload for lambda-003")
		}
		// Should include exfil/response since this is a direct-invoke module
		foundExfil := false
		for _, p := range payloadList {
			if p.Name == "exfil/response" {
				foundExfil = true
			}
		}
		if !foundExfil {
			t.Error("Expected exfil/response payload for direct-invoke lambda-003")
		}
	})
}

func TestLambda005Module(t *testing.T) {
	t.Run("LoadByPrimaryID", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-005")
		if err != nil {
			t.Fatalf("Expected no error loading lambda-005, got: %v", err)
		}
		if mod == nil {
			t.Fatal("Expected non-nil module")
		}
		if mod.Name() != "lambda-005" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-005", mod.Name())
		}
	})

	t.Run("LoadByAlias_ShortForm", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-updatecode-addpermission")
		if err != nil {
			t.Fatalf("Expected no error loading lambda-updatecode-addpermission, got: %v", err)
		}
		if mod.Name() != "lambda-005" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-005", mod.Name())
		}
	})

	t.Run("LoadByAlias_OldFormat", func(t *testing.T) {
		mod, err := modules.LoadModule("exploit/lambda_updatecode_addpermission")
		if err != nil {
			t.Fatalf("Expected no error loading exploit/lambda_updatecode_addpermission, got: %v", err)
		}
		if mod.Name() != "lambda-005" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-005", mod.Name())
		}
	})

	t.Run("PathInfoFields", func(t *testing.T) {
		info, found := modules.GetPathInfo("lambda-005")
		if !found {
			t.Fatal("Expected to find PathInfo for lambda-005")
		}
		if info.ID != "lambda-005" {
			t.Errorf("Expected ID %q, got %q", "lambda-005", info.ID)
		}
		if info.Category != "existing-passrole" {
			t.Errorf("Expected Category %q, got %q", "existing-passrole", info.Category)
		}
		if len(info.Services) != 1 {
			t.Errorf("Expected 1 service, got %d", len(info.Services))
		}
		if info.Services[0] != "lambda" {
			t.Errorf("Expected service %q, got %q", "lambda", info.Services[0])
		}
		if len(info.Permissions.Required) != 2 {
			t.Errorf("Expected 2 required permissions, got %d", len(info.Permissions.Required))
		}
		if len(info.Permissions.Additional) != 6 {
			t.Errorf("Expected 6 additional permissions, got %d", len(info.Permissions.Additional))
		}
		if info.MITRE == nil {
			t.Error("Expected non-nil MITRE mapping")
		}
		if len(info.MITRE.Tactics) != 2 {
			t.Errorf("Expected 2 MITRE tactics, got %d", len(info.MITRE.Tactics))
		}
		if len(info.MITRE.Techniques) != 2 {
			t.Errorf("Expected 2 MITRE techniques, got %d", len(info.MITRE.Techniques))
		}
		if len(info.Aliases) != 2 {
			t.Errorf("Expected 2 aliases, got %d", len(info.Aliases))
		}
		if len(info.RelatedPaths) != 4 {
			t.Errorf("Expected 4 related paths, got %d", len(info.RelatedPaths))
		}
		if info.Author != "Seth Art" {
			t.Errorf("Expected Author %q, got %q", "Seth Art", info.Author)
		}
	})

	t.Run("SearchFindsLambda005", func(t *testing.T) {
		results := modules.SearchModules("lambda-005")
		found := false
		for _, info := range results {
			if info.ID == "lambda-005" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-005 in search results")
		}
	})

	t.Run("SearchByAddPermission", func(t *testing.T) {
		results := modules.SearchModules("AddPermission")
		found := false
		for _, info := range results {
			if info.ID == "lambda-005" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-005 in search results for 'AddPermission'")
		}
	})

	t.Run("CategoryFilter", func(t *testing.T) {
		results := modules.ListModulesByCategory("existing-passrole")
		found := false
		for _, info := range results {
			if info.ID == "lambda-005" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-005 in existing-passrole category")
		}
	})

	t.Run("ServiceFilter", func(t *testing.T) {
		results := modules.ListModulesByService("lambda")
		found := false
		for _, info := range results {
			if info.ID == "lambda-005" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-005 in lambda service results")
		}
	})

	t.Run("DiscoverableInterface", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-005")
		if err != nil {
			t.Fatalf("Failed to load lambda-005: %v", err)
		}
		discoverable, ok := mod.(modules.Discoverable)
		if !ok {
			t.Fatal("Expected lambda-005 to implement Discoverable")
		}
		opts := discoverable.DiscoverableOptions()
		if len(opts) != 1 {
			t.Errorf("Expected 1 discoverable option, got %d", len(opts))
		}
		if opts[0] != "FUNCTION_NAME" {
			t.Errorf("Expected discoverable option %q, got %q", "FUNCTION_NAME", opts[0])
		}
	})

	t.Run("PayloadCompatibleInterface", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-005")
		if err != nil {
			t.Fatalf("Failed to load lambda-005: %v", err)
		}
		compatible, ok := mod.(modules.PayloadCompatible)
		if !ok {
			t.Fatal("Expected lambda-005 to implement PayloadCompatible")
		}
		tags := compatible.GetCompatibleTags()
		if len(tags) != 2 {
			t.Errorf("Expected 2 compatible tags, got %d", len(tags))
		}
		ctx := compatible.GetPayloadContext()
		if ctx != "lambda" {
			t.Errorf("Expected payload context %q, got %q", "lambda", ctx)
		}
	})

	t.Run("ListPayloads", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-005")
		if err != nil {
			t.Fatalf("Failed to load lambda-005: %v", err)
		}
		payloadList := mod.ListPayloads()
		if len(payloadList) == 0 {
			t.Error("Expected at least one payload for lambda-005")
		}
		foundExfil := false
		for _, p := range payloadList {
			if p.Name == "exfil/response" {
				foundExfil = true
			}
		}
		if !foundExfil {
			t.Error("Expected exfil/response payload for direct-invoke lambda-005")
		}
	})
}

func TestLambda006Module(t *testing.T) {
	t.Run("LoadByPrimaryID", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-006")
		if err != nil {
			t.Fatalf("Expected no error loading lambda-006, got: %v", err)
		}
		if mod == nil {
			t.Fatal("Expected non-nil module")
		}
		if mod.Name() != "lambda-006" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-006", mod.Name())
		}
	})

	t.Run("LoadByAlias_ShortForm", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-createfunction-addpermission")
		if err != nil {
			t.Fatalf("Expected no error loading lambda-createfunction-addpermission, got: %v", err)
		}
		if mod.Name() != "lambda-006" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-006", mod.Name())
		}
	})

	t.Run("LoadByAlias_OldFormat", func(t *testing.T) {
		mod, err := modules.LoadModule("exploit/lambda_createfunction_addpermission")
		if err != nil {
			t.Fatalf("Expected no error loading exploit/lambda_createfunction_addpermission, got: %v", err)
		}
		if mod.Name() != "lambda-006" {
			t.Errorf("Expected Name() = %q, got %q", "lambda-006", mod.Name())
		}
	})

	t.Run("PathInfoFields", func(t *testing.T) {
		info, found := modules.GetPathInfo("lambda-006")
		if !found {
			t.Fatal("Expected to find PathInfo for lambda-006")
		}
		if info.ID != "lambda-006" {
			t.Errorf("Expected ID %q, got %q", "lambda-006", info.ID)
		}
		if info.Category != "new-passrole" {
			t.Errorf("Expected Category %q, got %q", "new-passrole", info.Category)
		}
		if len(info.Services) != 2 {
			t.Errorf("Expected 2 services, got %d", len(info.Services))
		}
		if len(info.Permissions.Required) != 3 {
			t.Errorf("Expected 3 required permissions, got %d", len(info.Permissions.Required))
		}
		if len(info.Permissions.Additional) != 6 {
			t.Errorf("Expected 6 additional permissions, got %d", len(info.Permissions.Additional))
		}
		if info.MITRE == nil {
			t.Error("Expected non-nil MITRE mapping")
		}
		if len(info.MITRE.Tactics) != 2 {
			t.Errorf("Expected 2 MITRE tactics, got %d", len(info.MITRE.Tactics))
		}
		if len(info.MITRE.Techniques) != 2 {
			t.Errorf("Expected 2 MITRE techniques, got %d", len(info.MITRE.Techniques))
		}
		if len(info.Aliases) != 2 {
			t.Errorf("Expected 2 aliases, got %d", len(info.Aliases))
		}
		if len(info.RelatedPaths) != 2 {
			t.Errorf("Expected 2 related paths, got %d", len(info.RelatedPaths))
		}
		if info.Author != "Seth Art" {
			t.Errorf("Expected Author %q, got %q", "Seth Art", info.Author)
		}
	})

	t.Run("SearchFindsLambda006", func(t *testing.T) {
		results := modules.SearchModules("lambda-006")
		found := false
		for _, info := range results {
			if info.ID == "lambda-006" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-006 in search results")
		}
	})

	t.Run("SearchByAddPermission", func(t *testing.T) {
		results := modules.SearchModules("AddPermission")
		found := false
		for _, info := range results {
			if info.ID == "lambda-006" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-006 in search results for 'AddPermission'")
		}
	})

	t.Run("SearchByPassRole", func(t *testing.T) {
		results := modules.SearchModules("PassRole")
		found := false
		for _, info := range results {
			if info.ID == "lambda-006" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-006 in search results for 'PassRole'")
		}
	})

	t.Run("CategoryFilter", func(t *testing.T) {
		results := modules.ListModulesByCategory("new-passrole")
		found := false
		for _, info := range results {
			if info.ID == "lambda-006" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-006 in new-passrole category")
		}
	})

	t.Run("ServiceFilter_IAM", func(t *testing.T) {
		results := modules.ListModulesByService("iam")
		found := false
		for _, info := range results {
			if info.ID == "lambda-006" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-006 in iam service results")
		}
	})

	t.Run("ServiceFilter_Lambda", func(t *testing.T) {
		results := modules.ListModulesByService("lambda")
		found := false
		for _, info := range results {
			if info.ID == "lambda-006" {
				found = true
			}
		}
		if !found {
			t.Error("Expected lambda-006 in lambda service results")
		}
	})

	t.Run("DiscoverableInterface", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-006")
		if err != nil {
			t.Fatalf("Failed to load lambda-006: %v", err)
		}
		discoverable, ok := mod.(modules.Discoverable)
		if !ok {
			t.Fatal("Expected lambda-006 to implement Discoverable")
		}
		opts := discoverable.DiscoverableOptions()
		if len(opts) != 1 {
			t.Errorf("Expected 1 discoverable option, got %d", len(opts))
		}
		if opts[0] != "ROLE_ARN" {
			t.Errorf("Expected discoverable option %q, got %q", "ROLE_ARN", opts[0])
		}
	})

	t.Run("PayloadCompatibleInterface", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-006")
		if err != nil {
			t.Fatalf("Failed to load lambda-006: %v", err)
		}
		compatible, ok := mod.(modules.PayloadCompatible)
		if !ok {
			t.Fatal("Expected lambda-006 to implement PayloadCompatible")
		}
		tags := compatible.GetCompatibleTags()
		if len(tags) != 2 {
			t.Errorf("Expected 2 compatible tags, got %d", len(tags))
		}
		ctx := compatible.GetPayloadContext()
		if ctx != "lambda" {
			t.Errorf("Expected payload context %q, got %q", "lambda", ctx)
		}
	})

	t.Run("ListPayloads", func(t *testing.T) {
		mod, err := modules.LoadModule("lambda-006")
		if err != nil {
			t.Fatalf("Failed to load lambda-006: %v", err)
		}
		payloadList := mod.ListPayloads()
		if len(payloadList) == 0 {
			t.Error("Expected at least one payload for lambda-006")
		}
		foundExfil := false
		for _, p := range payloadList {
			if p.Name == "exfil/response" {
				foundExfil = true
			}
		}
		if !foundExfil {
			t.Error("Expected exfil/response payload for direct-invoke lambda-006")
		}
	})
}

func TestIAM001Module(t *testing.T) {
	t.Run("LoadByPrimaryID", func(t *testing.T) {
		mod, err := modules.LoadModule("iam-001")
		if err != nil {
			t.Fatalf("Expected no error loading iam-001, got: %v", err)
		}
		if mod == nil {
			t.Fatal("Expected non-nil module")
		}
		if mod.Name() != "iam-001" {
			t.Errorf("Expected Name() = %q, got %q", "iam-001", mod.Name())
		}
	})

	t.Run("LoadByAlias_ShortForm", func(t *testing.T) {
		mod, err := modules.LoadModule("iam-createpolicyversion")
		if err != nil {
			t.Fatalf("Expected no error loading iam-createpolicyversion, got: %v", err)
		}
		if mod.Name() != "iam-001" {
			t.Errorf("Expected Name() = %q, got %q", "iam-001", mod.Name())
		}
	})

	t.Run("LoadByAlias_OldFormat", func(t *testing.T) {
		mod, err := modules.LoadModule("exploit/iam_create_policy_version")
		if err != nil {
			t.Fatalf("Expected no error loading exploit/iam_create_policy_version, got: %v", err)
		}
		if mod.Name() != "iam-001" {
			t.Errorf("Expected Name() = %q, got %q", "iam-001", mod.Name())
		}
	})

	t.Run("PathInfoFields", func(t *testing.T) {
		info, found := modules.GetPathInfo("iam-001")
		if !found {
			t.Fatal("Expected to find PathInfo for iam-001")
		}
		if info.ID != "iam-001" {
			t.Errorf("Expected ID %q, got %q", "iam-001", info.ID)
		}
		if info.Category != "self-escalation" {
			t.Errorf("Expected Category %q, got %q", "self-escalation", info.Category)
		}
		if len(info.Services) != 1 || info.Services[0] != "iam" {
			t.Errorf("Expected services [iam], got %v", info.Services)
		}
		if len(info.Permissions.Required) != 1 {
			t.Errorf("Expected 1 required permission, got %d", len(info.Permissions.Required))
		}
		if len(info.Permissions.Additional) != 2 {
			t.Errorf("Expected 2 additional permissions, got %d", len(info.Permissions.Additional))
		}
		if info.MITRE == nil {
			t.Error("Expected non-nil MITRE mapping")
		}
		if len(info.MITRE.Tactics) != 2 {
			t.Errorf("Expected 2 MITRE tactics, got %d", len(info.MITRE.Tactics))
		}
		if len(info.Aliases) != 2 {
			t.Errorf("Expected 2 aliases, got %d", len(info.Aliases))
		}
		if len(info.RelatedPaths) != 2 {
			t.Errorf("Expected 2 related paths, got %d", len(info.RelatedPaths))
		}
		if info.Author != "Seth Art" {
			t.Errorf("Expected Author %q, got %q", "Seth Art", info.Author)
		}
	})

	t.Run("SearchFindsIAM001", func(t *testing.T) {
		results := modules.SearchModules("CreatePolicyVersion")
		found := false
		for _, info := range results {
			if info.ID == "iam-001" {
				found = true
			}
		}
		if !found {
			t.Error("Expected iam-001 in search results for 'CreatePolicyVersion'")
		}
	})

	t.Run("CategoryFilter", func(t *testing.T) {
		results := modules.ListModulesByCategory("self-escalation")
		found := false
		for _, info := range results {
			if info.ID == "iam-001" {
				found = true
			}
		}
		if !found {
			t.Error("Expected iam-001 in self-escalation category")
		}
	})

	t.Run("ServiceFilter", func(t *testing.T) {
		results := modules.ListModulesByService("iam")
		found := false
		for _, info := range results {
			if info.ID == "iam-001" {
				found = true
			}
		}
		if !found {
			t.Error("Expected iam-001 in iam service results")
		}
	})

	t.Run("Options", func(t *testing.T) {
		mod, err := modules.LoadModule("iam-001")
		if err != nil {
			t.Fatalf("Failed to load iam-001: %v", err)
		}
		opts := mod.Options()
		if len(opts) != 4 {
			t.Errorf("Expected 4 options, got %d", len(opts))
		}
		// POLICY_ARN should be required
		foundRequired := false
		for _, opt := range opts {
			if opt.Name == "POLICY_ARN" && opt.Required {
				foundRequired = true
			}
		}
		if !foundRequired {
			t.Error("Expected POLICY_ARN to be a required option")
		}
	})
}

func TestIAM002Module(t *testing.T) {
	t.Run("LoadByPrimaryID", func(t *testing.T) {
		mod, err := modules.LoadModule("iam-002")
		if err != nil {
			t.Fatalf("Expected no error loading iam-002, got: %v", err)
		}
		if mod == nil {
			t.Fatal("Expected non-nil module")
		}
		if mod.Name() != "iam-002" {
			t.Errorf("Expected Name() = %q, got %q", "iam-002", mod.Name())
		}
	})

	t.Run("LoadByAlias_ShortForm", func(t *testing.T) {
		mod, err := modules.LoadModule("iam-createaccesskey")
		if err != nil {
			t.Fatalf("Expected no error loading iam-createaccesskey, got: %v", err)
		}
		if mod.Name() != "iam-002" {
			t.Errorf("Expected Name() = %q, got %q", "iam-002", mod.Name())
		}
	})

	t.Run("LoadByAlias_OldFormat", func(t *testing.T) {
		mod, err := modules.LoadModule("exploit/iam_createaccesskey")
		if err != nil {
			t.Fatalf("Expected no error loading exploit/iam_createaccesskey, got: %v", err)
		}
		if mod.Name() != "iam-002" {
			t.Errorf("Expected Name() = %q, got %q", "iam-002", mod.Name())
		}
	})

	t.Run("PathInfoFields", func(t *testing.T) {
		info, found := modules.GetPathInfo("iam-002")
		if !found {
			t.Fatal("Expected to find PathInfo for iam-002")
		}
		if info.ID != "iam-002" {
			t.Errorf("Expected ID %q, got %q", "iam-002", info.ID)
		}
		if info.Category != "principal-access" {
			t.Errorf("Expected Category %q, got %q", "principal-access", info.Category)
		}
		if len(info.Services) != 1 || info.Services[0] != "iam" {
			t.Errorf("Expected services [iam], got %v", info.Services)
		}
		if len(info.Permissions.Required) != 1 {
			t.Errorf("Expected 1 required permission, got %d", len(info.Permissions.Required))
		}
		if len(info.Permissions.Additional) != 3 {
			t.Errorf("Expected 3 additional permissions, got %d", len(info.Permissions.Additional))
		}
		if info.MITRE == nil {
			t.Error("Expected non-nil MITRE mapping")
		}
		if len(info.Aliases) != 2 {
			t.Errorf("Expected 2 aliases, got %d", len(info.Aliases))
		}
		if len(info.RelatedPaths) != 3 {
			t.Errorf("Expected 3 related paths, got %d", len(info.RelatedPaths))
		}
		if info.Author != "Seth Art" {
			t.Errorf("Expected Author %q, got %q", "Seth Art", info.Author)
		}
	})

	t.Run("SearchFindsIAM002", func(t *testing.T) {
		results := modules.SearchModules("CreateAccessKey")
		found := false
		for _, info := range results {
			if info.ID == "iam-002" {
				found = true
			}
		}
		if !found {
			t.Error("Expected iam-002 in search results for 'CreateAccessKey'")
		}
	})

	t.Run("CategoryFilter", func(t *testing.T) {
		results := modules.ListModulesByCategory("principal-access")
		found := false
		for _, info := range results {
			if info.ID == "iam-002" {
				found = true
			}
		}
		if !found {
			t.Error("Expected iam-002 in principal-access category")
		}
	})

	t.Run("Options", func(t *testing.T) {
		mod, err := modules.LoadModule("iam-002")
		if err != nil {
			t.Fatalf("Failed to load iam-002: %v", err)
		}
		opts := mod.Options()
		if len(opts) != 3 {
			t.Errorf("Expected 3 options, got %d", len(opts))
		}
		foundRequired := false
		for _, opt := range opts {
			if opt.Name == "TARGET_USER" && opt.Required {
				foundRequired = true
			}
		}
		if !foundRequired {
			t.Error("Expected TARGET_USER to be a required option")
		}
	})
}

func TestIAM003Module(t *testing.T) {
	t.Run("LoadByPrimaryID", func(t *testing.T) {
		mod, err := modules.LoadModule("iam-003")
		if err != nil {
			t.Fatalf("Expected no error loading iam-003, got: %v", err)
		}
		if mod == nil {
			t.Fatal("Expected non-nil module")
		}
		if mod.Name() != "iam-003" {
			t.Errorf("Expected Name() = %q, got %q", "iam-003", mod.Name())
		}
	})

	t.Run("LoadByAlias_ShortForm", func(t *testing.T) {
		mod, err := modules.LoadModule("iam-deleteaccesskey-createaccesskey")
		if err != nil {
			t.Fatalf("Expected no error loading iam-deleteaccesskey-createaccesskey, got: %v", err)
		}
		if mod.Name() != "iam-003" {
			t.Errorf("Expected Name() = %q, got %q", "iam-003", mod.Name())
		}
	})

	t.Run("LoadByAlias_OldFormat", func(t *testing.T) {
		mod, err := modules.LoadModule("exploit/iam_deleteaccesskey_createaccesskey")
		if err != nil {
			t.Fatalf("Expected no error loading exploit/iam_deleteaccesskey_createaccesskey, got: %v", err)
		}
		if mod.Name() != "iam-003" {
			t.Errorf("Expected Name() = %q, got %q", "iam-003", mod.Name())
		}
	})

	t.Run("PathInfoFields", func(t *testing.T) {
		info, found := modules.GetPathInfo("iam-003")
		if !found {
			t.Fatal("Expected to find PathInfo for iam-003")
		}
		if info.ID != "iam-003" {
			t.Errorf("Expected ID %q, got %q", "iam-003", info.ID)
		}
		if info.Category != "principal-access" {
			t.Errorf("Expected Category %q, got %q", "principal-access", info.Category)
		}
		if len(info.Services) != 1 || info.Services[0] != "iam" {
			t.Errorf("Expected services [iam], got %v", info.Services)
		}
		if len(info.Permissions.Required) != 2 {
			t.Errorf("Expected 2 required permissions, got %d", len(info.Permissions.Required))
		}
		if len(info.Permissions.Additional) != 3 {
			t.Errorf("Expected 3 additional permissions, got %d", len(info.Permissions.Additional))
		}
		if info.MITRE == nil {
			t.Error("Expected non-nil MITRE mapping")
		}
		if len(info.Aliases) != 2 {
			t.Errorf("Expected 2 aliases, got %d", len(info.Aliases))
		}
		if len(info.RelatedPaths) != 1 {
			t.Errorf("Expected 1 related path, got %d", len(info.RelatedPaths))
		}
		if info.Author != "Seth Art" {
			t.Errorf("Expected Author %q, got %q", "Seth Art", info.Author)
		}
	})

	t.Run("SearchFindsIAM003", func(t *testing.T) {
		results := modules.SearchModules("DeleteAccessKey")
		found := false
		for _, info := range results {
			if info.ID == "iam-003" {
				found = true
			}
		}
		if !found {
			t.Error("Expected iam-003 in search results for 'DeleteAccessKey'")
		}
	})

	t.Run("Options", func(t *testing.T) {
		mod, err := modules.LoadModule("iam-003")
		if err != nil {
			t.Fatalf("Failed to load iam-003: %v", err)
		}
		opts := mod.Options()
		if len(opts) != 4 {
			t.Errorf("Expected 4 options, got %d", len(opts))
		}
	})
}

func TestIAM004Module(t *testing.T) {
	t.Run("LoadByPrimaryID", func(t *testing.T) {
		mod, err := modules.LoadModule("iam-004")
		if err != nil {
			t.Fatalf("Expected no error loading iam-004, got: %v", err)
		}
		if mod == nil {
			t.Fatal("Expected non-nil module")
		}
		if mod.Name() != "iam-004" {
			t.Errorf("Expected Name() = %q, got %q", "iam-004", mod.Name())
		}
	})

	t.Run("LoadByAlias_ShortForm", func(t *testing.T) {
		mod, err := modules.LoadModule("iam-createloginprofile")
		if err != nil {
			t.Fatalf("Expected no error loading iam-createloginprofile, got: %v", err)
		}
		if mod.Name() != "iam-004" {
			t.Errorf("Expected Name() = %q, got %q", "iam-004", mod.Name())
		}
	})

	t.Run("LoadByAlias_OldFormat", func(t *testing.T) {
		mod, err := modules.LoadModule("exploit/iam_createloginprofile")
		if err != nil {
			t.Fatalf("Expected no error loading exploit/iam_createloginprofile, got: %v", err)
		}
		if mod.Name() != "iam-004" {
			t.Errorf("Expected Name() = %q, got %q", "iam-004", mod.Name())
		}
	})

	t.Run("PathInfoFields", func(t *testing.T) {
		info, found := modules.GetPathInfo("iam-004")
		if !found {
			t.Fatal("Expected to find PathInfo for iam-004")
		}
		if info.ID != "iam-004" {
			t.Errorf("Expected ID %q, got %q", "iam-004", info.ID)
		}
		if info.Category != "principal-access" {
			t.Errorf("Expected Category %q, got %q", "principal-access", info.Category)
		}
		if len(info.Services) != 1 || info.Services[0] != "iam" {
			t.Errorf("Expected services [iam], got %v", info.Services)
		}
		if len(info.Permissions.Required) != 1 {
			t.Errorf("Expected 1 required permission, got %d", len(info.Permissions.Required))
		}
		if len(info.Permissions.Additional) != 3 {
			t.Errorf("Expected 3 additional permissions, got %d", len(info.Permissions.Additional))
		}
		if info.MITRE == nil {
			t.Error("Expected non-nil MITRE mapping")
		}
		if len(info.Aliases) != 2 {
			t.Errorf("Expected 2 aliases, got %d", len(info.Aliases))
		}
		if len(info.RelatedPaths) != 2 {
			t.Errorf("Expected 2 related paths, got %d", len(info.RelatedPaths))
		}
		if info.Author != "Seth Art" {
			t.Errorf("Expected Author %q, got %q", "Seth Art", info.Author)
		}
	})

	t.Run("SearchFindsIAM004", func(t *testing.T) {
		results := modules.SearchModules("CreateLoginProfile")
		found := false
		for _, info := range results {
			if info.ID == "iam-004" {
				found = true
			}
		}
		if !found {
			t.Error("Expected iam-004 in search results for 'CreateLoginProfile'")
		}
	})

	t.Run("CategoryFilter", func(t *testing.T) {
		results := modules.ListModulesByCategory("principal-access")
		found := false
		for _, info := range results {
			if info.ID == "iam-004" {
				found = true
			}
		}
		if !found {
			t.Error("Expected iam-004 in principal-access category")
		}
	})

	t.Run("Options", func(t *testing.T) {
		mod, err := modules.LoadModule("iam-004")
		if err != nil {
			t.Fatalf("Failed to load iam-004: %v", err)
		}
		opts := mod.Options()
		if len(opts) != 4 {
			t.Errorf("Expected 4 options, got %d", len(opts))
		}
		foundRequired := false
		for _, opt := range opts {
			if opt.Name == "TARGET_USER" && opt.Required {
				foundRequired = true
			}
		}
		if !foundRequired {
			t.Error("Expected TARGET_USER to be a required option")
		}
	})
}
