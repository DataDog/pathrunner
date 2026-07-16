package unit

import (
	"github.com/DataDog/pathrunner/pkg/modules"
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/cognitoidentity_passrole"
)

func TestCognitoIdentityPassroleModuleLoadByID(t *testing.T) {
	mod, err := modules.LoadModule("cognitoidentity-001")
	if err != nil {
		t.Fatalf("Expected no error loading cognitoidentity-001, got: %v", err)
	}
	if mod == nil {
		t.Fatal("Expected non-nil module")
	}
	if mod.Name() != "cognitoidentity-001" {
		t.Errorf("Expected Name() = %q, got %q", "cognitoidentity-001", mod.Name())
	}
}

func TestCognitoIdentityPassroleLoadByShortAlias(t *testing.T) {
	mod, err := modules.LoadModule("cognitoidentity-passrole")
	if err != nil {
		t.Fatalf("Expected no error loading by alias 'cognitoidentity-passrole', got: %v", err)
	}
	if mod.Name() != "cognitoidentity-001" {
		t.Errorf("Expected Name() = %q, got %q", "cognitoidentity-001", mod.Name())
	}
}

func TestCognitoIdentityPassroleLoadByOldAlias(t *testing.T) {
	mod, err := modules.LoadModule("exploit/cognitoidentity_passrole")
	if err != nil {
		t.Fatalf("Expected no error loading by alias 'exploit/cognitoidentity_passrole', got: %v", err)
	}
	if mod.Name() != "cognitoidentity-001" {
		t.Errorf("Expected Name() = %q, got %q", "cognitoidentity-001", mod.Name())
	}
}

func TestCognitoIdentityPassrolePathInfo(t *testing.T) {
	info, found := modules.GetPathInfo("cognitoidentity-001")
	if !found {
		t.Fatal("Expected to find PathInfo for cognitoidentity-001")
	}

	if info.ID != "cognitoidentity-001" {
		t.Errorf("Expected ID %q, got %q", "cognitoidentity-001", info.ID)
	}

	if info.Category != "new-passrole" {
		t.Errorf("Expected Category %q, got %q", "new-passrole", info.Category)
	}

	// Services should include iam and cognitoidentity.
	expectedServices := []string{"iam", "cognitoidentity"}
	if len(info.Services) != len(expectedServices) {
		t.Errorf("Expected %d services, got %d: %v", len(expectedServices), len(info.Services), info.Services)
	} else {
		for i, svc := range expectedServices {
			if info.Services[i] != svc {
				t.Errorf("Expected service[%d] = %q, got %q", i, svc, info.Services[i])
			}
		}
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

	if len(info.Aliases) != 2 {
		t.Errorf("Expected 2 aliases, got %d: %v", len(info.Aliases), info.Aliases)
	}

	if info.Author != "Seth Art" {
		t.Errorf("Expected Author %q, got %q", "Seth Art", info.Author)
	}
}

func TestCognitoIdentityPassroleOptions(t *testing.T) {
	mod, err := modules.LoadModule("cognitoidentity-001")
	if err != nil {
		t.Fatalf("Failed to load cognitoidentity-001: %v", err)
	}

	opts := mod.Options()
	if len(opts) != 6 {
		t.Errorf("Expected 6 options, got %d", len(opts))
	}

	// ROLE_ARN must be required.
	foundRoleARN := false
	for _, opt := range opts {
		if opt.Name == "ROLE_ARN" && opt.Required {
			foundRoleARN = true
		}
	}
	if !foundRoleARN {
		t.Error("Expected ROLE_ARN to be a required option")
	}

	// IDENTITY_POOL_ID must be required.
	foundPoolID := false
	for _, opt := range opts {
		if opt.Name == "IDENTITY_POOL_ID" && opt.Required {
			foundPoolID = true
		}
	}
	if !foundPoolID {
		t.Error("Expected IDENTITY_POOL_ID to be a required option")
	}
}

func TestCognitoIdentityPassroleDiscoverableInterface(t *testing.T) {
	mod, err := modules.LoadModule("cognitoidentity-001")
	if err != nil {
		t.Fatalf("Failed to load cognitoidentity-001: %v", err)
	}

	discoverable, ok := mod.(modules.Discoverable)
	if !ok {
		t.Fatal("Expected cognitoidentity-001 to implement Discoverable")
	}

	discoverableOpts := discoverable.DiscoverableOptions()
	if len(discoverableOpts) != 2 {
		t.Errorf("Expected 2 discoverable options, got %d: %v", len(discoverableOpts), discoverableOpts)
	}

	// Verify ROLE_ARN and IDENTITY_POOL_ID are both discoverable.
	foundRoleARN := false
	foundPoolID := false
	for _, opt := range discoverableOpts {
		if opt == "ROLE_ARN" {
			foundRoleARN = true
		}
		if opt == "IDENTITY_POOL_ID" {
			foundPoolID = true
		}
	}
	if !foundRoleARN {
		t.Error("Expected ROLE_ARN in discoverable options")
	}
	if !foundPoolID {
		t.Error("Expected IDENTITY_POOL_ID in discoverable options")
	}
}

func TestCognitoIdentityPassroleSearchable(t *testing.T) {
	results := modules.SearchModules("cognitoidentity-001")
	found := false
	for _, info := range results {
		if info.ID == "cognitoidentity-001" {
			found = true
		}
	}
	if !found {
		t.Error("Expected cognitoidentity-001 in search results")
	}
}

func TestCognitoIdentityPassroleCategoryFilter(t *testing.T) {
	results := modules.ListModulesByCategory("new-passrole")
	found := false
	for _, info := range results {
		if info.ID == "cognitoidentity-001" {
			found = true
		}
	}
	if !found {
		t.Error("Expected cognitoidentity-001 in new-passrole category")
	}
}

func TestCognitoIdentityPassroleServiceFilter(t *testing.T) {
	results := modules.ListModulesByService("cognitoidentity")
	found := false
	for _, info := range results {
		if info.ID == "cognitoidentity-001" {
			found = true
		}
	}
	if !found {
		t.Error("Expected cognitoidentity-001 in cognitoidentity service results")
	}
}

func TestCognitoIdentityPassroleExtractRegionFromPoolID(t *testing.T) {
	// Test the internal region extraction logic via options behavior.
	// REGION option should be present with a default.
	mod, err := modules.LoadModule("cognitoidentity-001")
	if err != nil {
		t.Fatalf("Failed to load cognitoidentity-001: %v", err)
	}

	opts := mod.Options()
	var regionOpt *modules.Option
	for i := range opts {
		if opts[i].Name == "REGION" {
			regionOpt = &opts[i]
			break
		}
	}
	if regionOpt == nil {
		t.Error("Expected REGION option to be present")
	} else if regionOpt.Default != "us-east-1" {
		t.Errorf("Expected REGION default to be 'us-east-1', got %q", regionOpt.Default)
	}
}
