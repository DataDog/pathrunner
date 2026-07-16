package integration

import (
	"testing"

	// Import new IAM modules to register them
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_putrolepolicy"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_updateloginprofile"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_putuserpolicy"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_attachuserpolicy"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_attachrolepolicy"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_attachgrouppolicy"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_putgrouppolicy"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_updateassumerolepolicy"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_addusertogroup"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_attachrolepolicy_assumerole"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_createpolicyversion_assumerole"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_putrolepolicy_assumerole"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_attachuserpolicy_createaccesskey"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_putuserpolicy_createaccesskey"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_attachrolepolicy_updateassumerolepolicy"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_createpolicyversion_updateassumerolepolicy"
	_ "github.com/DataDog/pathrunner/pkg/exploits/iam_putrolepolicy_updateassumerolepolicy"
)

func TestIAMModulesIntegration(t *testing.T) {
	modules := []struct {
		id       string
		short    string
		oldAlias string
	}{
		{"iam-005", "iam-putrolepolicy", "exploit/iam_putrolepolicy"},
		{"iam-006", "iam-updateloginprofile", "exploit/iam_updateloginprofile"},
		{"iam-007", "iam-putuserpolicy", "exploit/iam_putuserpolicy"},
		{"iam-008", "iam-attachuserpolicy", "exploit/iam_attachuserpolicy"},
		{"iam-009", "iam-attachrolepolicy", "exploit/iam_attachrolepolicy"},
		{"iam-010", "iam-attachgrouppolicy", "exploit/iam_attachgrouppolicy"},
		{"iam-011", "iam-putgrouppolicy", "exploit/iam_putgrouppolicy"},
		{"iam-012", "iam-updateassumerolepolicy", "exploit/iam_updateassumerolepolicy"},
		{"iam-013", "iam-addusertogroup", "exploit/iam_addusertogroup"},
		{"iam-014", "iam-attachrolepolicy-assumerole", "exploit/iam_attachrolepolicy_assumerole"},
		{"iam-015", "iam-attachuserpolicy-createaccesskey", "exploit/iam_attachuserpolicy_createaccesskey"},
		{"iam-016", "iam-createpolicyversion-assumerole", "exploit/iam_createpolicyversion_assumerole"},
		{"iam-017", "iam-putrolepolicy-assumerole", "exploit/iam_putrolepolicy_assumerole"},
		{"iam-018", "iam-putuserpolicy-createaccesskey", "exploit/iam_putuserpolicy_createaccesskey"},
		{"iam-019", "iam-attachrolepolicy-updateassumerolepolicy", "exploit/iam_attachrolepolicy_updateassumerolepolicy"},
		{"iam-020", "iam-createpolicyversion-updateassumerolepolicy", "exploit/iam_createpolicyversion_updateassumerolepolicy"},
		{"iam-021", "iam-putrolepolicy-updateassumerolepolicy", "exploit/iam_putrolepolicy_updateassumerolepolicy"},
	}

	for _, tc := range modules {
		t.Run(tc.id, func(t *testing.T) {
			r, _, _, cleanup := setupTest(t)
			defer cleanup()

			// Test 1: use by primary ID
			t.Run("use_by_id", func(t *testing.T) {
				err := r.ExecuteCommand("use " + tc.id)
				if err != nil {
					t.Fatalf("Expected no error using %s, got: %v", tc.id, err)
				}

				mod := r.GetCurrentModule()
				if mod == nil {
					t.Fatal("Expected current module to be set")
				}
				if mod.Name() != tc.id {
					t.Errorf("Expected module name %q, got %q", tc.id, mod.Name())
				}
			})

			// Test 2: use by short alias
			t.Run("use_by_short_alias", func(t *testing.T) {
				err := r.ExecuteCommand("use " + tc.short)
				if err != nil {
					t.Fatalf("Expected no error using %s, got: %v", tc.short, err)
				}

				mod := r.GetCurrentModule()
				if mod == nil {
					t.Fatal("Expected current module to be set")
				}
				if mod.Name() != tc.id {
					t.Errorf("Expected module name %q, got %q", tc.id, mod.Name())
				}
			})

			// Test 3: use by old format alias
			t.Run("use_by_old_alias", func(t *testing.T) {
				err := r.ExecuteCommand("use " + tc.oldAlias)
				if err != nil {
					t.Fatalf("Expected no error using %s, got: %v", tc.oldAlias, err)
				}

				mod := r.GetCurrentModule()
				if mod == nil {
					t.Fatal("Expected current module to be set")
				}
				if mod.Name() != tc.id {
					t.Errorf("Expected module name %q, got %q", tc.id, mod.Name())
				}
			})

			// Test 4: show info should not error
			t.Run("show_info", func(t *testing.T) {
				err := r.ExecuteCommand("use " + tc.id)
				if err != nil {
					t.Fatalf("Failed to use %s: %v", tc.id, err)
				}

				err = r.ExecuteCommand("show info")
				if err != nil {
					t.Errorf("Expected no error from show info for %s, got: %v", tc.id, err)
				}
			})

			// Test 5: show options should not error
			t.Run("show_options", func(t *testing.T) {
				err := r.ExecuteCommand("use " + tc.id)
				if err != nil {
					t.Fatalf("Failed to use %s: %v", tc.id, err)
				}

				err = r.ExecuteCommand("show options")
				if err != nil {
					t.Errorf("Expected no error from show options for %s, got: %v", tc.id, err)
				}
			})

			// Test 6: search by ID should not error
			t.Run("search_by_id", func(t *testing.T) {
				err := r.ExecuteCommand("search " + tc.id)
				if err != nil {
					t.Errorf("Expected no error from search %s, got: %v", tc.id, err)
				}
			})
		})
	}
}
