package unit

import (
	"pathrunner/pkg/modules"
	"testing"

	// Import IAM modules iam-005 through iam-021 to register them
	_ "pathrunner/pkg/exploits/iam_putrolepolicy"
	_ "pathrunner/pkg/exploits/iam_updateloginprofile"
	_ "pathrunner/pkg/exploits/iam_putuserpolicy"
	_ "pathrunner/pkg/exploits/iam_attachuserpolicy"
	_ "pathrunner/pkg/exploits/iam_attachrolepolicy"
	_ "pathrunner/pkg/exploits/iam_attachgrouppolicy"
	_ "pathrunner/pkg/exploits/iam_putgrouppolicy"
	_ "pathrunner/pkg/exploits/iam_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_addusertogroup"
	_ "pathrunner/pkg/exploits/iam_attachrolepolicy_assumerole"
	_ "pathrunner/pkg/exploits/iam_createpolicyversion_assumerole"
	_ "pathrunner/pkg/exploits/iam_putrolepolicy_assumerole"
	_ "pathrunner/pkg/exploits/iam_attachuserpolicy_createaccesskey"
	_ "pathrunner/pkg/exploits/iam_putuserpolicy_createaccesskey"
	_ "pathrunner/pkg/exploits/iam_attachrolepolicy_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_createpolicyversion_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_putrolepolicy_updateassumerolepolicy"
)

type iamModuleTestCase struct {
	id              string
	category        string
	shortAlias      string
	oldAlias        string
	requiredPerms   int
	additionalPerms int
	relatedPaths    int
	discoverOpts    []string // empty if not discoverable
	optionCount     int
	requiredOption  string   // name of a required option to check
	services        []string // expected services list
}

func getIAMModuleTestCases() []iamModuleTestCase {
	return []iamModuleTestCase{
		{
			id:              "iam-005",
			category:        "self-escalation",
			shortAlias:      "iam-putrolepolicy",
			oldAlias:        "exploit/iam_putrolepolicy",
			requiredPerms:   1,
			additionalPerms: 0,
			relatedPaths:    3,
			discoverOpts:    []string{},
			optionCount:     5,
			requiredOption:  "",
			services:        []string{"iam"},
		},
		{
			id:              "iam-006",
			category:        "principal-access",
			shortAlias:      "iam-updateloginprofile",
			oldAlias:        "exploit/iam_updateloginprofile",
			requiredPerms:   1,
			additionalPerms: 2,
			relatedPaths:    2,
			discoverOpts:    []string{"TARGET_USER"},
			optionCount:     4,
			requiredOption:  "TARGET_USER",
			services:        []string{"iam"},
		},
		{
			id:              "iam-007",
			category:        "self-escalation",
			shortAlias:      "iam-putuserpolicy",
			oldAlias:        "exploit/iam_putuserpolicy",
			requiredPerms:   1,
			additionalPerms: 0,
			relatedPaths:    4,
			discoverOpts:    []string{},
			optionCount:     3,
			requiredOption:  "",
			services:        []string{"iam"},
		},
		{
			id:              "iam-008",
			category:        "self-escalation",
			shortAlias:      "iam-attachuserpolicy",
			oldAlias:        "exploit/iam_attachuserpolicy",
			requiredPerms:   1,
			additionalPerms: 0,
			relatedPaths:    4,
			discoverOpts:    []string{},
			optionCount:     3,
			requiredOption:  "",
			services:        []string{"iam"},
		},
		{
			id:              "iam-009",
			category:        "self-escalation",
			shortAlias:      "iam-attachrolepolicy",
			oldAlias:        "exploit/iam_attachrolepolicy",
			requiredPerms:   1,
			additionalPerms: 0,
			relatedPaths:    3,
			discoverOpts:    []string{},
			optionCount:     5,
			requiredOption:  "",
			services:        []string{"iam"},
		},
		{
			id:              "iam-010",
			category:        "self-escalation",
			shortAlias:      "iam-attachgrouppolicy",
			oldAlias:        "exploit/iam_attachgrouppolicy",
			requiredPerms:   1,
			additionalPerms: 0,
			relatedPaths:    2,
			discoverOpts:    []string{"GROUP_NAME"},
			optionCount:     4,
			requiredOption:  "GROUP_NAME",
			services:        []string{"iam"},
		},
		{
			id:              "iam-011",
			category:        "self-escalation",
			shortAlias:      "iam-putgrouppolicy",
			oldAlias:        "exploit/iam_putgrouppolicy",
			requiredPerms:   1,
			additionalPerms: 0,
			relatedPaths:    3,
			discoverOpts:    []string{"GROUP_NAME"},
			optionCount:     4,
			requiredOption:  "GROUP_NAME",
			services:        []string{"iam"},
		},
		{
			id:              "iam-012",
			category:        "principal-access",
			shortAlias:      "iam-updateassumerolepolicy",
			oldAlias:        "exploit/iam_updateassumerolepolicy",
			requiredPerms:   1,
			additionalPerms: 2,
			relatedPaths:    0,
			discoverOpts:    []string{"TARGET_ROLE"},
			optionCount:     5,
			requiredOption:  "TARGET_ROLE",
			services:        []string{"iam"},
		},
		{
			id:              "iam-013",
			category:        "self-escalation",
			shortAlias:      "iam-addusertogroup",
			oldAlias:        "exploit/iam_addusertogroup",
			requiredPerms:   1,
			additionalPerms: 2,
			relatedPaths:    2,
			discoverOpts:    []string{"GROUP_NAME"},
			optionCount:     3,
			requiredOption:  "GROUP_NAME",
			services:        []string{"iam"},
		},
		{
			id:              "iam-014",
			category:        "principal-access",
			shortAlias:      "iam-attachrolepolicy-assumerole",
			oldAlias:        "exploit/iam_attachrolepolicy_assumerole",
			requiredPerms:   2,
			additionalPerms: 2,
			relatedPaths:    3,
			discoverOpts:    []string{"TARGET_ROLE"},
			optionCount:     4,
			requiredOption:  "TARGET_ROLE",
			services:        []string{"iam"},
		},
		{
			id:              "iam-015",
			category:        "principal-access",
			shortAlias:      "iam-attachuserpolicy-createaccesskey",
			oldAlias:        "exploit/iam_attachuserpolicy_createaccesskey",
			requiredPerms:   2,
			additionalPerms: 2,
			relatedPaths:    4,
			discoverOpts:    []string{"TARGET_USER"},
			optionCount:     4,
			requiredOption:  "TARGET_USER",
			services:        []string{"iam"},
		},
		{
			id:              "iam-016",
			category:        "principal-access",
			shortAlias:      "iam-createpolicyversion-assumerole",
			oldAlias:        "exploit/iam_createpolicyversion_assumerole",
			requiredPerms:   2,
			additionalPerms: 2,
			relatedPaths:    4,
			discoverOpts:    []string{"TARGET_ROLE"},
			optionCount:     4,
			requiredOption:  "POLICY_ARN",
			services:        []string{"iam", "sts"},
		},
		{
			id:              "iam-017",
			category:        "principal-access",
			shortAlias:      "iam-putrolepolicy-assumerole",
			oldAlias:        "exploit/iam_putrolepolicy_assumerole",
			requiredPerms:   2,
			additionalPerms: 2,
			relatedPaths:    6,
			discoverOpts:    []string{"TARGET_ROLE"},
			optionCount:     4,
			requiredOption:  "TARGET_ROLE",
			services:        []string{"iam", "sts"},
		},
		{
			id:              "iam-018",
			category:        "principal-access",
			shortAlias:      "iam-putuserpolicy-createaccesskey",
			oldAlias:        "exploit/iam_putuserpolicy_createaccesskey",
			requiredPerms:   2,
			additionalPerms: 2,
			relatedPaths:    5,
			discoverOpts:    []string{"TARGET_USER"},
			optionCount:     4,
			requiredOption:  "TARGET_USER",
			services:        []string{"iam"},
		},
		{
			id:              "iam-019",
			category:        "principal-access",
			shortAlias:      "iam-attachrolepolicy-updateassumerolepolicy",
			oldAlias:        "exploit/iam_attachrolepolicy_updateassumerolepolicy",
			requiredPerms:   2,
			additionalPerms: 2,
			relatedPaths:    0,
			discoverOpts:    []string{"TARGET_ROLE"},
			optionCount:     4,
			requiredOption:  "TARGET_ROLE",
			services:        []string{"iam"},
		},
		{
			id:              "iam-020",
			category:        "principal-access",
			shortAlias:      "iam-createpolicyversion-updateassumerolepolicy",
			oldAlias:        "exploit/iam_createpolicyversion_updateassumerolepolicy",
			requiredPerms:   2,
			additionalPerms: 3,
			relatedPaths:    4,
			discoverOpts:    []string{"TARGET_ROLE"},
			optionCount:     4,
			requiredOption:  "POLICY_ARN",
			services:        []string{"iam"},
		},
		{
			id:              "iam-021",
			category:        "principal-access",
			shortAlias:      "iam-putrolepolicy-updateassumerolepolicy",
			oldAlias:        "exploit/iam_putrolepolicy_updateassumerolepolicy",
			requiredPerms:   2,
			additionalPerms: 2,
			relatedPaths:    4,
			discoverOpts:    []string{"TARGET_ROLE"},
			optionCount:     4,
			requiredOption:  "TARGET_ROLE",
			services:        []string{"iam"},
		},
	}
}

func TestIAMModules(t *testing.T) {
	for _, tc := range getIAMModuleTestCases() {
		tc := tc // capture range variable
		t.Run(tc.id, func(t *testing.T) {

			t.Run("LoadByPrimaryID", func(t *testing.T) {
				mod, err := modules.LoadModule(tc.id)
				if err != nil {
					t.Fatalf("Expected no error loading %s, got: %v", tc.id, err)
				}
				if mod == nil {
					t.Fatal("Expected non-nil module")
				}
				if mod.Name() != tc.id {
					t.Errorf("Expected Name() = %q, got %q", tc.id, mod.Name())
				}
			})

			t.Run("LoadByAlias_ShortForm", func(t *testing.T) {
				mod, err := modules.LoadModule(tc.shortAlias)
				if err != nil {
					t.Fatalf("Expected no error loading %s, got: %v", tc.shortAlias, err)
				}
				if mod == nil {
					t.Fatal("Expected non-nil module")
				}
				if mod.Name() != tc.id {
					t.Errorf("Expected Name() = %q, got %q", tc.id, mod.Name())
				}
			})

			t.Run("LoadByAlias_OldFormat", func(t *testing.T) {
				mod, err := modules.LoadModule(tc.oldAlias)
				if err != nil {
					t.Fatalf("Expected no error loading %s, got: %v", tc.oldAlias, err)
				}
				if mod == nil {
					t.Fatal("Expected non-nil module")
				}
				if mod.Name() != tc.id {
					t.Errorf("Expected Name() = %q, got %q", tc.id, mod.Name())
				}
			})

			t.Run("PathInfoFields", func(t *testing.T) {
				info, found := modules.GetPathInfo(tc.id)
				if !found {
					t.Fatalf("Expected to find PathInfo for %s", tc.id)
				}
				if info.ID != tc.id {
					t.Errorf("Expected ID %q, got %q", tc.id, info.ID)
				}
				if info.Category != tc.category {
					t.Errorf("Expected Category %q, got %q", tc.category, info.Category)
				}
				if len(info.Services) != len(tc.services) {
					t.Errorf("Expected %d services, got %d: %v", len(tc.services), len(info.Services), info.Services)
				} else {
					for i, svc := range tc.services {
						if info.Services[i] != svc {
							t.Errorf("Expected service[%d] = %q, got %q", i, svc, info.Services[i])
						}
					}
				}
				if len(info.Permissions.Required) != tc.requiredPerms {
					t.Errorf("Expected %d required permissions, got %d", tc.requiredPerms, len(info.Permissions.Required))
				}
				if tc.additionalPerms > 0 {
					if len(info.Permissions.Additional) != tc.additionalPerms {
						t.Errorf("Expected %d additional permissions, got %d", tc.additionalPerms, len(info.Permissions.Additional))
					}
				}
				if info.MITRE == nil {
					t.Error("Expected non-nil MITRE mapping")
				}
				if len(info.Aliases) != 2 {
					t.Errorf("Expected 2 aliases, got %d", len(info.Aliases))
				}
				if tc.relatedPaths > 0 {
					if len(info.RelatedPaths) != tc.relatedPaths {
						t.Errorf("Expected %d related paths, got %d", tc.relatedPaths, len(info.RelatedPaths))
					}
				}
				if info.Author != "Seth Art" {
					t.Errorf("Expected Author %q, got %q", "Seth Art", info.Author)
				}
			})

			t.Run("SearchFinds", func(t *testing.T) {
				results := modules.SearchModules(tc.id)
				found := false
				for _, info := range results {
					if info.ID == tc.id {
						found = true
					}
				}
				if !found {
					t.Errorf("Expected %s in search results", tc.id)
				}
			})

			t.Run("CategoryFilter", func(t *testing.T) {
				results := modules.ListModulesByCategory(tc.category)
				found := false
				for _, info := range results {
					if info.ID == tc.id {
						found = true
					}
				}
				if !found {
					t.Errorf("Expected %s in %s category", tc.id, tc.category)
				}
			})

			t.Run("ServiceFilter", func(t *testing.T) {
				results := modules.ListModulesByService("iam")
				found := false
				for _, info := range results {
					if info.ID == tc.id {
						found = true
					}
				}
				if !found {
					t.Errorf("Expected %s in iam service results", tc.id)
				}
			})

			t.Run("Options", func(t *testing.T) {
				if tc.requiredOption == "" && tc.optionCount == 0 {
					t.Skip("No option checks for this module")
				}
				mod, err := modules.LoadModule(tc.id)
				if err != nil {
					t.Fatalf("Failed to load %s: %v", tc.id, err)
				}
				opts := mod.Options()
				if len(opts) != tc.optionCount {
					t.Errorf("Expected %d options, got %d", tc.optionCount, len(opts))
				}
				if tc.requiredOption != "" {
					foundRequired := false
					for _, opt := range opts {
						if opt.Name == tc.requiredOption && opt.Required {
							foundRequired = true
						}
					}
					if !foundRequired {
						t.Errorf("Expected %s to be a required option", tc.requiredOption)
					}
				}
			})

			t.Run("DiscoverableInterface", func(t *testing.T) {
				if len(tc.discoverOpts) == 0 {
					t.Skip("Module does not implement Discoverable")
				}
				mod, err := modules.LoadModule(tc.id)
				if err != nil {
					t.Fatalf("Failed to load %s: %v", tc.id, err)
				}
				discoverable, ok := mod.(modules.Discoverable)
				if !ok {
					t.Fatalf("Expected %s to implement Discoverable", tc.id)
				}
				opts := discoverable.DiscoverableOptions()
				if len(opts) != len(tc.discoverOpts) {
					t.Errorf("Expected %d discoverable options, got %d", len(tc.discoverOpts), len(opts))
				}
				for i, expected := range tc.discoverOpts {
					if i < len(opts) && opts[i] != expected {
						t.Errorf("Expected discoverable option %q, got %q", expected, opts[i])
					}
				}
			})
		})
	}
}
