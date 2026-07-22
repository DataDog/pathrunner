// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package repl

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DataDog/pathrunner/pkg/pmapper"
	"github.com/DataDog/pathrunner/pkg/resources"
	"github.com/DataDog/pathrunner/pkg/ui"
)

// promptCloudfoxDir finds the default cloudfox output directory, lists available
// profile subdirectories, and asks the user which one to import.
func (r *REPL) promptCloudfoxDir() (string, error) {
	baseDir := resources.DefaultCloudfoxDir()
	if baseDir == "" {
		return "", NewExecutionError("could not find cloudfox output directory (~/.cloudfox/cloudfox-output/aws/). Use --path to specify", nil)
	}

	profileDirs, err := resources.ListProfileDirs(baseDir)
	if err != nil || len(profileDirs) == 0 {
		// No profile subdirectories found; import from the base directory directly.
		return baseDir, nil
	}

	options := make([]string, 0, len(profileDirs)+1)
	options = append(options, fmt.Sprintf("All profiles (%s)", baseDir))
	for _, dir := range profileDirs {
		label := dir.Profile
		if dir.AccountID != "" {
			label = fmt.Sprintf("%s (%s)", dir.Profile, dir.AccountID)
		}
		options = append(options, label)
	}

	idx, err := ui.Select("Select cloudfox profile to import:", options)
	if err != nil {
		return "", NewExecutionError("profile selection cancelled", err)
	}

	if idx == 0 {
		return baseDir, nil
	}
	return filepath.Join(baseDir, filepath.Base(profileDirs[idx-1].Path)), nil
}

// promptCacheAccount finds available accounts in the cloudfox cached-data directory
// and asks the user which one to import. Returns the account ID and its cache directory path.
func (r *REPL) promptCacheAccount() (accountID string, accountDir string, err error) {
	cacheBase := resources.DefaultCloudfoxCacheDir()
	if cacheBase == "" {
		return "", "", nil // no cache dir, signal caller to fall back
	}

	accounts, err := resources.ListCacheAccounts(cacheBase)
	if err != nil || len(accounts) == 0 {
		return "", "", nil // no accounts, signal caller to fall back
	}

	if len(accounts) == 1 {
		id := accounts[0]
		return id, filepath.Join(cacheBase, id), nil
	}

	idx, err := ui.Select("Select account to import from cloudfox cache:", accounts)
	if err != nil {
		return "", "", NewExecutionError("account selection cancelled", err)
	}
	id := accounts[idx]
	return id, filepath.Join(cacheBase, id), nil
}

// cmdCloudfox handles cloudfox commands
func (r *REPL) cmdCloudfox(repl *REPL, args []string) error {
	if len(args) == 0 {
		return r.showCloudfoxHelp()
	}

	switch args[0] {
	case "import":
		return r.cloudfoxImport(args[1:])
	case "help":
		return r.showCloudfoxHelp()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown cloudfox subcommand: %s. Use 'cloudfox help' for available commands", args[0]))
	}
}

// cmdResources handles resources commands
func (r *REPL) cmdResources(repl *REPL, args []string) error {
	if len(args) == 0 {
		return r.resourcesList(nil)
	}

	switch args[0] {
	case "import":
		return r.cloudfoxImport(args[1:])
	case "list":
		return r.resourcesList(args[1:])
	case "summary":
		return r.resourcesSummary(args[1:])
	case "status":
		return r.resourcesStatus(args[1:])
	case "clear":
		return r.resourcesClear(args[1:])
	case "help":
		return r.showResourcesHelp()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown resources subcommand: %s. Use 'resources help' for available commands", args[0]))
	}
}

// cloudfoxImport imports cloudfox output data
func (r *REPL) cloudfoxImport(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showCloudfoxImportHelp()
	}

	// Parse flags
	dirPath := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--path":
			if i+1 < len(args) {
				i++
				dirPath = args[i]
			} else {
				return NewInvalidArgumentsError("--path requires a directory path")
			}
		default:
			// Treat bare argument as path
			dirPath = args[i]
		}
	}

	// Auto-detect: collect account IDs from all workspace identities
	seen := make(map[string]bool)
	var accountIDs []string
	for _, identity := range r.identityManager.GetIdentities() {
		if identity.CallerARN == "" {
			continue
		}
		accountID := pmapper.ExtractAccountIDFromARN(identity.CallerARN)
		if accountID != "" && !seen[accountID] {
			seen[accountID] = true
			accountIDs = append(accountIDs, accountID)
		}
	}

	// When no explicit path is given, prefer the cloudfox cached-data directory (raw SDK
	// responses) over the cloudfox-output directory (pre-rendered JSON/loot files).
	if dirPath == "" {
		accountID, accountDir, err := r.promptCacheAccount()
		if err != nil {
			return err
		}
		if accountDir != "" {
			// Cache path: import a single account from the gob cache.
			fmt.Printf("Importing cloudfox cached-data for account %s...\n", accountID)
			importedID, err := r.resourcesManager.ImportCache(accountDir, accountID)
			if err != nil {
				return NewExecutionError("cache import failed", err)
			}
			return r.printImportSummary([]string{importedID}, nil)
		}

		// Fall back to the cloudfox-output directory.
		selected, err := r.promptCloudfoxDir()
		if err != nil {
			return err
		}
		dirPath = selected
	}

	fmt.Printf("Importing cloudfox data from %s...\n", dirPath)

	imported, accessKeyIDs, err := r.resourcesManager.Import(dirPath, accountIDs)
	if err != nil {
		return NewExecutionError("import failed", err)
	}

	return r.printImportSummary(imported, accessKeyIDs)
}

// resourcesList lists imported resources
func (r *REPL) resourcesList(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showResourcesListHelp()
	}

	accountID := r.getCurrentAccountID()
	serviceFilter := ""
	wide := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--account":
			if i+1 < len(args) {
				i++
				accountID = args[i]
			} else {
				return NewInvalidArgumentsError("--account requires an account ID")
			}
		case "--wide":
			wide = true
		default:
			serviceFilter = args[i]
		}
	}

	if accountID == "" {
		// Try to find any loaded account
		statuses := r.resourcesManager.Status()
		if len(statuses) == 0 {
			fmt.Println("No resources imported. Use 'cloudfox import' to import cloudfox output data.")
			return nil
		}
		accountID = statuses[0].AccountID
	}

	// Try auto-loading from disk
	r.resourcesManager.TryAutoLoad(accountID)

	resList := r.resourcesManager.ListResources(accountID, serviceFilter)
	if len(resList) == 0 {
		if serviceFilter != "" {
			fmt.Printf("No %s resources found for account %s\n", serviceFilter, accountID)
		} else {
			fmt.Printf("No resources found for account %s. Use 'cloudfox import' to import data.\n", accountID)
		}
		return nil
	}

	if serviceFilter != "" {
		fmt.Printf("%s resources for account %s (%d):\n", serviceFilter, accountID, len(resList))
	} else {
		fmt.Printf("Resources for account %s (%d):\n", accountID, len(resList))
	}
	fmt.Println()

	if wide {
		headers, rows := resources.FormatResourceTableWide(resList)
		ui.Table(headers, rows)
	} else {
		headers, rows := resources.FormatResourceTable(resList)
		ui.Table(headers, rows)
	}

	return nil
}

// resourcesSummary shows resource counts by service and region
func (r *REPL) resourcesSummary(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showResourcesSummaryHelp()
	}

	accountID := r.getCurrentAccountID()

	for i := 0; i < len(args); i++ {
		if args[i] == "--account" && i+1 < len(args) {
			i++
			accountID = args[i]
		}
	}

	if accountID == "" {
		statuses := r.resourcesManager.Status()
		if len(statuses) == 0 {
			fmt.Println("No resources imported. Use 'cloudfox import' to import cloudfox output data.")
			return nil
		}
		accountID = statuses[0].AccountID
	}

	r.resourcesManager.TryAutoLoad(accountID)

	summaries := r.resourcesManager.Summary(accountID)
	if len(summaries) == 0 {
		fmt.Printf("No resources found for account %s. Use 'cloudfox import' to import data.\n", accountID)
		return nil
	}

	fmt.Printf("Resource summary for account %s:\n", accountID)
	fmt.Println()

	headers, rows := resources.FormatSummaryTable(summaries)
	if headers != nil {
		ui.Table(headers, rows)
	}

	return nil
}

// resourcesStatus shows import status
func (r *REPL) resourcesStatus(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showResourcesStatusHelp()
	}

	// Try auto-loading for current account
	accountID := r.getCurrentAccountID()
	if accountID != "" {
		r.resourcesManager.TryAutoLoad(accountID)
	}

	statuses := r.resourcesManager.Status()
	fmt.Print(resources.FormatStatusReport(statuses))

	return nil
}

// resourcesClear removes imported resource data from memory and disk.
func (r *REPL) resourcesClear(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showResourcesClearHelp()
	}

	all := false
	accountID := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--all":
			all = true
		case "--account":
			if i+1 < len(args) {
				i++
				accountID = args[i]
			} else {
				return NewInvalidArgumentsError("--account requires an account ID")
			}
		}
	}

	if all {
		n, err := r.resourcesManager.ClearAll()
		if err != nil {
			return NewExecutionError("failed to clear resources", err)
		}
		if n == 0 {
			fmt.Println("No resources to clear.")
		} else {
			fmt.Printf("Cleared resources for %d account(s).\n", n)
		}
		return nil
	}

	if accountID == "" {
		accountID = r.getCurrentAccountID()
	}
	if accountID == "" {
		// Fall back to any loaded account if there is exactly one
		ids := r.resourcesManager.LoadedAccountIDs()
		if len(ids) == 1 {
			accountID = ids[0]
		} else if len(ids) > 1 {
			return NewInvalidArgumentsError("multiple accounts loaded — use --account <id> or --all")
		} else {
			fmt.Println("No resources loaded.")
			return nil
		}
	}

	if err := r.resourcesManager.ClearAccount(accountID); err != nil {
		return NewExecutionError("failed to clear resources", err)
	}
	fmt.Printf("Cleared resources for account %s.\n", accountID)
	return nil
}

// getCurrentAccountID extracts the account ID from the current identity, if any.
func (r *REPL) getCurrentAccountID() string {
	identity := r.identityManager.GetCurrent()
	if identity == nil || identity.CallerARN == "" {
		return ""
	}
	return pmapper.ExtractAccountIDFromARN(identity.CallerARN)
}

// printImportSummary prints a per-account resource count after a successful import.
func (r *REPL) printImportSummary(imported []string, accessKeyIDs []string) error {
	for _, accountID := range imported {
		ar, err := r.resourcesManager.GetAccount(accountID)
		if err != nil {
			continue
		}
		serviceCounts := make(map[string]int)
		for _, res := range ar.Resources {
			serviceCounts[res.Service]++
		}
		fmt.Printf("Imported account %s: %d resources", accountID, len(ar.Resources))
		if len(serviceCounts) > 0 {
			services := make([]string, 0, len(serviceCounts))
			for svc := range serviceCounts {
				services = append(services, svc)
			}
			sort.Strings(services)
			var parts []string
			for _, svc := range services {
				parts = append(parts, fmt.Sprintf("%s(%d)", svc, serviceCounts[svc]))
			}
			fmt.Printf(" [%s]", strings.Join(parts, ", "))
		}
		fmt.Println()
	}

	if len(accessKeyIDs) > 0 {
		fmt.Println()
		fmt.Printf("Found %d access key ID(s) in access-keys.txt (no secret keys available)\n", len(accessKeyIDs))
		fmt.Println("Use 'identity add' with the corresponding secrets to add them manually")
	}

	fmt.Println()
	fmt.Println("Run 'resources list' to view imported resources or 'resources summary' for an overview.")
	return nil
}

// Help functions

func (r *REPL) showCloudfoxHelp() error {
	fmt.Println("Cloudfox Commands:")
	fmt.Println("  cloudfox import [--path <dir>]   - Import cloudfox output data")
	fmt.Println("  cloudfox help                    - Show this help message")
	fmt.Println()
	fmt.Println("Imports AWS resource data from cloudfox output directories.")
	fmt.Println("Without --path, auto-detects from ~/.cloudfox/cloudfox-output/aws/")
	fmt.Println()
	fmt.Println("After importing, use 'resources' to view the data:")
	fmt.Println("  resources list [service]         - List resources")
	fmt.Println("  resources summary                - Service x region overview")
	fmt.Println("  resources status                 - Import history")
	return nil
}

func (r *REPL) showCloudfoxImportHelp() error {
	fmt.Println("Cloudfox Import Command:")
	fmt.Println("  cloudfox import                  - Import from default cloudfox directory")
	fmt.Println("  cloudfox import --path <dir>     - Import from specific directory")
	fmt.Println("  cloudfox import <dir>            - Import from specific directory")
	fmt.Println()
	fmt.Println("Reads cloudfox json/ and loot/ output files opportunistically.")
	fmt.Println("Multiple imports for the same account merge resources by ARN.")
	fmt.Println()
	fmt.Println("When workspace identities have account IDs, only matching accounts")
	fmt.Println("are imported. Without identities, all found profiles are imported.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  cloudfox import")
	fmt.Println("  cloudfox import --path ~/.cloudfox/cloudfox-output/aws/myprofile-123456789012")
	fmt.Println("  cloudfox import ~/.cloudfox/cloudfox-output/aws/")
	return nil
}

func (r *REPL) showResourcesClearHelp() error {
	fmt.Println("Resources Clear Command:")
	fmt.Println("  resources clear                  - Clear resources for the current account")
	fmt.Println("  resources clear --account <id>   - Clear resources for a specific account")
	fmt.Println("  resources clear --all            - Clear resources for all accounts")
	fmt.Println()
	fmt.Println("Removes resource data from memory and from disk (~/.pathrunner/resources/).")
	fmt.Println("After clearing, re-import with 'resources import'.")
	return nil
}

func (r *REPL) showResourcesHelp() error {
	fmt.Println("Resources Commands:")
	fmt.Println("  resources list [service]         - List imported resources, optionally filtered by service")
	fmt.Println("  resources list --wide             - List with type and name columns")
	fmt.Println("  resources summary                - Show resource counts by service and region")
	fmt.Println("  resources status                 - Show import status and history")
	fmt.Println("  resources import [--path <dir>]  - Import cloudfox output (alias for 'cloudfox import')")
	fmt.Println("  resources clear                  - Remove imported resource data")
	fmt.Println("  resources help                   - Show this help message")
	fmt.Println()
	fmt.Println("Service filter examples:")
	fmt.Println("  resources list ec2               - EC2 instances")
	fmt.Println("  resources list lambda            - Lambda functions")
	fmt.Println("  resources list iam               - IAM users and roles")
	fmt.Println("  resources list s3                - S3 buckets")
	return nil
}

func (r *REPL) showResourcesListHelp() error {
	fmt.Println("Resources List Command:")
	fmt.Println("  resources list                   - List all resources for current account")
	fmt.Println("  resources list <service>         - Filter by service (ec2, lambda, iam, s3, ...)")
	fmt.Println("  resources list --wide             - Show ARN and resource type columns")
	fmt.Println("  resources list --account <id>    - List resources for a specific account")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  resources list ec2")
	fmt.Println("  resources list lambda --wide")
	fmt.Println("  resources list --account 123456789012")
	return nil
}

func (r *REPL) showResourcesSummaryHelp() error {
	fmt.Println("Resources Summary Command:")
	fmt.Println("  resources summary                - Show resource counts by service and region")
	fmt.Println("  resources summary --account <id> - Summary for a specific account")
	fmt.Println()
	fmt.Println("Displays a pivot table with services as rows and regions as columns.")
	return nil
}

func (r *REPL) showResourcesStatusHelp() error {
	fmt.Println("Resources Status Command:")
	fmt.Println("  resources status    - Show import status for all loaded accounts")
	fmt.Println()
	fmt.Println("Displays:")
	fmt.Println("  - Total resource count per account")
	fmt.Println("  - Breakdown by service")
	fmt.Println("  - Import history (source directory, profile, timestamp, files parsed)")
	return nil
}
