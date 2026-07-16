package repl

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/DataDog/pathrunner/pkg/attacker"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/status"
	"github.com/DataDog/pathrunner/pkg/ui"
	"github.com/DataDog/pathrunner/pkg/utils"
)

// cmdUse selects a module for use
func (r *REPL) cmdUse(repl *REPL, args []string) error {
	if len(args) == 0 {
		return NewInvalidArgumentsError("use command requires module name. Use 'use help' for more information")
	}

	if args[0] == "help" {
		return r.showUseHelp()
	}

	moduleName := args[0]
	// Support "id/short-name" format from tab completion (e.g. "lambda-001/lambda-passrole")
	// Only strip suffix if the part before "/" looks like a pathfinding ID (e.g. "lambda-001")
	// Don't strip "exploit/lambda_passrole" style aliases
	if idx := strings.Index(moduleName, "/"); idx != -1 {
		prefix := moduleName[:idx]
		// Check if prefix matches {service}-{number} pattern
		if dashIdx := strings.LastIndex(prefix, "-"); dashIdx != -1 {
			suffix := prefix[dashIdx+1:]
			isNumber := len(suffix) > 0
			for _, c := range suffix {
				if c < '0' || c > '9' {
					isNumber = false
					break
				}
			}
			if isNumber {
				moduleName = prefix
			}
		}
	}
	module, err := modules.LoadModule(moduleName)
	if err != nil {
		return NewModuleNotFoundError(moduleName)
	}

	r.currentModule = module
	// Clear existing options when switching modules
	r.options = make(map[string]string)

	r.updateCompletion()
	r.UpdatePrompt()

	fmt.Printf("Module set to: %s\n", module.Name())
	fmt.Printf("Description: %s\n", module.Description())
	return nil
}

// showAllowed is the set of top-level commands that 'show' is permitted to proxy.
// Write-level commands (set, exploit, use, exit, etc.) are absent intentionally.
var showAllowed = map[string]bool{
	"modules":   true,
	"payloads":  true,
	"identity":  true,
	"workspace": true,
	"options":   true,
	"info":      true,
	"pmapper":   true,
	"sessions":  true,
	"attacker":  true,
	"resources": true,
}

// showBlockedSubcmds lists subcommands that 'show' must not proxy per target command.
// These are write or action operations that don't belong behind a read-intent prefix.
var showBlockedSubcmds = map[string]map[string]bool{
	"modules": {
		"mark-tested":  true,
		"mark-results": true,
		"mark-status":  true,
		"search":       true,
	},
	"identity": {
		"add":     true,
		"switch":  true,
		"clear":   true,
		"remove":  true,
		"refresh": true,
	},
	"workspace": {
		"create":  true,
		"switch":  true,
		"delete":  true,
		"cleanup": true,
	},
	"resources": {
		"import": true,
	},
	"attacker": {
		"set":   true,
		"clear": true,
	},
}

// cmdShow is a transparent read-intent proxy: 'show <cmd> [args...]' forwards
// to '<cmd> [args...]'. A top-level allowlist blocks write commands; a per-command
// subcommand blocklist blocks write subcommands (e.g. 'show modules mark-tested').
func (r *REPL) cmdShow(repl *REPL, args []string) error {
	if len(args) == 0 || args[0] == "help" {
		return r.showShowHelp()
	}

	target := args[0]

	// Normalize aliases to canonical command names
	switch target {
	case "module":
		target = "modules"
	case "payload":
		target = "payloads"
	case "identities":
		target = "identity"
	case "workspaces":
		target = "workspace"
	}

	if !showAllowed[target] {
		return NewInvalidArgumentsError(fmt.Sprintf(
			"'show %s' is not supported — use '%s' directly", args[0], args[0]))
	}

	// Block write subcommands for allowed targets
	if len(args) > 1 {
		if blocked, ok := showBlockedSubcmds[target]; ok && blocked[args[1]] {
			return NewInvalidArgumentsError(fmt.Sprintf(
				"'show %s %s' is not supported — use '%s %s' directly", target, args[1], target, args[1]))
		}
	}

	cmds := r.getCommands()
	cmd, ok := cmds[target]
	if !ok {
		return NewInvalidArgumentsError(fmt.Sprintf("unknown show target: %s", args[0]))
	}
	return cmd.Handler(r, args[1:])
}

// cmdSearch searches modules by keyword
func (r *REPL) cmdSearch(repl *REPL, args []string) error {
	if len(args) == 0 {
		return NewInvalidArgumentsError("search command requires a query. Usage: search <keyword>")
	}

	if args[0] == "help" {
		return r.showSearchHelp()
	}

	query := strings.Join(args, " ")
	results := modules.SearchModules(query)

	if len(results) == 0 {
		fmt.Printf("No modules found matching '%s'\n", query)
		return nil
	}

	fmt.Printf("Search results for '%s':\n", query)
	fmt.Println()

	rows := make([][]string, 0, len(results))
	for _, info := range results {
		rows = append(rows, []string{info.ID, info.Name, info.Category, strings.Join(info.Services, ", ")})
	}

	ui.Table([]string{"ID", "Name", "Category", "Services"}, rows)
	fmt.Println()

	return nil
}

// cmdModules handles the top-level modules command with subcommands
func (r *REPL) cmdModules(repl *REPL, args []string) error {
	if len(args) == 0 {
		return r.showModules(false)
	}

	switch args[0] {
	case "list":
		wide := len(args) > 1 && args[1] == "--wide"
		return r.showModules(wide)
	case "search":
		if len(args) < 2 {
			return NewInvalidArgumentsError("modules search requires a query")
		}
		return r.cmdSearch(repl, args[1:])
	case "status":
		if len(args) > 1 {
			return r.showModuleStatus(args[1])
		}
		return r.showAllModuleStatuses()
	case "mark-tested":
		if len(args) < 2 {
			return NewInvalidArgumentsError("modules mark-tested requires a module ID")
		}
		testedAgainst := ""
		if len(args) >= 3 {
			testedAgainst = args[2]
		}
		return r.markModuleTested(args[1], testedAgainst)
	case "mark-results":
		if len(args) < 4 {
			return NewInvalidArgumentsError("modules mark-results requires module ID, scenario, and results JSON file. Usage: modules mark-results <id> <scenario> <json-file>")
		}
		return r.markModuleResults(args[1], args[2], args[3])
	case "mark-status":
		if len(args) < 3 {
			return NewInvalidArgumentsError("modules mark-status requires module ID and status. Usage: modules mark-status <id> <tested|untested|failing|needs-update>")
		}
		return r.markModuleStatus(args[1], args[2])
	case "summary":
		return r.showModulesSummary()
	case "help":
		return r.showModulesHelp()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown modules subcommand: %s", args[0]))
	}
}

// cmdPayloads handles the top-level payloads command with subcommands
func (r *REPL) cmdPayloads(repl *REPL, args []string) error {
	if len(args) == 0 {
		return r.showPayloads()
	}

	switch args[0] {
	case "list":
		if len(args) > 1 && args[1] == "--all" {
			return r.showAllPayloads()
		}
		return r.showPayloads()
	case "help":
		return r.showPayloadsHelp()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown payloads subcommand: %s", args[0]))
	}
}

// cmdSet sets option values
func (r *REPL) cmdSet(repl *REPL, args []string) error {
	if len(args) == 0 {
		return NewInvalidArgumentsError("set command requires option name and value. Use 'set help' for more information")
	}

	if args[0] == "help" {
		return r.showSetHelp()
	}

	if len(args) != 2 {
		return NewInvalidArgumentsError("set command requires option name and value")
	}

	option := args[0]
	value := args[1]

	// Validate PAYLOAD option
	if strings.ToUpper(option) == "PAYLOAD" {
		if r.currentModule == nil {
			return NewValidationError("no module selected. Use 'use <module>' to select one", nil)
		}

		// Check if payload exists
		payloads := r.currentModule.ListPayloads()
		validPayload := false
		for _, p := range payloads {
			if p.Name == value {
				validPayload = true
				break
			}
		}

		if !validPayload {
			// Show available payloads
			fmt.Printf("Error: Invalid payload '%s'\n\n", value)
			fmt.Println("Available payloads:")
			for _, p := range payloads {
				fmt.Printf("  - %s: %s\n", p.Name, p.Description)
			}
			return NewValidationError(fmt.Sprintf("payload '%s' does not exist for module '%s'", value, r.currentModule.Name()), nil)
		}
	}

	r.options[option] = value
	fmt.Printf("Set %s => %s\n", option, value)

	// Auto-show payload options and rebuild completions after setting PAYLOAD
	if strings.ToUpper(option) == "PAYLOAD" {
		r.updateCompletion()
		r.autoPopulatePayloadDefaults(value)
		fmt.Println()
		if r.currentModule != nil {
			r.showPayloadOptions(value)
		}
	}

	return nil
}

// cmdUnset clears option values
func (r *REPL) cmdUnset(repl *REPL, args []string) error {
	if len(args) == 0 {
		return NewInvalidArgumentsError("unset command requires option name. Use 'unset help' for more information")
	}

	if args[0] == "help" {
		return r.showUnsetHelp()
	}

	if len(args) != 1 {
		return NewInvalidArgumentsError("unset command requires option name")
	}

	option := args[0]

	if option == "module" {
		if r.currentModule == nil {
			fmt.Println("No module selected.")
			return nil
		}
		name := r.currentModule.Name()
		r.currentModule = nil
		r.options = make(map[string]string)
		r.updateCompletion()
		fmt.Printf("Unset module: %s\n", name)
		return nil
	}

	if option == "identity" {
		if r.identityManager.GetCurrent() == nil {
			fmt.Println("No identity selected.")
			return nil
		}
		r.identityManager.ClearIdentity()
		r.updateCompletion()
		fmt.Println("Unset current identity.")
		return nil
	}

	if _, exists := r.options[option]; !exists {
		return NewInvalidArgumentsError(fmt.Sprintf("option '%s' is not set", option))
	}

	delete(r.options, option)
	fmt.Printf("Unset %s\n", option)

	// Rebuild completions when PAYLOAD is unset to remove payload-specific options
	if strings.ToUpper(option) == "PAYLOAD" {
		r.updateCompletion()
	}

	return nil
}

// cmdDiscover proactively discovers values for discoverable options
func (r *REPL) cmdDiscover(repl *REPL, args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showDiscoverHelp()
	}

	if r.currentModule == nil {
		return NewValidationError("no module selected. Use 'use <module>' to select one", nil)
	}

	identity := r.identityManager.GetCurrent()
	if identity == nil {
		return NewIdentityRequiredError()
	}

	if identity.IsExpired() {
		return NewAuthError("current identity has expired. Use 'identity refresh' or add new credentials", nil)
	}

	discoverable, ok := r.currentModule.(modules.Discoverable)
	if !ok {
		fmt.Printf("Module %s does not support auto-discovery.\n", r.currentModule.Name())
		fmt.Println("Set options manually with 'set <option> <value>'")
		return nil
	}

	discoverableOpts := discoverable.DiscoverableOptions()
	if len(discoverableOpts) == 0 {
		fmt.Println("No discoverable options for this module.")
		return nil
	}

	// If specific option requested
	if len(args) > 0 {
		optionName := strings.ToUpper(args[0])
		found := false
		for _, opt := range discoverableOpts {
			if opt == optionName {
				found = true
				break
			}
		}
		if !found {
			return NewInvalidArgumentsError(fmt.Sprintf("option '%s' does not support auto-discovery. Discoverable options: %s", optionName, strings.Join(discoverableOpts, ", ")))
		}

		return r.discoverAndSetOption(discoverable, optionName, identity)
	}

	// Discover all missing discoverable options
	for _, optName := range discoverableOpts {
		if existing := r.options[optName]; existing != "" {
			fmt.Printf("%s already set to '%s', skipping.\n", optName, existing)
			continue
		}

		if err := r.discoverAndSetOption(discoverable, optName, identity); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
	}

	return nil
}

// discoverAndSetOption runs discovery for a single option and presents an interactive selection.
func (r *REPL) discoverAndSetOption(discoverable modules.Discoverable, optionName string, identity *modules.Identity) error {
	fmt.Printf("Discovering values for %s...\n", optionName)

	choices, err := discoverable.Discover(optionName, identity, r.options)
	if err != nil {
		return fmt.Errorf("discovery failed for %s: %v", optionName, err)
	}

	if len(choices) == 0 {
		fmt.Printf("No values found for %s. Set it manually: set %s <value>\n", optionName, optionName)
		return nil
	}

	fmt.Printf("Found %d option(s) for %s:\n", len(choices), optionName)

	// When only one choice is available, auto-select it without prompting.
	// This supports non-interactive use (test scripts, CI) where there's no TTY.
	if len(choices) == 1 {
		selected := choices[0]
		r.options[optionName] = selected.Value
		fmt.Printf("Auto-selected %s => %s\n", optionName, selected.Value)
		return nil
	}

	// Build selection options
	labels := make([]string, len(choices))
	for i, c := range choices {
		labels[i] = c.Label
	}

	selectedIndex, err := ui.Select(fmt.Sprintf("Select value for %s:", optionName), labels)
	if err != nil {
		return fmt.Errorf("selection cancelled for %s", optionName)
	}

	selected := choices[selectedIndex]
	r.options[optionName] = selected.Value
	fmt.Printf("Set %s => %s\n", optionName, selected.Value)

	return nil
}

// tryResolveMissingOptions walks through all missing required options interactively:
// - Discoverable options: auto-enumerate via AWS API, present selection
// - PAYLOAD option: present selection from module's ListPayloads()
// - Other options: prompt with input for manual entry
// After PAYLOAD is resolved, also checks for payload-specific required options.
// Returns true if all missing options were resolved.
func (r *REPL) tryResolveMissingOptions(missing []string) bool {
	identity := r.identityManager.GetCurrent()
	if identity == nil {
		return false
	}

	// Build discoverable set
	var discoverableSet map[string]bool
	var discoverable modules.Discoverable
	if d, ok := r.currentModule.(modules.Discoverable); ok {
		discoverable = d
		discoverableSet = make(map[string]bool)
		for _, opt := range d.DiscoverableOptions() {
			discoverableSet[opt] = true
		}
	}

	fmt.Println("Resolving missing required options...")
	fmt.Println()

	for _, optName := range missing {
		if r.options[optName] != "" {
			continue // already resolved by a prior step
		}

		var err error
		switch {
		case optName == "PAYLOAD":
			err = r.promptPayloadSelection()
		case discoverableSet != nil && discoverableSet[optName]:
			err = r.discoverAndSetOption(discoverable, optName, identity)
		default:
			err = r.promptManualOption(optName)
		}

		if err != nil {
			fmt.Printf("  %v\n", err)
			return false
		}
	}

	// After PAYLOAD is set, check for payload-specific required options.
	// Auto-populate well-known options from context before prompting.
	if payload, exists := r.options["PAYLOAD"]; exists {
		payloadOpts := r.currentModule.PayloadOptions(payload)
		for _, opt := range payloadOpts {
			if opt.Name == "EXFIL_BUCKET" && r.options["EXFIL_BUCKET"] == "" {
				if bucket := attacker.GetExfilBucket(); bucket != "" {
					r.options["EXFIL_BUCKET"] = bucket
					fmt.Printf("  [*] Using attacker exfil bucket: %s\n", bucket)
					continue
				}
				if opt.Required {
					if r.tryGuideInfraSetup("bucket", "attacker infra bucket create", "attacker infra bucket status") {
						if bucket := attacker.GetExfilBucket(); bucket != "" {
							r.options["EXFIL_BUCKET"] = bucket
							fmt.Printf("  [*] Using attacker exfil bucket: %s\n", bucket)
							continue
						}
					}
				}
			}
			if opt.Name == "TARGET_ARN" && r.options["TARGET_ARN"] == "" {
				if identity.CallerARN != "" {
					r.options["TARGET_ARN"] = identity.CallerARN
					fmt.Printf("  [*] Defaulting TARGET_ARN to current identity: %s\n", identity.CallerARN)
					fmt.Printf("      Use 'set TARGET_ARN <arn>' to change before running\n")
					continue
				}
			}
			if opt.Required && r.options[opt.Name] == "" && opt.Default == "" {
				if err := r.promptManualOption(opt.Name); err != nil {
					fmt.Printf("  %v\n", err)
					return false
				}
			}
		}
	}

	return true
}

// autoPopulatePayloadDefaults fills in well-known payload options from context
// when they haven't been explicitly set. Called after PAYLOAD is selected so the
// defaults show up in the options table before the user runs the exploit.
func (r *REPL) autoPopulatePayloadDefaults(payloadName string) {
	if r.currentModule == nil {
		return
	}

	payloadOpts := r.currentModule.PayloadOptions(payloadName)
	identity := r.identityManager.GetCurrent()

	for _, opt := range payloadOpts {
		if r.options[opt.Name] != "" {
			continue
		}

		switch opt.Name {
		case "EXFIL_BUCKET":
			if bucket := attacker.GetExfilBucket(); bucket != "" {
				r.options["EXFIL_BUCKET"] = bucket
				fmt.Printf("[*] Using attacker exfil bucket: %s\n", bucket)
			}
		case "TARGET_ARN":
			if identity != nil && identity.CallerARN != "" {
				r.options["TARGET_ARN"] = identity.CallerARN
				fmt.Printf("[*] Defaulting TARGET_ARN to current identity: %s\n", identity.CallerARN)
				fmt.Printf("    Use 'set TARGET_ARN <arn>' to change before running\n")
			}
		}
	}
}

// promptPayloadSelection presents an interactive selection of available payloads.
func (r *REPL) promptPayloadSelection() error {
	payloadList := r.currentModule.ListPayloads()
	if len(payloadList) == 0 {
		return fmt.Errorf("no payloads available for module %s", r.currentModule.Name())
	}

	labels := make([]string, len(payloadList))
	for i, p := range payloadList {
		labels[i] = fmt.Sprintf("%s - %s", p.Name, p.Description)
	}

	selectedIndex, err := ui.Select("Select PAYLOAD:", labels)
	if err != nil {
		return fmt.Errorf("selection cancelled for PAYLOAD")
	}

	selected := payloadList[selectedIndex]
	r.options["PAYLOAD"] = selected.Name
	fmt.Printf("Set PAYLOAD => %s\n", selected.Name)

	r.autoPopulatePayloadDefaults(selected.Name)

	// Show payload options after selection
	fmt.Println()
	r.showPayloadOptions(selected.Name)

	return nil
}

// tryGuideInfraSetup checks whether the attacker infra needed for a module
// option is deployed, and if not, guides the user through creating it. Returns
// true if the infra was successfully created (caller should re-check the option
// value). Returns false if the user declined, the attacker identity is missing,
// or creation failed -- caller should fall through to the manual prompt.
//
// infraType is a human-readable label ("ecr", "bucket").
// createCmd is the REPL command to run (e.g., "attacker infra ecr create").
// statusCmd is the command to view the result (e.g., "attacker infra ecr status").
func (r *REPL) tryGuideInfraSetup(infraType string, createCmd string, statusCmd string) bool {
	attackerIdentity := r.identityManager.GetAttackerIdentity()
	if attackerIdentity == nil {
		fmt.Println()
		fmt.Printf("  This module requires attacker %s infrastructure, but no attacker identity is configured.\n", infraType)
		fmt.Println("  Set one up with:")
		fmt.Println()
		fmt.Println("    attacker set profile <profile-name>")
		fmt.Println()
		return false
	}

	fmt.Println()
	fmt.Printf("  This module requires attacker %s infrastructure that hasn't been deployed yet.\n", infraType)

	confirmed, err := ui.Confirm(fmt.Sprintf("Create attacker %s infrastructure now?", infraType))
	if err != nil || !confirmed {
		fmt.Println()
		fmt.Println("  You can create it manually later with:")
		fmt.Printf("    %s\n", createCmd)
		fmt.Println()
		return false
	}

	fmt.Println()
	if err := r.ExecuteCommand(createCmd); err != nil {
		fmt.Printf("  [!] Failed to create %s infrastructure: %v\n", infraType, err)
		fmt.Println()
		return false
	}

	fmt.Println()
	fmt.Printf("  View status anytime with: %s\n", statusCmd)
	fmt.Println()
	return true
}

// promptManualOption asks the user to type in a value for a required option.
func (r *REPL) promptManualOption(optionName string) error {
	// Find the option description for context
	desc := ""
	for _, opt := range r.currentModule.Options() {
		if opt.Name == optionName {
			desc = opt.Description
			break
		}
	}
	// Also check payload options
	if desc == "" {
		if payload, exists := r.options["PAYLOAD"]; exists {
			for _, opt := range r.currentModule.PayloadOptions(payload) {
				if opt.Name == optionName {
					desc = opt.Description
					break
				}
			}
		}
	}

	message := fmt.Sprintf("Enter value for %s", optionName)
	if desc != "" {
		message = fmt.Sprintf("Enter value for %s (%s)", optionName, desc)
	}

	value, err := ui.Input(message)
	if err != nil {
		return fmt.Errorf("input cancelled for %s", optionName)
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("no value provided for %s", optionName)
	}

	r.options[optionName] = value
	fmt.Printf("Set %s => %s\n", optionName, value)
	return nil
}

// cmdExploit executes the current module
func (r *REPL) cmdExploit(repl *REPL, args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showExploitHelp()
	}

	if r.currentModule == nil {
		return NewValidationError("no module selected. Use 'use <module>' to select one", nil)
	}

	identity := r.identityManager.GetCurrent()
	if identity == nil {
		return NewIdentityRequiredError()
	}

	if identity.IsExpired() {
		return NewAuthError("current identity has expired. Use 'identity refresh' or add new credentials", nil)
	}

	// Validate required options — if missing, walk the user through resolving them
	if err := r.validateOptions(); err != nil {
		missing := r.getMissingOptions()
		if len(missing) == 0 {
			return err
		}
		r.tryResolveMissingOptions(missing)
		// Always re-validate after the wizard, regardless of what it resolved
		if err2 := r.validateOptions(); err2 != nil {
			return err2
		}
	}

	fmt.Printf("Executing module: %s\n", r.currentModule.Name())
	fmt.Printf("Using identity: %s\n", identity.Name)
	fmt.Println()

	result, err := r.currentModule.Execute(modules.ExecutionContext{
		Identity:         identity,
		Options:          r.options,
		Tracker:          r.sessionManager,
		AttackerIdentity: r.identityManager.GetAttackerIdentity(),
	})
	if err != nil {
		return NewExecutionError(fmt.Sprintf("module execution failed: %v", err), err)
	}

	r.lastResult = result
	fmt.Println(result)

	// Handle special result processing (like extracting credentials)
	if err := r.handleSpecialResults(result); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	return nil
}

// showInfo displays detailed PathInfo for the current module
func (r *REPL) showInfo() error {
	if r.currentModule == nil {
		return NewValidationError("no module selected. Use 'use <module>' to select one", nil)
	}

	info := r.currentModule.PathInfo()
	if info.ID == "" {
		fmt.Printf("Module %s has no path metadata.\n", r.currentModule.Name())
		return nil
	}

	kvPairs := []ui.KV{
		{Key: "Path ID", Value: info.ID},
		{Key: "Name", Value: info.Name},
		{Key: "Category", Value: info.Category},
		{Key: "Services", Value: strings.Join(info.Services, ", ")},
		{Key: "Description", Value: info.Description},
	}

	// Required Permissions
	if len(info.Permissions.Required) > 0 {
		var perms []string
		for _, perm := range info.Permissions.Required {
			entry := perm.Permission
			if perm.Description != "" {
				entry += " (" + perm.Description + ")"
			}
			perms = append(perms, entry)
		}
		kvPairs = append(kvPairs, ui.KV{Key: "Required Permissions", Value: strings.Join(perms, "\n")})
	}

	// Additional Permissions
	if len(info.Permissions.Additional) > 0 {
		var perms []string
		for _, perm := range info.Permissions.Additional {
			entry := perm.Permission
			if perm.Description != "" {
				entry += " (" + perm.Description + ")"
			}
			perms = append(perms, entry)
		}
		kvPairs = append(kvPairs, ui.KV{Key: "Additional Permissions", Value: strings.Join(perms, "\n")})
	}

	// Prerequisites
	if len(info.Prerequisites.Admin) > 0 {
		kvPairs = append(kvPairs, ui.KV{Key: "Prerequisites (Admin)", Value: strings.Join(info.Prerequisites.Admin, "\n")})
	}
	if len(info.Prerequisites.Lateral) > 0 {
		kvPairs = append(kvPairs, ui.KV{Key: "Prerequisites (Lateral)", Value: strings.Join(info.Prerequisites.Lateral, "\n")})
	}

	// Related Paths
	if len(info.RelatedPaths) > 0 {
		kvPairs = append(kvPairs, ui.KV{Key: "Related Paths", Value: strings.Join(info.RelatedPaths, ", ")})
	}

	// References
	if len(info.References) > 0 {
		var refs []string
		for _, ref := range info.References {
			refs = append(refs, ref.Title+": "+ref.URL)
		}
		kvPairs = append(kvPairs, ui.KV{Key: "References", Value: strings.Join(refs, "\n")})
	}

	// URL
	kvPairs = append(kvPairs, ui.KV{Key: "URL", Value: info.PathfindingCloudURL()})

	// Aliases
	if len(info.Aliases) > 0 {
		kvPairs = append(kvPairs, ui.KV{Key: "Aliases", Value: strings.Join(info.Aliases, ", ")})
	}

	if info.Author != "" {
		kvPairs = append(kvPairs, ui.KV{Key: "Author", Value: info.Author})
	}

	fmt.Println()
	ui.KeyValueTable("", kvPairs)
	fmt.Println()

	options := r.currentModule.Options()
	if len(options) > 0 {
		var discoverableSet map[string]bool
		if discoverable, ok := r.currentModule.(modules.Discoverable); ok {
			discoverableSet = make(map[string]bool)
			for _, opt := range discoverable.DiscoverableOptions() {
				discoverableSet[opt] = true
			}
		}

		rows := make([][]string, 0, len(options))
		for _, option := range options {
			value := r.options[option.Name]
			if value == "" && option.Default != "" {
				value = option.Default + " (default)"
			}
			missing := value == "" && option.Required
			if value == "" {
				if missing {
					value = ui.Error.Render("<not set>")
				} else {
					value = ui.Muted.Render("<not set>")
				}
			}

			required := ui.Muted.Render("No")
			if option.Required {
				if missing {
					required = ui.Error.Render("Yes")
				} else {
					required = ui.Success.Render("Yes")
				}
			}

			desc := option.Description
			if discoverableSet != nil && discoverableSet[option.Name] {
				desc += " " + ui.Accent.Render("[auto]")
			}

			rows = append(rows, []string{option.Name, value, required, desc})
		}

		fmt.Println(ui.BoldCyan.Render("Options"))
		fmt.Println()
		ui.Table([]string{"Option", "Value", "Required", "Description"}, rows)
		fmt.Println()
	}

	return nil
}

// showModules displays available modules with enriched metadata.
// Pass wide=true to include the description column.
// showModulesSummary displays a count of modules total and per service
func (r *REPL) showModulesSummary() error {
	infos := modules.ListPathInfos()

	if len(infos) == 0 {
		fmt.Println("No modules available.")
		return nil
	}

	// Count modules by primary service, derived from the ID prefix (e.g., "lambda-001" -> "lambda").
	// Using the Services list would overcount services like "iam" that appear on nearly every module.
	serviceCounts := make(map[string]int)
	for _, info := range infos {
		primaryService := info.ID
		if dashIdx := strings.LastIndex(info.ID, "-"); dashIdx != -1 {
			primaryService = info.ID[:dashIdx]
		}
		serviceCounts[primaryService]++
	}

	// Sort service names for consistent output
	serviceNames := make([]string, 0, len(serviceCounts))
	for service := range serviceCounts {
		serviceNames = append(serviceNames, service)
	}
	sort.Strings(serviceNames)

	fmt.Printf("Total modules: %d\n", len(infos))
	fmt.Println()

	rows := make([][]string, 0, len(serviceNames))
	for _, service := range serviceNames {
		rows = append(rows, []string{service, fmt.Sprintf("%d", serviceCounts[service])})
	}

	ui.Table([]string{"Service", "Count"}, rows)
	fmt.Println()

	return nil
}

func (r *REPL) showModules(wide bool) error {
	infos := modules.ListPathInfos()

	// Fall back to basic listing if no PathInfo available
	if len(infos) == 0 {
		moduleNames := modules.ListModules()
		if len(moduleNames) == 0 {
			fmt.Println("No modules available.")
			return nil
		}

		rows := make([][]string, 0, len(moduleNames))
		for _, name := range moduleNames {
			_, description, err := modules.GetModuleInfo(name)
			if err == nil {
				if wide {
					rows = append(rows, []string{name, description})
				} else {
					rows = append(rows, []string{name})
				}
			}
		}

		fmt.Println("Available Modules:")
		fmt.Println()
		if wide {
			ui.Table([]string{"Module", "Description"}, rows)
		} else {
			ui.Table([]string{"Module"}, rows)
		}
		fmt.Println()
		return nil
	}

	fmt.Println("Available Modules:")
	fmt.Println()
	if wide {
		rows := make([][]string, 0, len(infos))
		for _, info := range infos {
			rows = append(rows, []string{info.ID, info.Name, info.Category, info.Description})
		}
		ui.Table([]string{"ID", "Name", "Category", "Description"}, rows)
	} else {
		rows := make([][]string, 0, len(infos))
		for _, info := range infos {
			rows = append(rows, []string{info.ID, info.Name, info.Category})
		}
		ui.Table([]string{"ID", "Name", "Category"}, rows)
	}
	fmt.Println()

	return nil
}

// showPayloads displays available payloads for current module or all modules
func (r *REPL) showPayloads() error {
	// If no module selected, show payloads for all modules
	if r.currentModule == nil {
		return r.showAllPayloads()
	}

	payloads := r.currentModule.ListPayloads()
	if len(payloads) == 0 {
		fmt.Printf("Module %s has no payloads.\n", r.currentModule.Name())
		return nil
	}

	moduleName := r.currentModule.Name()

	rows := make([][]string, 0, len(payloads))
	for _, payload := range payloads {
		rows = append(rows, []string{moduleName, payload.Name, payload.Description})
	}

	fmt.Printf("Available Payloads for %s:\n", moduleName)
	fmt.Println()
	ui.Table([]string{"Module", "Payload", "Description"}, rows)
	fmt.Println()

	return nil
}

// showAllPayloads displays all payloads from all modules
func (r *REPL) showAllPayloads() error {
	moduleNames := modules.ListModules()
	if len(moduleNames) == 0 {
		fmt.Println("No modules available.")
		return nil
	}

	var rows [][]string
	for _, moduleName := range moduleNames {
		module, err := modules.LoadModule(moduleName)
		if err != nil || module == nil {
			continue
		}

		payloads := module.ListPayloads()
		for _, payload := range payloads {
			rows = append(rows, []string{moduleName, payload.Name, payload.Description})
		}
	}

	if len(rows) == 0 {
		fmt.Println("No payloads available.")
		return nil
	}

	fmt.Println("Available Payloads (all modules):")
	fmt.Println()
	ui.Table([]string{"Module", "Payload", "Description"}, rows)
	fmt.Println()

	return nil
}

// showOptions displays current module options
func (r *REPL) showOptions() error {
	if r.currentModule == nil {
		return NewValidationError("no module selected", nil)
	}

	options := r.currentModule.Options()
	if len(options) == 0 {
		fmt.Printf("Module %s has no options.\n", r.currentModule.Name())
		return nil
	}

	// Check if module supports discovery
	var discoverableSet map[string]bool
	if discoverable, ok := r.currentModule.(modules.Discoverable); ok {
		discoverableSet = make(map[string]bool)
		for _, opt := range discoverable.DiscoverableOptions() {
			discoverableSet[opt] = true
		}
	}

	rows := make([][]string, 0, len(options))
	for _, option := range options {
		value := r.options[option.Name]
		if value == "" && option.Default != "" {
			value = option.Default + " (default)"
		}
		missing := value == "" && option.Required
		if value == "" {
			if missing {
				value = ui.Error.Render("<not set>")
			} else {
				value = ui.Muted.Render("<not set>")
			}
		}

		required := ui.Muted.Render("No")
		if option.Required {
			if missing {
				required = ui.Error.Render("Yes")
			} else {
				required = ui.Success.Render("Yes")
			}
		}

		desc := option.Description
		if discoverableSet != nil && discoverableSet[option.Name] {
			desc += " " + ui.Accent.Render("[auto]")
		}

		rows = append(rows, []string{option.Name, value, required, desc})
	}

	fmt.Printf("%s %s\n", ui.BoldCyan.Render("Options for"), ui.Accent.Render(r.currentModule.Name()))
	fmt.Println()
	ui.Table([]string{"Option", "Value", "Required", "Description"}, rows)
	fmt.Println()

	// Hint about discover command if there are missing required options
	hasMissingRequired := false
	for _, option := range options {
		if option.Required && r.options[option.Name] == "" && option.Default == "" {
			hasMissingRequired = true
			break
		}
	}
	if hasMissingRequired {
		if _, ok := r.currentModule.(modules.Discoverable); ok {
			fmt.Println(ui.Muted.Render("  Tip: run 'discover' to auto-populate options (requires appropriate IAM permissions)"))
			fmt.Println(ui.Muted.Render("  Run 'exploit' to execute the attack (will run `discover` if all required values are not populated)"))
			fmt.Println()
		}
	}

	// Show payload options if payload is selected
	if payload, exists := r.options["PAYLOAD"]; exists {
		return r.showPayloadOptions(payload)
	}

	return nil
}

// cmdOptions is the top-level handler for the 'options' command.
func (r *REPL) cmdOptions(repl *REPL, args []string) error {
	if len(args) > 0 && args[0] == "help" {
		fmt.Println("Options Command:")
		fmt.Println("  options   - Show current module options")
		return nil
	}
	return r.showOptions()
}

// showPayloadOptions displays payload-specific options
func (r *REPL) showPayloadOptions(payload string) error {
	payloadOptions := r.currentModule.PayloadOptions(payload)
	if len(payloadOptions) == 0 {
		return nil
	}

	rows := make([][]string, 0, len(payloadOptions))
	for _, option := range payloadOptions {
		value := r.options[option.Name]
		if value == "" && option.Default != "" {
			value = option.Default + " (default)"
		}
		missing := value == "" && option.Required
		if value == "" {
			if missing {
				value = ui.Error.Render("<not set>")
			} else {
				value = ui.Muted.Render("<not set>")
			}
		}

		required := ui.Muted.Render("No")
		if option.Required {
			if missing {
				required = ui.Error.Render("Yes")
			} else {
				required = ui.Success.Render("Yes")
			}
		}

		rows = append(rows, []string{option.Name, value, required, option.Description})
	}

	fmt.Printf("%s %s\n", ui.BoldCyan.Render("Payload Options for"), ui.Accent.Render(payload))
	fmt.Println()
	ui.Table([]string{"Payload Option", "Value", "Required", "Description"}, rows)
	fmt.Println()

	return nil
}

// getMissingOptions returns the names of required options that are not set.
func (r *REPL) getMissingOptions() []string {
	if r.currentModule == nil {
		return nil
	}

	options := r.currentModule.Options()
	var missing []string
	for _, option := range options {
		if option.Required {
			value := r.options[option.Name]
			if value == "" && option.Default == "" {
				missing = append(missing, option.Name)
			}
		}
	}

	// Check payload options if payload is selected
	if payload, exists := r.options["PAYLOAD"]; exists {
		payloadOptions := r.currentModule.PayloadOptions(payload)
		for _, option := range payloadOptions {
			if option.Required {
				value := r.options[option.Name]
				if value == "" && option.Default == "" {
					missing = append(missing, option.Name)
				}
			}
		}
	}

	return missing
}

// validateOptions validates all required options are set
func (r *REPL) validateOptions() error {
	options := r.currentModule.Options()

	var missing []string
	for _, option := range options {
		if option.Required {
			value := r.options[option.Name]
			if value == "" && option.Default == "" {
				missing = append(missing, option.Name)
			}
		}
	}

	// Check payload options if payload is selected
	if payload, exists := r.options["PAYLOAD"]; exists {
		payloadOptions := r.currentModule.PayloadOptions(payload)
		for _, option := range payloadOptions {
			if option.Required {
				value := r.options[option.Name]
				if value == "" && option.Default == "" {
					missing = append(missing, option.Name)
				}
			}
		}
	}

	if len(missing) > 0 {
		return NewValidationError(
			fmt.Sprintf("missing required options: %s", strings.Join(missing, ", ")),
			nil,
		)
	}

	return nil
}

// handleSpecialResults processes module results for special cases
func (r *REPL) handleSpecialResults(result string) error {
	// Check for structured identity data that needs processing
	if strings.Contains(result, "--- PATHFINDER_IDENTITY_DATA ---") {
		return r.handleStructuredIdentityData(result)
	}

	// Try to extract credentials from any format in the output
	return r.tryAutoImportCredentials(result)
}

// handleStructuredIdentityData processes structured identity data from modules
func (r *REPL) handleStructuredIdentityData(result string) error {
	// Extract identity data between markers
	start := strings.Index(result, "--- PATHFINDER_IDENTITY_DATA ---")
	end := strings.Index(result, "--- END_PATHFINDER_IDENTITY_DATA ---")

	if start == -1 || end == -1 {
		return fmt.Errorf("invalid identity data format")
	}

	// Extract the data section
	dataSection := result[start+len("--- PATHFINDER_IDENTITY_DATA ---"):end]

	// Parse key-value pairs
	lines := strings.Split(strings.TrimSpace(dataSection), "\n")
	data := make(map[string]string)
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			data[parts[0]] = parts[1]
		}
	}

	// Validate required fields
	if data["ACCESS_KEY_ID"] == "" || data["SECRET_ACCESS_KEY"] == "" {
		return fmt.Errorf("incomplete identity data: missing required fields")
	}

	// Import the identity
	name := data["NAME"]
	if name == "" {
		name = fmt.Sprintf("exploit_%s", data["ACCESS_KEY_ID"][len(data["ACCESS_KEY_ID"])-4:])
	}

	// Build the identity add command
	cmdArgs := []string{
		"--access",
		data["ACCESS_KEY_ID"],
		"--secret",
		data["SECRET_ACCESS_KEY"],
	}

	if data["SESSION_TOKEN"] != "" {
		cmdArgs = append(cmdArgs, "--token", data["SESSION_TOKEN"])
	}

	if name != "" {
		cmdArgs = append(cmdArgs, "--name", name)
	}

	// Pass --switch so AddIdentity skips the interactive prompt.
	// The AUTO_SWITCH field controls whether we actually switch after adding,
	// but we always want non-interactive add during auto-import.
	cmdArgs = append(cmdArgs, "--switch")

	fmt.Printf("\n✓ Detected credentials in exploit output\n")
	fmt.Printf("  Identity name: %s\n", name)
	fmt.Printf("  Type: %s\n", data["TYPE"])
	if data["EXPIRES_AT"] != "" {
		fmt.Printf("  Expires: %s\n", data["EXPIRES_AT"])
	}
	fmt.Printf("  Automatically importing credentials...\n\n")

	// Add the identity (--switch makes it non-interactive and auto-switches)
	err := r.identityManager.AddIdentity(cmdArgs)
	if err != nil {
		fmt.Printf("⚠ Failed to auto-import identity: %v\n", err)
		fmt.Printf("  You can manually add it with: identity add %s\n", strings.Join(cmdArgs, " "))
		return err
	}

	fmt.Printf("✓ Identity added successfully!\n")
	r.UpdatePrompt()

	return nil
}

// tryAutoImportCredentials attempts to extract and import credentials from any format
func (r *REPL) tryAutoImportCredentials(result string) error {
	// Use the existing credential extraction utility
	creds, err := utils.ExtractCredentialsFromText(result)
	if err != nil {
		// No credentials found, that's okay
		return nil
	}

	// Build identity add command
	identityName := creds.GenerateIdentityName()

	cmdArgs := []string{
		"--access",
		creds.AccessKeyID,
		"--secret",
		creds.SecretAccessKey,
	}

	if creds.SessionToken != "" {
		cmdArgs = append(cmdArgs, "--token", creds.SessionToken)
	}

	if identityName != "" {
		cmdArgs = append(cmdArgs, "--name", identityName)
	}

	fmt.Printf("\n✓ Detected credentials in exploit output\n")
	fmt.Printf("  Identity name: %s\n", identityName)
	fmt.Printf("  Source: %s\n", creds.Source)
	fmt.Printf("  Region: %s\n", creds.Region)
	fmt.Printf("  Automatically importing credentials...\n\n")

	// Add the identity
	err = r.identityManager.AddIdentity(cmdArgs)
	if err != nil {
		// Check if identity already exists
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "duplicate") {
			fmt.Printf("⚠ Identity with these credentials already exists\n")
			return nil
		}
		fmt.Printf("⚠ Failed to auto-import identity: %v\n", err)
		fmt.Printf("  You can manually add it with: identity add %s\n", strings.Join(cmdArgs, " "))
		return err
	}

	fmt.Printf("✓ Identity added successfully!\n")
	r.UpdatePrompt()

	return nil
}

// showAllModuleStatuses displays a table of all modules with their test status.
func (r *REPL) showAllModuleStatuses() error {
	manifest, err := status.LoadManifest()
	if err != nil {
		return NewExecutionError(fmt.Sprintf("failed to load status manifest: %v", err), err)
	}

	registeredModules := modules.ListPathInfos()

	// Build rows combining registry data with status manifest
	var rows [][]string
	for _, info := range registeredModules {
		statusText := "unknown"
		lastTested := "-"
		notes := ""
		entry := manifest.Modules[info.ID]

		if entry.Status != "" {
			statusText = entry.Status
			if entry.LastTested != nil {
				lastTested = *entry.LastTested
			}
			notes = entry.Notes
		}

		// Color-code the status
		styledStatus := statusText
		switch statusText {
		case "tested":
			styledStatus = ui.Success.Render(statusText)
		case "failing":
			styledStatus = ui.Error.Render(statusText)
		case "needs-update":
			styledStatus = ui.Warning.Render(statusText)
		case "untested":
			styledStatus = ui.Muted.Render(statusText)
		}

		payloadSummary := "-"
		if len(entry.PayloadResults) > 0 {
			passed := 0
			for _, pr := range entry.PayloadResults {
				if pr.Execution == "PASS" && (pr.Verified == "YES" || pr.Verified == "SKIP") {
					passed++
				}
			}
			total := len(entry.PayloadResults)
			summary := fmt.Sprintf("%d/%d passed", passed, total)
			if passed == total {
				payloadSummary = ui.Success.Render(summary)
			} else {
				payloadSummary = ui.Error.Render(summary)
			}
		}

		rows = append(rows, []string{info.ID, info.Name, styledStatus, lastTested, payloadSummary, notes})
	}

	// Summary counts
	summary := manifest.Summary()
	total := len(registeredModules)

	fmt.Println()
	fmt.Printf("Module Test Status (%d total", total)
	if tested := summary["tested"]; tested > 0 {
		fmt.Printf(", %s tested", ui.Success.Render(fmt.Sprintf("%d", tested)))
	}
	if failing := summary["failing"]; failing > 0 {
		fmt.Printf(", %s failing", ui.Error.Render(fmt.Sprintf("%d", failing)))
	}
	if needsUpdate := summary["needs-update"]; needsUpdate > 0 {
		fmt.Printf(", %s needs update", ui.Warning.Render(fmt.Sprintf("%d", needsUpdate)))
	}
	if untested := summary["untested"]; untested > 0 {
		fmt.Printf(", %s untested", ui.Muted.Render(fmt.Sprintf("%d", untested)))
	}
	fmt.Println(")")
	fmt.Println()

	ui.Table([]string{"ID", "Name", "Status", "Last Tested", "Results", "Notes"}, rows)
	fmt.Println()

	return nil
}

// showModuleStatus displays detailed status for a single module.
func (r *REPL) showModuleStatus(moduleID string) error {
	manifest, err := status.LoadManifest()
	if err != nil {
		return NewExecutionError(fmt.Sprintf("failed to load status manifest: %v", err), err)
	}

	entry, exists := manifest.Modules[moduleID]
	if !exists {
		return NewInvalidArgumentsError(fmt.Sprintf("module '%s' not found in status manifest", moduleID))
	}

	kvPairs := []ui.KV{
		{Key: "Module", Value: moduleID},
		{Key: "Status", Value: entry.Status},
	}

	if entry.LastTested != nil {
		kvPairs = append(kvPairs, ui.KV{Key: "Last Tested", Value: *entry.LastTested})
	} else {
		kvPairs = append(kvPairs, ui.KV{Key: "Last Tested", Value: "-"})
	}

	if entry.TestedAgainst != nil {
		kvPairs = append(kvPairs, ui.KV{Key: "Tested Against", Value: *entry.TestedAgainst})
	}

	if entry.Notes != "" {
		kvPairs = append(kvPairs, ui.KV{Key: "Notes", Value: entry.Notes})
	}

	fmt.Println()
	ui.KeyValueTable("", kvPairs)

	if len(entry.PayloadResults) > 0 {
		fmt.Println()
		fmt.Println(ui.BoldCyan.Render("Payload Results"))
		fmt.Println()

		var resultRows [][]string
		for _, pr := range entry.PayloadResults {
			execStyled := pr.Execution
			if pr.Execution == "PASS" {
				execStyled = ui.Success.Render(pr.Execution)
			} else {
				execStyled = ui.Error.Render(pr.Execution)
			}

			verStyled := pr.Verified
			switch pr.Verified {
			case "YES":
				verStyled = ui.Success.Render(pr.Verified)
			case "NO":
				verStyled = ui.Error.Render(pr.Verified)
			case "SKIP":
				verStyled = ui.Warning.Render(pr.Verified)
			}

			reason := pr.FailReason
			if reason == "" {
				reason = "-"
			}
			resultRows = append(resultRows, []string{pr.Payload, execStyled, pr.Creds, verStyled, reason})
		}
		ui.Table([]string{"Payload", "Execution", "Creds", "Verified", "Failure Reason"}, resultRows)
	}

	fmt.Println()

	return nil
}

// markModuleTested marks a module as tested and saves the manifest.
func (r *REPL) markModuleTested(moduleID string, testedAgainst string) error {
	manifest, err := status.LoadManifest()
	if err != nil {
		return NewExecutionError(fmt.Sprintf("failed to load status manifest: %v", err), err)
	}

	if manifest.Modules == nil {
		manifest.Modules = make(map[string]status.ModuleStatus)
	}

	manifest.MarkTested(moduleID, testedAgainst)

	if err := status.SaveManifest(manifest); err != nil {
		return NewExecutionError(fmt.Sprintf("failed to save status manifest: %v", err), err)
	}

	fmt.Printf("Marked '%s' as tested.\n", moduleID)
	return nil
}

// markModuleResults records per-payload test results for a module.
// The resultsPath argument is a file path containing a JSON array of PayloadResult objects.
func (r *REPL) markModuleResults(moduleID string, testedAgainst string, resultsPath string) error {
	resultsData, err := os.ReadFile(resultsPath)
	if err != nil {
		return NewInvalidArgumentsError(fmt.Sprintf("failed to read results file '%s': %v", resultsPath, err))
	}

	var results []status.PayloadResult
	if err := json.Unmarshal(resultsData, &results); err != nil {
		return NewInvalidArgumentsError(fmt.Sprintf("invalid results JSON: %v", err))
	}

	manifest, err := status.LoadManifest()
	if err != nil {
		return NewExecutionError(fmt.Sprintf("failed to load status manifest: %v", err), err)
	}

	if manifest.Modules == nil {
		manifest.Modules = make(map[string]status.ModuleStatus)
	}

	manifest.MarkTestedWithResults(moduleID, testedAgainst, results)

	if err := status.SaveManifest(manifest); err != nil {
		return NewExecutionError(fmt.Sprintf("failed to save status manifest: %v", err), err)
	}

	passed := 0
	for _, r := range results {
		if r.Execution == "PASS" && (r.Verified == "YES" || r.Verified == "SKIP") {
			passed++
		}
	}

	if passed == len(results) {
		fmt.Printf("Marked '%s' as tested (%d/%d payloads passed).\n", moduleID, passed, len(results))
	} else {
		fmt.Printf("Marked '%s' as failing (%d/%d payloads passed).\n", moduleID, passed, len(results))
	}
	return nil
}

// markModuleStatus updates a module's status and saves the manifest.
func (r *REPL) markModuleStatus(moduleID string, newStatus string) error {
	manifest, err := status.LoadManifest()
	if err != nil {
		return NewExecutionError(fmt.Sprintf("failed to load status manifest: %v", err), err)
	}

	if manifest.Modules == nil {
		manifest.Modules = make(map[string]status.ModuleStatus)
	}

	if err := manifest.MarkStatus(moduleID, newStatus); err != nil {
		return NewInvalidArgumentsError(err.Error())
	}

	if err := status.SaveManifest(manifest); err != nil {
		return NewExecutionError(fmt.Sprintf("failed to save status manifest: %v", err), err)
	}

	fmt.Printf("Marked '%s' as '%s'.\n", moduleID, newStatus)
	return nil
}
