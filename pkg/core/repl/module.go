package repl

import (
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/ui"
	"pathrunner/pkg/utils"
	"strings"
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

// cmdShow displays various information
func (r *REPL) cmdShow(repl *REPL, args []string) error {
	if len(args) == 0 {
		return NewInvalidArgumentsError("show command requires a target. Use 'show help' for more information")
	}

	target := args[0]

	if target == "help" {
		return r.showShowHelp()
	}

	// Handle aliases for show subcommands
	switch target {
	case "module":
		target = "modules"
	case "payload":
		target = "payloads"
	}

	switch target {
	case "modules":
		return r.showModules()
	case "payloads":
		return r.showPayloads()
	case "options":
		return r.showOptions()
	case "info":
		return r.showInfo()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown show target: %s. Use 'show help' for available targets", args[0]))
	}
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
		return r.showModules()
	}

	switch args[0] {
	case "list":
		return r.showModules()
	case "search":
		if len(args) < 2 {
			return NewInvalidArgumentsError("modules search requires a query")
		}
		return r.cmdSearch(repl, args[1:])
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

	// After PAYLOAD is set, check for payload-specific required options
	if payload, exists := r.options["PAYLOAD"]; exists {
		payloadOpts := r.currentModule.PayloadOptions(payload)
		for _, opt := range payloadOpts {
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

	// Show payload options after selection
	fmt.Println()
	r.showPayloadOptions(selected.Name)

	return nil
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

	result, err := r.currentModule.Execute(identity, r.options, r.sessionManager)
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

// showModules displays available modules with enriched metadata
func (r *REPL) showModules() error {
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
				rows = append(rows, []string{name, description})
			}
		}

		fmt.Println("Available Modules:")
		fmt.Println()
		ui.Table([]string{"Module", "Description"}, rows)
		fmt.Println()
		return nil
	}

	rows := make([][]string, 0, len(infos))
	for _, info := range infos {
		rows = append(rows, []string{info.ID, info.Name, info.Category, info.Description})
	}

	fmt.Println("Available Modules:")
	fmt.Println()
	ui.Table([]string{"ID", "Name", "Category", "Description"}, rows)
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

	fmt.Printf("\n✓ Detected credentials in exploit output\n")
	fmt.Printf("  Identity name: %s\n", name)
	fmt.Printf("  Type: %s\n", data["TYPE"])
	if data["EXPIRES_AT"] != "" {
		fmt.Printf("  Expires: %s\n", data["EXPIRES_AT"])
	}
	fmt.Printf("  Automatically importing credentials...\n\n")

	// Add the identity
	err := r.identityManager.AddIdentity(cmdArgs)
	if err != nil {
		fmt.Printf("⚠ Failed to auto-import identity: %v\n", err)
		fmt.Printf("  You can manually add it with: identity add %s\n", strings.Join(cmdArgs, " "))
		return err
	}

	fmt.Printf("✓ Identity added successfully!\n")
	r.UpdatePrompt()

	// Check if we should auto-switch
	if data["AUTO_SWITCH"] == "true" {
		identities := r.identityManager.GetIdentities()

		for identName := range identities {
			ident := identities[identName]
			if ident.AccessKeyID == data["ACCESS_KEY_ID"] {
				err := r.identityManager.SwitchIdentity(identName)
				if err == nil {
					fmt.Printf("✓ Switched to identity '%s'\n", identName)
					r.UpdatePrompt()
				}
				break
			}
		}
	}

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
