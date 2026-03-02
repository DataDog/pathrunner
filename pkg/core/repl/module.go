package repl

import (
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/utils"
	"strings"

	"os"

	"github.com/aquasecurity/table"
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

	t := table.New(os.Stdout)
	t.SetHeaders("ID", "Name", "Category", "Services")
	t.SetHeaderStyle(table.StyleBold)
	t.SetRowLines(false)
	t.SetLineStyle(table.StyleCyan)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.SetAlignment(table.AlignLeft)

	for _, info := range results {
		t.AddRow(info.ID, info.Name, info.Category, strings.Join(info.Services, ", "))
	}

	fmt.Printf("Search results for '%s':\n", query)
	fmt.Println()
	t.Render()
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

	// Auto-show payload options after setting PAYLOAD
	if strings.ToUpper(option) == "PAYLOAD" {
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

	// Validate required options
	if err := r.validateOptions(); err != nil {
		return err
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

// showInfo displays detailed PathInfo for the current module as a single table
func (r *REPL) showInfo() error {
	if r.currentModule == nil {
		return NewValidationError("no module selected. Use 'use <module>' to select one", nil)
	}

	info := r.currentModule.PathInfo()
	if info.ID == "" {
		fmt.Printf("Module %s has no path metadata.\n", r.currentModule.Name())
		return nil
	}

	t := table.New(os.Stdout)
	t.SetHeaders("Field", "Value")
	t.SetHeaderStyle(table.StyleBold)
	t.SetRowLines(false)
	t.SetLineStyle(table.StyleCyan)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.SetAlignment(table.AlignLeft)

	t.AddRow("Path ID", info.ID)
	t.AddRow("Name", info.Name)
	t.AddRow("Category", info.Category)
	t.AddRow("Services", strings.Join(info.Services, ", "))
	t.AddRow("Description", info.Description)

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
		t.AddRow("Required Permissions", strings.Join(perms, "\n"))
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
		t.AddRow("Additional Permissions", strings.Join(perms, "\n"))
	}

	// Prerequisites
	if len(info.Prerequisites.Admin) > 0 {
		var items []string
		for _, req := range info.Prerequisites.Admin {
			items = append(items, req)
		}
		t.AddRow("Prerequisites (Admin)", strings.Join(items, "\n"))
	}
	if len(info.Prerequisites.Lateral) > 0 {
		var items []string
		for _, req := range info.Prerequisites.Lateral {
			items = append(items, req)
		}
		t.AddRow("Prerequisites (Lateral)", strings.Join(items, "\n"))
	}

	// Related Paths
	if len(info.RelatedPaths) > 0 {
		t.AddRow("Related Paths", strings.Join(info.RelatedPaths, ", "))
	}

	// References
	if len(info.References) > 0 {
		var refs []string
		for _, ref := range info.References {
			refs = append(refs, ref.Title+": "+ref.URL)
		}
		t.AddRow("References", strings.Join(refs, "\n"))
	}

	// URL
	t.AddRow("URL", info.PathfindingCloudURL())

	// Aliases
	if len(info.Aliases) > 0 {
		t.AddRow("Aliases", strings.Join(info.Aliases, ", "))
	}

	if info.Author != "" {
		t.AddRow("Author", info.Author)
	}

	fmt.Println()
	t.Render()
	fmt.Println()

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

		t := table.New(os.Stdout)
		t.SetHeaders("Module", "Description")
		t.SetHeaderStyle(table.StyleBold)
		t.SetRowLines(false)
		t.SetLineStyle(table.StyleCyan)
		t.SetDividers(table.UnicodeRoundedDividers)
		t.SetAlignment(table.AlignLeft)

		for _, name := range moduleNames {
			_, description, err := modules.GetModuleInfo(name)
			if err == nil {
				t.AddRow(name, description)
			}
		}

		fmt.Println("Available Modules:")
		fmt.Println()
		t.Render()
		fmt.Println()
		return nil
	}

	t := table.New(os.Stdout)
	t.SetHeaders("ID", "Name", "Category", "Description")
	t.SetHeaderStyle(table.StyleBold)
	t.SetRowLines(false)
	t.SetLineStyle(table.StyleCyan)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.SetAlignment(table.AlignLeft)

	for _, info := range infos {
		t.AddRow(info.ID, info.Name, info.Category, info.Description)
	}

	fmt.Println("Available Modules:")
	fmt.Println()
	t.Render()
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

	// Create table
	t := table.New(os.Stdout)
	t.SetHeaders("Module", "Payload", "Description")
	t.SetHeaderStyle(table.StyleBold)
	t.SetRowLines(false)
	t.SetLineStyle(table.StyleCyan)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.SetAlignment(table.AlignLeft)

	for _, payload := range payloads {
		t.AddRow(moduleName, payload.Name, payload.Description)
	}

	fmt.Printf("Available Payloads for %s:\n", moduleName)
	fmt.Println()
	t.Render()
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

	// Create table
	t := table.New(os.Stdout)
	t.SetHeaders("Module", "Payload", "Description")
	t.SetHeaderStyle(table.StyleBold)
	t.SetRowLines(false)
	t.SetLineStyle(table.StyleCyan)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.SetAlignment(table.AlignLeft)

	totalPayloads := 0
	for _, moduleName := range moduleNames {
		module, err := modules.LoadModule(moduleName)
		if err != nil || module == nil {
			continue
		}

		payloads := module.ListPayloads()
		for _, payload := range payloads {
			t.AddRow(moduleName, payload.Name, payload.Description)
			totalPayloads++
		}
	}

	if totalPayloads == 0 {
		fmt.Println("No payloads available.")
		return nil
	}

	fmt.Println("Available Payloads (all modules):")
	fmt.Println()
	t.Render()
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

	// Create table
	t := table.New(os.Stdout)
	t.SetHeaders("Option", "Value", "Required", "Description")
	t.SetHeaderStyle(table.StyleBold)
	t.SetRowLines(false)
	t.SetLineStyle(table.StyleCyan)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.SetAlignment(table.AlignLeft)

	for _, option := range options {
		value := r.options[option.Name]
		if value == "" && option.Default != "" {
			value = option.Default + " (default)"
		}
		if value == "" {
			value = "<not set>"
		}

		required := "No"
		if option.Required {
			required = "Yes"
		}

		t.AddRow(option.Name, value, required, option.Description)
	}

	fmt.Printf("Options for %s:\n", r.currentModule.Name())
	fmt.Println()
	t.Render()
	fmt.Println()

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

	// Create table
	t := table.New(os.Stdout)
	t.SetHeaders("Payload Option", "Value", "Required", "Description")
	t.SetHeaderStyle(table.StyleBold)
	t.SetRowLines(false)
	t.SetLineStyle(table.StyleCyan)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.SetAlignment(table.AlignLeft)

	for _, option := range payloadOptions {
		value := r.options[option.Name]
		if value == "" && option.Default != "" {
			value = option.Default + " (default)"
		}
		if value == "" {
			value = "<not set>"
		}

		required := "No"
		if option.Required {
			required = "Yes"
		}

		t.AddRow(option.Name, value, required, option.Description)
	}

	fmt.Printf("Payload Options for %s:\n", payload)
	fmt.Println()
	t.Render()
	fmt.Println()

	return nil
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
		"--keys",
		data["ACCESS_KEY_ID"],
		data["SECRET_ACCESS_KEY"],
	}

	if data["SESSION_TOKEN"] != "" {
		cmdArgs = append(cmdArgs, data["SESSION_TOKEN"])
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

	// Check if we should auto-switch
	if data["AUTO_SWITCH"] == "true" {
		// The identity manager will have created the identity with a generated name
		// We need to find it and switch to it
		identities := r.identityManager.GetIdentities()

		// Look for the most recently added identity with matching access key
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
	cmdArgs := []string{
		"--keys",
		creds.AccessKeyID,
		creds.SecretAccessKey,
	}

	if creds.SessionToken != "" {
		cmdArgs = append(cmdArgs, creds.SessionToken)
	}

	identityName := creds.GenerateIdentityName()

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

	return nil
}
