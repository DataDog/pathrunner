package repl

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/ui"
	"pathrunner/pkg/version"
	"strings"
)

// GetCommands returns all available commands (public interface)
func (r *REPL) GetCommands() map[string]*Command {
	return r.getCommands()
}

// getCommands returns all available commands
func (r *REPL) getCommands() map[string]*Command {
	return map[string]*Command{
		"help": {
			Name:        "help",
			Description: "Show help information",
			Handler:     r.cmdHelp,
		},
		"exit": {
			Name:        "exit",
			Description: "Exit pathrunner",
			Handler:     r.cmdExit,
		},
		"identity": {
			Name:        "identity",
			Description: "Manage AWS identities",
			Handler:     r.cmdIdentity,
		},
		"use": {
			Name:        "use",
			Description: "Select a module",
			Handler:     r.cmdUse,
		},
		"show": {
			Name:        "show",
			Description: "Alias for multiple display commands",
			Handler:     r.cmdShow,
		},
		"set": {
			Name:        "set",
			Description: "Set option values",
			Handler:     r.cmdSet,
		},
		"unset": {
			Name:        "unset",
			Description: "Unset option values",
			Handler:     r.cmdUnset,
		},
		"exploit": {
			Name:        "exploit",
			Description: "Execute the current module",
			Handler:     r.cmdExploit,
		},
		"whoami": {
			Name:        "whoami",
			Description: "Show current AWS identity information",
			Handler:     r.cmdWhoami,
		},
		"workspace": {
			Name:        "workspace",
			Description: "Manage pathrunner workspaces",
			Handler:     r.cmdWorkspace,
		},
		"context": {
			Name:        "context",
			Description: "Show current context (session, identity, module, options)",
			Handler:     r.cmdContext,
		},
		"aws": {
			Name:        "aws",
			Description: "Execute AWS CLI commands with current identity credentials",
			Handler:     r.cmdAWS,
		},
		"search": {
			Name:        "search",
			Description: "Search modules by keyword",
			Handler:     r.cmdSearch,
		},
		"modules": {
			Name:        "modules",
			Description: "List and search modules",
			Handler:     r.cmdModules,
		},
		"payloads": {
			Name:        "payloads",
			Description: "List available payloads",
			Handler:     r.cmdPayloads,
		},
		"discover": {
			Name:        "discover",
			Description: "Auto-discover values for module options",
			Handler:     r.cmdDiscover,
		},
		"version": {
			Name:        "version",
			Description: "Show version information",
			Handler:     r.cmdVersion,
		},
		"info": {
			Name:        "info",
			Description: "Show detailed module and path information",
			Handler:     r.cmdInfo,
		},
	}
}

// Help command implementation
func (r *REPL) cmdHelp(repl *REPL, args []string) error {
	if len(args) > 0 {
		return r.showSpecificHelp(args[0])
	}

	commands := r.getCommands()

	fmt.Println()

	coreOrder := []string{
		"modules", "search", "use",
		"identity", "aws", "whoami",
		"workspace", "context", "version",
		"help", "exit",
	}
	fmt.Println(ui.BoldCyan.Render("  Core Commands"))
	fmt.Println()
	for _, name := range coreOrder {
		if cmd, ok := commands[name]; ok {
			fmt.Printf("    %s  %s\n", ui.Primary.Render(fmt.Sprintf("%-12s", cmd.Name)), ui.Muted.Render(cmd.Description))
		}
	}

	fmt.Println()

	moduleOrder := []string{
		"info", "show", "set", "unset",
		"payloads", "discover", "exploit",
	}
	if r.currentModule == nil {
		fmt.Printf("  %s  %s\n", ui.BoldCyan.Render("Module Commands"), ui.Muted.Render("(select a module with 'use')"))
	} else {
		fmt.Printf("  %s  %s\n", ui.BoldCyan.Render("Module Commands"), ui.Accent.Render(r.currentModule.Name()))
	}
	fmt.Println()
	for _, name := range moduleOrder {
		if cmd, ok := commands[name]; ok {
			fmt.Printf("    %s  %s\n", ui.Primary.Render(fmt.Sprintf("%-12s", cmd.Name)), ui.Muted.Render(cmd.Description))
		}
	}

	fmt.Println()
	fmt.Printf("  %s\n", ui.Muted.Render("Use 'help <command>' for detailed information."))
	fmt.Println()

	return nil
}

// showSpecificHelp shows help for a specific command
func (r *REPL) showSpecificHelp(command string) error {
	switch command {
	case "identity":
		return r.showIdentityHelp()
	case "show":
		return r.showShowHelp()
	case "use":
		return r.showUseHelp()
	case "set":
		return r.showSetHelp()
	case "unset":
		return r.showUnsetHelp()
	case "exploit":
		return r.showExploitHelp()
	case "whoami":
		return r.showWhoamiHelp()
	case "workspace":
		return r.showWorkspaceHelp()
	case "context":
		return r.showContextHelp()
	case "search":
		return r.showSearchHelp()
	case "modules":
		return r.showModulesHelp()
	case "payloads":
		return r.showPayloadsHelp()
	case "discover":
		return r.showDiscoverHelp()
	case "version":
		return r.showVersionHelp()
	case "info":
		return r.showInfoHelp()
	default:
		return NewCommandNotFoundError(command)
	}
}

// Exit command implementation
func (r *REPL) cmdExit(repl *REPL, args []string) error {
	r.saveCurrentState()
	// Persist session to disk before exiting
	current := r.sessionManager.GetCurrentSession()
	if current != nil {
		r.sessionManager.SaveSession(current)
	}
	return io.EOF
}

// Help content methods
func (r *REPL) showIdentityHelp() error {
	fmt.Println("Identity Management Commands:")
	fmt.Println("  identity add                    - Add credentials from environment variables")
	fmt.Println("  identity add --profile <name>   - Add credentials from AWS profile")
	fmt.Println("  identity add --access <key> --secret <secret> [--token <token>] - Add credentials manually")
	fmt.Println("  identity add --from-output [--name <name>]      - Extract credentials from last command output")
	fmt.Println("  identity add --from-file <path> [--name <name>] - Extract credentials from file")
	fmt.Println("  identity add --from-clipboard [--name <name>]   - Extract credentials from clipboard")
	fmt.Println("  identity list                   - List all configured identities")
	fmt.Println("  identity show                   - Show current identity details")
	fmt.Println("  identity switch <name>          - Switch to a different identity")
	fmt.Println("  identity check [name]           - Check if identity has admin privileges")
	fmt.Println("  identity refresh                - Refresh current identity credentials")
	fmt.Println("  identity clear [name]           - Remove identity by name")
	fmt.Println("  identity clear --expired        - Remove all expired identities")
	fmt.Println("  identity remove [name]          - Alias for clear")
	fmt.Println()
	fmt.Println("Note: Use --name to set a custom identity name with any add method.")
	fmt.Println("      If --name is not provided, a name will be auto-generated.")
	fmt.Println("      Use --switch to auto-switch to the new identity without prompting.")
	fmt.Println("      Use --check-admin to auto-check admin privileges after adding.")
	fmt.Println()
	fmt.Println("Use 'identity <subcommand> help' for detailed help on a specific subcommand.")
	return nil
}

func (r *REPL) showIdentityCheckHelp() error {
	fmt.Println("Identity Check Command:")
	fmt.Println("  identity check          - Check if current identity has admin privileges")
	fmt.Println("  identity check <name>   - Check if named identity has admin privileges")
	fmt.Println()
	fmt.Println("Uses the IAM Policy Simulator (iam:SimulatePrincipalPolicy) to test")
	fmt.Println("whether the identity can perform admin-level actions. Tests 6 actions:")
	fmt.Println("  iam:PutUserPolicy, iam:AttachUserPolicy, iam:PutRolePolicy,")
	fmt.Println("  iam:AttachRolePolicy, secretsmanager:GetSecretValue, ssm:GetParameters")
	fmt.Println()
	fmt.Println("Results are cached on the identity and shown in 'identity list' and prompt.")
	fmt.Println("Admin identities show '!' suffix in the REPL prompt.")
	fmt.Println()
	fmt.Println("Note: Requires iam:SimulatePrincipalPolicy permission on the identity.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  identity check              # Check current identity")
	fmt.Println("  identity check my-profile   # Check specific identity")
	return nil
}

func (r *REPL) showIdentityAddHelp() error {
	fmt.Println("Identity Add Command:")
	fmt.Println("  identity add                                    - Add credentials from environment variables")
	fmt.Println("  identity add --profile <name>                   - Add credentials from AWS profile (SSO supported)")
	fmt.Println("  identity add --access <key> --secret <secret> [--token <token>] [--name <name>] - Add credentials manually")
	fmt.Println("  identity add --from-output [--name <name>]      - Extract credentials from last command output")
	fmt.Println("  identity add --from-file <path> [--name <name>] - Extract credentials from file")
	fmt.Println("  identity add --from-clipboard [--name <name>]   - Extract credentials from clipboard")
	fmt.Println()
	fmt.Println("The --name flag sets a custom identity name for any add method.")
	fmt.Println("If --name is not provided, a name will be auto-generated.")
	fmt.Println("The --switch flag auto-switches to the new identity without prompting.")
	fmt.Println("The --check-admin flag auto-checks admin privileges after adding.")
	fmt.Println()
	fmt.Println("Supported credential formats for extraction:")
	fmt.Println("  - AWS environment variables (AWS_ACCESS_KEY_ID, etc.)")
	fmt.Println("  - JSON objects with credential fields")
	fmt.Println("  - Python dict format")
	fmt.Println("  - Base64-encoded credentials")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  identity add --profile my-sso-profile")
	fmt.Println("  identity add --access AKIAIOSFODNN7EXAMPLE --secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	fmt.Println("  identity add --access AKIAEXAMPLE --secret SECRET --token TOKEN123 --name my-target")
	fmt.Println("  identity add --from-output --name exploited-role")
	return nil
}

func (r *REPL) showIdentitySwitchHelp() error {
	fmt.Println("Identity Switch Command:")
	fmt.Println("  identity switch <name>    - Switch to a different identity")
	fmt.Println()
	fmt.Println("Switches the active AWS identity used for all operations,")
	fmt.Println("including exploit execution and AWS CLI passthrough.")
	fmt.Println()
	fmt.Println("Use 'identity list' to see available identities.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  identity switch initial-access")
	fmt.Println("  identity switch exploited-role")
	return nil
}

func (r *REPL) showIdentityClearHelp() error {
	fmt.Println("Identity Clear/Remove Command:")
	fmt.Println("  identity clear [name]      - Remove a specific identity by name")
	fmt.Println("  identity clear --expired   - Remove all expired identities")
	fmt.Println("  identity remove [name]     - Alias for clear")
	fmt.Println("  identity remove --expired  - Alias for clear --expired")
	fmt.Println()
	fmt.Println("Cannot remove the currently active identity. Switch to a")
	fmt.Println("different identity first if you need to remove the current one.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  identity clear old-creds")
	fmt.Println("  identity clear --expired")
	return nil
}

func (r *REPL) showShowHelp() error {
	fmt.Println("Show Commands:")
	fmt.Println("  show modules    - List all available modules")
	fmt.Println("  show payloads   - List available payloads for current module")
	fmt.Println("  show options    - Show current module options")
	fmt.Println("  show info       - Show detailed path metadata for current module")
	return nil
}

func (r *REPL) showSearchHelp() error {
	fmt.Println("Search Command:")
	fmt.Println("  search <query>    - Search modules by keyword")
	fmt.Println()
	fmt.Println("Searches across module IDs, names, descriptions, categories,")
	fmt.Println("services, aliases, and required permissions.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  search passrole   - Find modules involving PassRole")
	fmt.Println("  search ec2        - Find EC2-related modules")
	fmt.Println("  search lambda     - Find Lambda-related modules")
	fmt.Println("  search escalation - Find privilege escalation modules")
	return nil
}

func (r *REPL) showModulesHelp() error {
	fmt.Println("Modules Command:")
	fmt.Println("  modules               - List all available modules")
	fmt.Println("  modules list           - List all available modules")
	fmt.Println("  modules search <query> - Search modules by keyword")
	fmt.Println("  modules help           - Show this help message")
	return nil
}

func (r *REPL) showPayloadsHelp() error {
	fmt.Println("Payloads Command:")
	fmt.Println("  payloads        - List payloads (current module or all)")
	fmt.Println("  payloads list   - List payloads (current module or all)")
	fmt.Println("  payloads help   - Show this help message")
	return nil
}

func (r *REPL) showDiscoverHelp() error {
	fmt.Println("Discover Command:")
	fmt.Println("  discover               - Auto-discover all missing discoverable options")
	fmt.Println("  discover <OPTION>      - Auto-discover a specific option")
	fmt.Println("  discover help          - Show this help message")
	fmt.Println()
	fmt.Println("Uses AWS API calls to enumerate valid values for module options.")
	fmt.Println("Requires an active identity with appropriate 'additional' permissions")
	fmt.Println("(e.g., iam:ListRoles for ROLE_ARN, iam:ListInstanceProfiles for INSTANCE_PROFILE).")
	fmt.Println()
	fmt.Println("Options that support auto-discovery are marked with [auto] in 'show options'.")
	fmt.Println("When 'exploit' is run with missing discoverable options, discovery is")
	fmt.Println("attempted automatically before failing.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  discover               # Discover all missing options")
	fmt.Println("  discover ROLE_ARN      # Discover only ROLE_ARN")
	return nil
}

func (r *REPL) showUseHelp() error {
	fmt.Println("Use Command:")
	fmt.Println("  use <module>    - Select a module for use")
	fmt.Println()

	infos := modules.ListPathInfos()
	if len(infos) > 0 {
		fmt.Println("Available modules:")
		fmt.Println()

		rows := make([][]string, 0, len(infos))
		for _, info := range infos {
			shortName := ""
			if len(info.Aliases) > 0 {
				shortName = info.Aliases[0]
			}
			rows = append(rows, []string{info.ID, shortName})
		}

		ui.Table([]string{"ID", "Short Name"}, rows)
		fmt.Println()
		fmt.Println("Use either the ID or short name with 'use'. For full details: 'show modules'")
	} else {
		fmt.Println("Available modules can be listed with 'show modules'")
	}
	return nil
}

func (r *REPL) showSetHelp() error {
	fmt.Println("Set Command:")
	fmt.Println("  set <option> <value>    - Set module option value")
	fmt.Println()
	fmt.Println("Available options can be listed with 'show options'")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  set ROLE_ARN arn:aws:iam::123456789012:role/MyRole")
	fmt.Println("  set PAYLOAD exfil/response")
	return nil
}

func (r *REPL) showUnsetHelp() error {
	fmt.Println("Unset Command:")
	fmt.Println("  unset <option>    - Clear module option value")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  unset ROLE_ARN")
	fmt.Println("  unset PAYLOAD")
	return nil
}

func (r *REPL) showExploitHelp() error {
	fmt.Println("Exploit Command:")
	fmt.Println("  exploit    - Execute the currently selected module")
	fmt.Println()
	fmt.Println("Before running exploit:")
	fmt.Println("1. Select a module with 'use <module>'")
	fmt.Println("2. Configure required options with 'set <option> <value>'")
	fmt.Println("3. Ensure you have valid AWS credentials with 'identity add'")
	return nil
}

func (r *REPL) showWhoamiHelp() error {
	fmt.Println("Whoami Command:")
	fmt.Println("  whoami    - Display current AWS identity information")
	fmt.Println()
	fmt.Println("Shows:")
	fmt.Println("  - Current identity name and type")
	fmt.Println("  - AWS account ID")
	fmt.Println("  - IAM user or role ARN")
	fmt.Println("  - AWS region")
	fmt.Println("  - Credential expiration (if applicable)")
	return nil
}

func (r *REPL) showWorkspaceHelp() error {
	fmt.Println("Workspace Management Commands:")
	fmt.Println("  workspace create <name>    - Create a new workspace")
	fmt.Println("  workspace list             - List all workspaces")
	fmt.Println("  workspace switch <name>    - Switch to a different workspace")
	fmt.Println("  workspace save             - Save the current workspace")
	fmt.Println("  workspace delete <name>    - Delete a workspace")
	fmt.Println("  workspace cleanup          - Clean up AWS resources (interactive)")
	fmt.Println("  workspace cleanup --all    - Clean up all resources without prompt")
	fmt.Println("  workspace cleanup --module <id> - Clean up resources from a specific module")
	fmt.Println("  workspace report           - Generate cleanup report for handoff")
	fmt.Println("  workspace report --module <id>  - Report for a specific module only")
	fmt.Println("  workspace history [limit]  - Show command history with timestamps")
	fmt.Println("  workspace help             - Show this help message")
	fmt.Println()
	fmt.Println("Workspaces persist:")
	fmt.Println("  - AWS identities and current selection")
	fmt.Println("  - Command execution history with timestamps")
	fmt.Println("  - Created AWS resources for cleanup")
	fmt.Println("  - Module options and current module selection")
	fmt.Println()
	fmt.Println("Use 'workspace <subcommand> help' for detailed help on a specific subcommand.")
	return nil
}

func (r *REPL) showWorkspaceCreateHelp() error {
	fmt.Println("Workspace Create Command:")
	fmt.Println("  workspace create <name>    - Create a new workspace and switch to it")
	fmt.Println()
	fmt.Println("Creates a new workspace with an isolated set of identities, options,")
	fmt.Println("and resource tracking. Automatically switches to the new workspace.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  workspace create my-project")
	fmt.Println("  workspace create pentest-2024")
	return nil
}

func (r *REPL) showWorkspaceSwitchHelp() error {
	fmt.Println("Workspace Switch Command:")
	fmt.Println("  workspace switch <name>    - Switch to a different workspace")
	fmt.Println()
	fmt.Println("Saves the current workspace state and loads the target workspace.")
	fmt.Println("Identities, module selection, options, and resource tracking are")
	fmt.Println("completely isolated between workspaces.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  workspace switch default")
	fmt.Println("  workspace switch my-project")
	return nil
}

func (r *REPL) showWorkspaceDeleteHelp() error {
	fmt.Println("Workspace Delete Command:")
	fmt.Println("  workspace delete <name>    - Delete a workspace")
	fmt.Println()
	fmt.Println("Permanently deletes a workspace and its saved state.")
	fmt.Println("Cannot delete the 'default' workspace or the currently active workspace.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  workspace delete old-project")
	return nil
}

func (r *REPL) showWorkspaceCleanupHelp() error {
	fmt.Println("Workspace Cleanup Command:")
	fmt.Println("  workspace cleanup                - Interactive cleanup (multi-select)")
	fmt.Println("  workspace cleanup --all           - Clean up all tracked resources")
	fmt.Println("  workspace cleanup --module <id>   - Clean up resources from a specific module")
	fmt.Println("  workspace cleanup --all --module <id> - Non-interactive, filtered by module")
	fmt.Println()
	fmt.Println("Cleans up AWS resources created by exploit modules in the current workspace.")
	fmt.Println("Without flags, shows an interactive multi-select prompt to choose resources.")
	fmt.Println()
	fmt.Println("Requires an active identity with permissions to delete the tracked resources.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  workspace cleanup                     # Interactive selection")
	fmt.Println("  workspace cleanup --all               # Clean everything")
	fmt.Println("  workspace cleanup --module lambda-001  # Only Lambda module resources")
	return nil
}

func (r *REPL) showWorkspaceReportHelp() error {
	fmt.Println("Workspace Report Command:")
	fmt.Println("  workspace report                - Generate full cleanup report")
	fmt.Println("  workspace report --module <id>  - Report for a specific module only")
	fmt.Println()
	fmt.Println("Generates a cleanup report listing all resources created or modified")
	fmt.Println("by pathrunner in the current workspace. The report includes:")
	fmt.Println("  - Created resources (Lambda functions, EC2 instances, IAM entities)")
	fmt.Println("  - Modified resources (policy attachments that need reversal)")
	fmt.Println("  - Manual AWS CLI cleanup commands for each resource")
	fmt.Println()
	fmt.Println("Useful for handing off to a client, admin, or point of contact when")
	fmt.Println("the penetration tester cannot or should not delete resources themselves.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  workspace report                      # Full report")
	fmt.Println("  workspace report --module lambda-002   # Only lambda-002 resources")
	return nil
}

func (r *REPL) showWorkspaceHistoryHelp() error {
	fmt.Println("Workspace History Command:")
	fmt.Println("  workspace history          - Show last 20 commands")
	fmt.Println("  workspace history <limit>  - Show last N commands")
	fmt.Println()
	fmt.Println("Displays the command execution history for the current workspace,")
	fmt.Println("including timestamps and success/failure status.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  workspace history          # Last 20 commands")
	fmt.Println("  workspace history 50       # Last 50 commands")
	return nil
}

// Utility function to check if string is in slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

// cmdInfo shows detailed module and path information
func (r *REPL) cmdInfo(repl *REPL, args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showInfoHelp()
	}
	return r.showInfo()
}

func (r *REPL) showInfoHelp() error {
	fmt.Println("Info Command:")
	fmt.Println("  info    - Show detailed path metadata for the current module")
	fmt.Println()
	fmt.Println("Displays path ID, name, category, services, permissions,")
	fmt.Println("prerequisites, related paths, references, and aliases.")
	fmt.Println()
	fmt.Println("Requires a module to be selected with 'use <module>'.")
	fmt.Println("Equivalent to 'show info'.")
	return nil
}

// cmdVersion shows version information
func (r *REPL) cmdVersion(repl *REPL, args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showVersionHelp()
	}
	fmt.Println(version.Info())
	return nil
}

func (r *REPL) showVersionHelp() error {
	fmt.Println("Version Command:")
	fmt.Println("  version    - Show pathrunner version, build, and runtime information")
	return nil
}

// buildContextData gathers current workspace/identity/module/payload/status.
func (r *REPL) buildContextData() (workspace, identityStr, moduleStr, payloadStr, status string) {
	session := r.sessionManager.GetCurrentSession()
	workspace = session.GetName()

	identity := r.identityManager.GetCurrent()
	if identity != nil {
		identityStr = identity.Name
		if identity.IsExpired() {
			identityStr += " " + ui.Error.Render("(expired)")
		} else {
			identityStr += " " + ui.Success.Render("✓")
		}
	}

	if r.currentModule != nil {
		moduleStr = r.currentModule.Name()
	}

	if payload, exists := r.options["PAYLOAD"]; exists && payload != "" {
		payloadStr = payload
	}

	if identity == nil {
		status = "❌ No identity configured"
	} else if identity.IsExpired() {
		status = "❌ Identity expired"
	} else if r.currentModule == nil {
		status = "⚠️  No module selected"
	} else if err := r.validateOptionsForContext(); err != nil {
		status = "⚠️  " + err.Error()
	} else {
		status = "✅ Ready for exploitation"
	}

	return
}

// PrintStartupBanner prints the integrated startup banner with context.
func (r *REPL) PrintStartupBanner() {
	ui.StartupBanner(r.buildContextData())
}

// PrintContextPanel prints the context summary box.
func (r *REPL) PrintContextPanel() {
	fmt.Println(ui.ContextPanel(r.buildContextData()))
	fmt.Println()
}

// cmdContext shows current context information
func (r *REPL) cmdContext(repl *REPL, args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showContextHelp()
	}

	r.PrintContextPanel()

	session := r.sessionManager.GetCurrentSession()
	identity := r.identityManager.GetCurrent()

	// Workspace details table
	ui.Section("Workspace")
	ui.KeyValueTable("", []ui.KV{
		{Key: "Name", Value: session.GetName()},
		{Key: "Created", Value: session.GetCreated()},
		{Key: "Last Accessed", Value: session.GetLastAccessed()},
		{Key: "Commands", Value: fmt.Sprintf("%d", session.GetCommandCount())},
		{Key: "Resources", Value: fmt.Sprintf("%d", session.GetResourceCount())},
	})
	fmt.Println()

	// Identity details
	if identity != nil {
		ui.Section("Identity")

		kvPairs := []ui.KV{
			{Key: "Name", Value: identity.Name},
			{Key: "Type", Value: identity.Type},
			{Key: "Region", Value: identity.Region},
		}

		if identity.Profile != "" {
			kvPairs = append(kvPairs, ui.KV{Key: "Profile", Value: identity.Profile})
		}
		if identity.CallerARN != "" {
			kvPairs = append(kvPairs, ui.KV{Key: "ARN", Value: identity.CallerARN})
		}
		if identity.IsAdmin != nil {
			if *identity.IsAdmin {
				kvPairs = append(kvPairs, ui.KV{Key: "Admin", Value: "Yes"})
			} else {
				kvPairs = append(kvPairs, ui.KV{Key: "Admin", Value: "No"})
			}
		} else {
			kvPairs = append(kvPairs, ui.KV{Key: "Admin", Value: "- (not checked)"})
		}

		if identity.ExpiresAt != nil {
			expiryStatus := "Valid"
			if identity.IsExpired() {
				expiryStatus = ui.Error.Render("EXPIRED")
			}
			kvPairs = append(kvPairs, ui.KV{Key: "Expires", Value: identity.ExpiresAt.Format("2006-01-02 15:04:05 MST")})
			kvPairs = append(kvPairs, ui.KV{Key: "Status", Value: expiryStatus})
		} else {
			kvPairs = append(kvPairs, ui.KV{Key: "Status", Value: "Valid (no expiration)"})
		}

		ui.KeyValueTable("", kvPairs)
	} else {
		fmt.Println("Identity: None configured")
		fmt.Println("  Use 'identity add' to configure AWS credentials")
	}
	fmt.Println()

	// Module information
	if r.currentModule != nil {
		ui.Section("Module")

		modulePayload := "None selected"
		if payload, exists := r.options["PAYLOAD"]; exists && payload != "" {
			modulePayload = payload
		}

		ui.KeyValueTable("", []ui.KV{
			{Key: "Name", Value: r.currentModule.Name()},
			{Key: "Description", Value: r.currentModule.Description()},
			{Key: "Payload", Value: modulePayload},
		})
		fmt.Println()

		// Options table
		options := r.currentModule.Options()
		if len(options) > 0 {
			ui.Section("Module Options")

			rows := make([][]string, 0, len(options))
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
					if value == "<not set>" {
						required = ui.Error.Render("Yes")
					} else {
						required = "Yes"
					}
				}

				rows = append(rows, []string{option.Name, value, required})
			}

			ui.Table([]string{"Option", "Value", "Required"}, rows)
			fmt.Println()
		}

		// Payload options
		if payload, exists := r.options["PAYLOAD"]; exists && payload != "" {
			payloadOptions := r.currentModule.PayloadOptions(payload)
			if len(payloadOptions) > 0 {
				ui.Section(fmt.Sprintf("Payload Options (%s)", payload))

				rows := make([][]string, 0, len(payloadOptions))
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
						if value == "<not set>" {
							required = ui.Error.Render("Yes")
						} else {
							required = "Yes"
						}
					}

					rows = append(rows, []string{option.Name, value, required})
				}

				ui.Table([]string{"Payload Option", "Value", "Required"}, rows)
				fmt.Println()
			}
		}
	} else {
		fmt.Println("Module: None selected")
		fmt.Println("  Use 'use <module>' to select a module")
		fmt.Println()
	}

	return nil
}

// validateOptionsForContext validates options without throwing errors
func (r *REPL) validateOptionsForContext() error {
	if r.currentModule == nil {
		return fmt.Errorf("no module selected")
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

	if len(missing) > 0 {
		return fmt.Errorf("missing required options: %s", strings.Join(missing, ", "))
	}

	return nil
}

func (r *REPL) showContextHelp() error {
	fmt.Println("Context Command:")
	fmt.Println("  context    - Show detailed information about current context")
	fmt.Println()
	fmt.Println("Displays:")
	fmt.Println("  - Current workspace information")
	fmt.Println("  - Active AWS identity and status")
	fmt.Println("  - Selected module and configuration")
	fmt.Println("  - Set options and payload selection")
	fmt.Println("  - Readiness status for exploitation")
	fmt.Println()
	fmt.Println("The prompt also shows abbreviated context:")
	fmt.Println("  pathrunner[workspace][identity][module][payload]>")
	fmt.Println("  - '*' after identity name indicates expired credentials")
	fmt.Println("  - '!' after identity name indicates confirmed admin")
	fmt.Println("  - Components only show when configured")
	return nil
}

// cmdAWS executes AWS CLI commands with current identity credentials
func (r *REPL) cmdAWS(repl *REPL, args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showAWSHelp()
	}

	// Check if AWS CLI is available
	awsPath, err := exec.LookPath("aws")
	if err != nil {
		return fmt.Errorf("AWS CLI not found in PATH. Please install the AWS CLI: https://aws.amazon.com/cli/")
	}

	// Get current identity
	identity := r.identityManager.GetCurrent()
	if identity == nil {
		return NewIdentityRequiredError()
	}

	if identity.IsExpired() {
		return NewAuthError("current identity has expired. Use 'identity refresh' or add new credentials", nil)
	}

	// Get credentials from identity
	var accessKey, secretKey, sessionToken, region string
	if identity.Type == "profile" {
		config := identity.GetConfig()
		creds, err := config.Credentials.Retrieve(context.Background())
		if err != nil {
			return fmt.Errorf("failed to retrieve credentials from profile: %v", err)
		}
		accessKey = creds.AccessKeyID
		secretKey = creds.SecretAccessKey
		sessionToken = creds.SessionToken
		region = config.Region
	} else {
		accessKey = identity.AccessKeyID
		secretKey = identity.SecretKey
		sessionToken = identity.SessionToken
		region = identity.Region
	}

	if accessKey == "" || secretKey == "" {
		return fmt.Errorf("identity has no credentials available")
	}

	// Create command with AWS CLI
	cmd := exec.Command(awsPath, args...)

	// Set environment variables with current identity credentials
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", accessKey),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", secretKey),
		fmt.Sprintf("AWS_REGION=%s", region),
	)

	if sessionToken != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("AWS_SESSION_TOKEN=%s", sessionToken))
	}

	// Connect stdin, stdout, stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Execute the command
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return nil
		}
		return fmt.Errorf("failed to execute AWS CLI: %v", err)
	}

	return nil
}

func (r *REPL) showAWSHelp() error {
	fmt.Println("AWS CLI Passthrough Command:")
	fmt.Println("  aws <aws-cli-args>    - Execute AWS CLI with current identity credentials")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  This command passes through to the AWS CLI binary with the current")
	fmt.Println("  identity's credentials automatically injected as environment variables.")
	fmt.Println()
	fmt.Println("Requirements:")
	fmt.Println("  - AWS CLI must be installed and available in PATH")
	fmt.Println("  - A current identity must be selected")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  aws s3 ls                        - List S3 buckets")
	fmt.Println("  aws sts get-caller-identity      - Show current identity")
	fmt.Println("  aws iam list-roles               - List IAM roles")
	fmt.Println("  aws ec2 describe-instances       - List EC2 instances")
	fmt.Println()
	fmt.Println("Note:")
	fmt.Println("  Credentials are passed via environment variables and automatically")
	fmt.Println("  update when you switch identities in Pathrunner.")
	return nil
}
