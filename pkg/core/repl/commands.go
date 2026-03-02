package repl

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/aquasecurity/table"
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
			Description: "Display information",
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
			Description: "Manage workspaces",
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
	}
}

// Help command implementation
func (r *REPL) cmdHelp(repl *REPL, args []string) error {
	if len(args) > 0 {
		return r.showSpecificHelp(args[0])
	}

	// Show general help
	fmt.Println("Pathrunner AWS Post-Exploitation Framework")
	fmt.Println("=========================================")
	fmt.Println()
	fmt.Println("Available Commands:")

	commands := r.getCommands()

	// Sort commands for consistent display
	var names []string
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		cmd := commands[name]
		fmt.Printf("  %-12s %s\n", cmd.Name, cmd.Description)
	}

	fmt.Println()
	fmt.Println("Use 'help <command>' for detailed information about a specific command.")
	fmt.Println()

	if r.currentModule != nil {
		fmt.Printf("Current Module: %s\n", r.currentModule.Name())
		fmt.Printf("Description: %s\n", r.currentModule.Description())
	} else {
		fmt.Println("No module selected. Use 'use <module>' to select one.")
	}

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
	fmt.Println("  identity add --keys <key> <secret> [token] - Add credentials manually")
	fmt.Println("  identity add --from-output [--name <name>]      - Extract credentials from last command output")
	fmt.Println("  identity add --from-file <path> [--name <name>] - Extract credentials from file")
	fmt.Println("  identity add --from-clipboard [--name <name>]   - Extract credentials from clipboard")
	fmt.Println("  identity list                   - List all configured identities")
	fmt.Println("  identity show                   - Show current identity details")
	fmt.Println("  identity switch <name>          - Switch to a different identity")
	fmt.Println("  identity refresh                - Refresh current identity credentials")
	fmt.Println("  identity clear [name]           - Remove identity by name")
	fmt.Println("  identity clear --expired        - Remove all expired identities")
	fmt.Println("  identity remove [name]          - Alias for clear")
	fmt.Println()
	fmt.Println("Note: For credential extraction methods (--from-output, --from-file, --from-clipboard),")
	fmt.Println("      you can optionally specify --name to set a custom identity name.")
	fmt.Println("      If --name is not provided, you will be prompted to enter a custom name.")
	fmt.Println()
	fmt.Println("Use 'identity <subcommand> help' for detailed help on a specific subcommand.")
	return nil
}

func (r *REPL) showIdentityAddHelp() error {
	fmt.Println("Identity Add Command:")
	fmt.Println("  identity add                                    - Add credentials from environment variables")
	fmt.Println("  identity add --profile <name>                   - Add credentials from AWS profile (SSO supported)")
	fmt.Println("  identity add --keys <key> <secret> [token]      - Add credentials manually")
	fmt.Println("  identity add --from-output [--name <name>]      - Extract credentials from last command output")
	fmt.Println("  identity add --from-file <path> [--name <name>] - Extract credentials from file")
	fmt.Println("  identity add --from-clipboard [--name <name>]   - Extract credentials from clipboard")
	fmt.Println()
	fmt.Println("The --name flag sets a custom identity name for credential extraction methods.")
	fmt.Println("If --name is not provided, you will be prompted to enter one.")
	fmt.Println()
	fmt.Println("Supported credential formats for extraction:")
	fmt.Println("  - AWS environment variables (AWS_ACCESS_KEY_ID, etc.)")
	fmt.Println("  - JSON objects with credential fields")
	fmt.Println("  - Python dict format")
	fmt.Println("  - Base64-encoded credentials")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  identity add --profile my-sso-profile")
	fmt.Println("  identity add --keys AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	fmt.Println("  identity add --keys AKIAEXAMPLE SECRET TOKEN123")
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

func (r *REPL) showUseHelp() error {
	fmt.Println("Use Command:")
	fmt.Println("  use <module>    - Select a module for use")
	fmt.Println()
	fmt.Println("Available modules can be listed with 'show modules'")
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
	fmt.Println("  set PAYLOAD exfil/output")
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

// cmdContext shows current context information
func (r *REPL) cmdContext(repl *REPL, args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showContextHelp()
	}

	fmt.Println("Current Context:")
	fmt.Println("===============")
	fmt.Println()

	// Workspace information table
	session := r.sessionManager.GetCurrentSession()
	workspaceTable := table.New(os.Stdout)
	workspaceTable.SetHeaders("Property", "Value")
	workspaceTable.SetHeaderStyle(table.StyleBold)
	workspaceTable.SetRowLines(false)
	workspaceTable.SetLineStyle(table.StyleCyan)
	workspaceTable.SetDividers(table.UnicodeRoundedDividers)
	workspaceTable.SetAlignment(table.AlignLeft)

	workspaceTable.AddRow("Name", session.GetName())
	workspaceTable.AddRow("Created", session.GetCreated())
	workspaceTable.AddRow("Last Accessed", session.GetLastAccessed())
	workspaceTable.AddRow("Commands", fmt.Sprintf("%d", session.GetCommandCount()))
	workspaceTable.AddRow("Resources", fmt.Sprintf("%d", session.GetResourceCount()))

	fmt.Println("Workspace:")
	workspaceTable.Render()
	fmt.Println()

	// Identity information table
	identity := r.identityManager.GetCurrent()
	identityTable := table.New(os.Stdout)
	identityTable.SetHeaders("Property", "Value")
	identityTable.SetHeaderStyle(table.StyleBold)
	identityTable.SetRowLines(false)
	identityTable.SetLineStyle(table.StyleCyan)
	identityTable.SetDividers(table.UnicodeRoundedDividers)
	identityTable.SetAlignment(table.AlignLeft)

	if identity != nil {
		identityTable.AddRow("Name", identity.Name)
		identityTable.AddRow("Type", identity.Type)
		identityTable.AddRow("Region", identity.Region)
		if identity.Profile != "" {
			identityTable.AddRow("Profile", identity.Profile)
		}
		if identity.ExpiresAt != nil {
			status := "Valid"
			if identity.IsExpired() {
				status = "EXPIRED"
			}
			identityTable.AddRow("Expires", identity.ExpiresAt.Format("2006-01-02 15:04:05 MST"))
			identityTable.AddRow("Status", status)
		} else {
			identityTable.AddRow("Status", "Valid (no expiration)")
		}

		fmt.Println("Identity:")
		identityTable.Render()
	} else {
		fmt.Println("Identity: None configured")
		fmt.Println("  Use 'identity add' to configure AWS credentials")
	}
	fmt.Println()

	// Module information table
	if r.currentModule != nil {
		moduleTable := table.New(os.Stdout)
		moduleTable.SetHeaders("Property", "Value")
		moduleTable.SetHeaderStyle(table.StyleBold)
		moduleTable.SetRowLines(false)
		moduleTable.SetLineStyle(table.StyleCyan)
		moduleTable.SetDividers(table.UnicodeRoundedDividers)
		moduleTable.SetAlignment(table.AlignLeft)

		moduleTable.AddRow("Name", r.currentModule.Name())
		moduleTable.AddRow("Description", r.currentModule.Description())

		// Show payload if selected
		if payload, exists := r.options["PAYLOAD"]; exists && payload != "" {
			moduleTable.AddRow("Payload", payload)
		} else {
			moduleTable.AddRow("Payload", "None selected")
		}

		fmt.Println("Module:")
		moduleTable.Render()
		fmt.Println()

		// Show configured options in a table
		options := r.currentModule.Options()
		if len(options) > 0 {
			optionsTable := table.New(os.Stdout)
			optionsTable.SetHeaders("Option", "Value", "Required")
			optionsTable.SetHeaderStyle(table.StyleBold)
			optionsTable.SetRowLines(false)
			optionsTable.SetLineStyle(table.StyleCyan)
			optionsTable.SetDividers(table.UnicodeRoundedDividers)
			optionsTable.SetAlignment(table.AlignLeft)

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
						required = "\033[31mYes\033[0m" // Red text for missing required
					} else {
						required = "Yes"
					}
				}

				optionsTable.AddRow(option.Name, value, required)
			}

			fmt.Println("Module Options:")
			optionsTable.Render()
			fmt.Println()
		}

		// Show payload-specific options if payload is selected
		if payload, exists := r.options["PAYLOAD"]; exists && payload != "" {
			payloadOptions := r.currentModule.PayloadOptions(payload)
			if len(payloadOptions) > 0 {
				payloadTable := table.New(os.Stdout)
				payloadTable.SetHeaders("Payload Option", "Value", "Required")
				payloadTable.SetHeaderStyle(table.StyleBold)
				payloadTable.SetRowLines(false)
				payloadTable.SetLineStyle(table.StyleCyan)
				payloadTable.SetDividers(table.UnicodeRoundedDividers)
				payloadTable.SetAlignment(table.AlignLeft)

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
							required = "\033[31mYes\033[0m" // Red text for missing required
						} else {
							required = "Yes"
						}
					}

					payloadTable.AddRow(option.Name, value, required)
				}

				fmt.Printf("Payload Options (%s):\n", payload)
				payloadTable.Render()
				fmt.Println()
			}
		}
	} else {
		fmt.Println("Module: None selected")
		fmt.Println("  Use 'use <module>' to select a module")
		fmt.Println()
	}

	// Show readiness status
	fmt.Printf("Status: ")
	if identity == nil {
		fmt.Println("❌ No identity configured")
	} else if identity.IsExpired() {
		fmt.Println("❌ Identity expired")
	} else if r.currentModule == nil {
		fmt.Println("⚠️  No module selected")
	} else {
		// Check if required options are set
		if err := r.validateOptionsForContext(); err != nil {
			fmt.Printf("⚠️  %s\n", err.Error())
		} else {
			fmt.Println("✅ Ready for exploitation")
		}
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
	// For profile-based identities, retrieve fresh credentials
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
		// For non-profile identities, use stored credentials
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
		// Check if it's an exit error
		if _, ok := err.(*exec.ExitError); ok {
			// AWS CLI returned non-zero exit code
			// The error output has already been printed to stderr
			// Return nil to keep REPL running (don't exit the whole program)
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
