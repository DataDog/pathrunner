package cli

import (
	"fmt"
	"pathrunner/pkg/version"
	"strings"

	"github.com/spf13/cobra"
)

// Identity command and subcommands
func (c *CLI) createIdentityCmd() *cobra.Command {
	identityCmd := &cobra.Command{
		Use:   "identity",
		Short: "Manage AWS identities",
		Long:  "Add, list, switch, and manage AWS credential identities",
	}

	// identity list
	identityCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all configured identities",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("identity list")
		},
	})

	// identity current
	identityCmd.AddCommand(&cobra.Command{
		Use:   "current",
		Short: "Show current identity details",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("identity current")
		},
	})

	// identity add
	addCmd := &cobra.Command{
		Use:   "add",
		Short: "Add AWS identity",
		Long:  "Add AWS identity from environment, profile, keys, file, clipboard, or exploit output",
		Run: func(cmd *cobra.Command, args []string) {
			// Build command based on flags
			var replArgs []string

			if profile, _ := cmd.Flags().GetString("profile"); profile != "" {
				replArgs = append(replArgs, "--profile", profile)
			} else if accessKey, _ := cmd.Flags().GetString("access"); accessKey != "" {
				secretKey, _ := cmd.Flags().GetString("secret")
				if secretKey == "" {
					fmt.Println("Error: --secret is required when using --access")
					return
				}
				replArgs = append(replArgs, "--access", accessKey, "--secret", secretKey)
				if token, _ := cmd.Flags().GetString("token"); token != "" {
					replArgs = append(replArgs, "--token", token)
				}
				if name, _ := cmd.Flags().GetString("name"); name != "" {
					replArgs = append(replArgs, "--name", name)
				}
			} else if fromOutput, _ := cmd.Flags().GetBool("from-output"); fromOutput {
				replArgs = append(replArgs, "--from-output")
			} else if fromFile, _ := cmd.Flags().GetString("from-file"); fromFile != "" {
				replArgs = append(replArgs, "--from-file", fromFile)
			} else if fromClipboard, _ := cmd.Flags().GetBool("from-clipboard"); fromClipboard {
				replArgs = append(replArgs, "--from-clipboard")
			}

			if autoSwitch, _ := cmd.Flags().GetBool("switch"); autoSwitch {
				replArgs = append(replArgs, "--switch")
			}

			if checkAdmin, _ := cmd.Flags().GetBool("check-admin"); checkAdmin {
				replArgs = append(replArgs, "--check-admin")
			}

			if len(replArgs) == 0 {
				c.executeREPLCommand("identity add")
			} else {
				c.executeREPLCommand("identity add " + strings.Join(replArgs, " "))
			}
		},
	}
	addCmd.Flags().String("profile", "", "AWS profile name")
	addCmd.Flags().String("access", "", "Access key ID (requires --secret)")
	addCmd.Flags().String("secret", "", "Secret access key")
	addCmd.Flags().String("token", "", "Session token (optional)")
	addCmd.Flags().String("name", "", "Custom name for the identity")
	addCmd.Flags().Bool("from-output", false, "Extract credentials from last exploit output")
	addCmd.Flags().String("from-file", "", "Read credentials from file")
	addCmd.Flags().Bool("from-clipboard", false, "Read credentials from clipboard or stdin")
	addCmd.Flags().Bool("switch", false, "Auto-switch to the new identity without prompting")
	addCmd.Flags().Bool("check-admin", false, "Auto-check admin privileges after adding")
	identityCmd.AddCommand(addCmd)

	// identity switch
	switchCmd := &cobra.Command{
		Use:   "switch <name>",
		Short: "Switch to different identity",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("identity switch " + args[0])
		},
	}
	identityCmd.AddCommand(switchCmd)

	// identity check
	checkCmd := &cobra.Command{
		Use:   "check [name]",
		Short: "Check if identity has admin privileges",
		Long:  "Uses IAM Policy Simulator to test whether an identity has admin-level access",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				c.executeREPLCommand("identity check " + args[0])
			} else {
				c.executeREPLCommand("identity check")
			}
		},
	}
	identityCmd.AddCommand(checkCmd)

	// identity clear/remove
	clearCmd := &cobra.Command{
		Use:     "clear [identity-name]",
		Aliases: []string{"remove"},
		Short:   "Remove identity or clear expired identities",
		Long:    "Remove a specific identity by name, or use --expired to remove all expired identities",
		Run: func(cmd *cobra.Command, args []string) {
			expired, _ := cmd.Flags().GetBool("expired")

			var err error
			if expired {
				err = c.executeREPLCommand("identity clear --expired")
			} else if len(args) > 0 {
				err = c.executeREPLCommand("identity clear " + args[0])
			} else {
				fmt.Println("Error: specify identity name or use --expired flag")
				return
			}

			if err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		},
	}
	clearCmd.Flags().Bool("expired", false, "Remove all expired identities")
	identityCmd.AddCommand(clearCmd)

	return identityCmd
}

// Workspace command and subcommands
func (c *CLI) createWorkspaceCmd() *cobra.Command {
	workspaceCmd := &cobra.Command{
		Use:   "workspace",
		Short: "Manage pathrunner workspaces",
		Long:  "Create, switch, save, delete, and manage pathrunner workspaces",
	}

	// workspace create
	createCmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create new workspace",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("workspace create " + args[0])
		},
	}
	workspaceCmd.AddCommand(createCmd)

	// workspace list
	workspaceCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all workspaces",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("workspace list")
		},
	})

	// workspace switch
	switchCmd := &cobra.Command{
		Use:   "switch <name>",
		Short: "Switch to different workspace",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("workspace switch " + args[0])
		},
	}
	workspaceCmd.AddCommand(switchCmd)

	// workspace save
	workspaceCmd.AddCommand(&cobra.Command{
		Use:   "save",
		Short: "Save current workspace state",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("workspace save")
		},
	})

	// workspace delete
	deleteCmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete workspace",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("workspace delete " + args[0])
		},
	}
	workspaceCmd.AddCommand(deleteCmd)

	// workspace cleanup
	cleanupCmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Clean up AWS resources in current workspace",
		Run: func(cmd *cobra.Command, args []string) {
			var replArgs []string
			replArgs = append(replArgs, "workspace", "cleanup")

			if all, _ := cmd.Flags().GetBool("all"); all {
				replArgs = append(replArgs, "--all")
			}
			if module, _ := cmd.Flags().GetString("module"); module != "" {
				replArgs = append(replArgs, "--module", module)
			}

			c.executeREPLCommand(strings.Join(replArgs, " "))
		},
	}
	cleanupCmd.Flags().Bool("all", false, "Clean up all resources without interactive prompt")
	cleanupCmd.Flags().String("module", "", "Only clean up resources created by a specific module ID")
	workspaceCmd.AddCommand(cleanupCmd)

	// workspace report
	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Generate cleanup report for handoff to client/admin",
		Run: func(cmd *cobra.Command, args []string) {
			var replArgs []string
			replArgs = append(replArgs, "workspace", "report")

			if module, _ := cmd.Flags().GetString("module"); module != "" {
				replArgs = append(replArgs, "--module", module)
			}

			c.executeREPLCommand(strings.Join(replArgs, " "))
		},
	}
	reportCmd.Flags().String("module", "", "Only report resources from a specific module ID")
	workspaceCmd.AddCommand(reportCmd)

	// workspace history
	workspaceCmd.AddCommand(&cobra.Command{
		Use:   "history",
		Short: "Show command history with timestamps",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("workspace history")
		},
	})

	return workspaceCmd
}

// Show command and subcommands
func (c *CLI) createShowCmd() *cobra.Command {
	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show module options or information",
	}

	// show options
	showCmd.AddCommand(&cobra.Command{
		Use:   "options",
		Short: "Show current module options",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("show options")
		},
	})

	// show modules
	showCmd.AddCommand(&cobra.Command{
		Use:   "modules",
		Short: "List all available modules",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("show modules")
		},
	})

	// show payloads
	showCmd.AddCommand(&cobra.Command{
		Use:   "payloads",
		Short: "List payloads for current module",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("show payloads")
		},
	})

	// show info
	showCmd.AddCommand(&cobra.Command{
		Use:   "info",
		Short: "Show detailed path metadata for current module",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("show info")
		},
	})

	// show payload options
	payloadCmd := &cobra.Command{
		Use:   "payload",
		Short: "Show payload information",
	}
	payloadCmd.AddCommand(&cobra.Command{
		Use:   "options",
		Short: "Show options for current payload",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("show payload options")
		},
	})
	showCmd.AddCommand(payloadCmd)

	return showCmd
}

// Modules command with subcommands
func (c *CLI) createModulesCmd() *cobra.Command {
	modulesCmd := &cobra.Command{
		Use:   "modules",
		Short: "List and search modules",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("modules list")
		},
	}

	modulesCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all available modules",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("modules list")
		},
	})

	modulesCmd.AddCommand(&cobra.Command{
		Use:   "search <query>",
		Short: "Search modules by keyword",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("search " + strings.Join(args, " "))
		},
	})

	modulesCmd.AddCommand(&cobra.Command{
		Use:   "status [module-id]",
		Short: "Show test status for modules",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				c.executeREPLCommand("modules status " + args[0])
			} else {
				c.executeREPLCommand("modules status")
			}
		},
	})

	modulesCmd.AddCommand(&cobra.Command{
		Use:   "mark-tested <module-id> [lab-name]",
		Short: "Mark a module as tested",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("modules mark-tested " + strings.Join(args, " "))
		},
	})

	modulesCmd.AddCommand(&cobra.Command{
		Use:   "mark-status <module-id> <status>",
		Short: "Set module test status (tested|untested|failing|needs-update)",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("modules mark-status " + args[0] + " " + args[1])
		},
	})

	return modulesCmd
}

// Payloads command with subcommands
func (c *CLI) createPayloadsCmd() *cobra.Command {
	payloadsCmd := &cobra.Command{
		Use:   "payloads",
		Short: "List available payloads",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("payloads list")
		},
	}

	payloadsCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all available payloads",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("payloads list")
		},
	})

	return payloadsCmd
}

// Search command
func (c *CLI) createSearchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "search <query>",
		Short: "Search modules by keyword",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("search " + strings.Join(args, " "))
		},
	}
}

// Use command
func (c *CLI) createUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use <module>",
		Short: "Select an exploitation module",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("use " + args[0])
		},
	}
}

// Set command
func (c *CLI) createSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <option> <value>",
		Short: "Set module or payload options",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("set " + args[0] + " " + args[1])
		},
	}
}

// Unset command
func (c *CLI) createUnsetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unset <option>",
		Short: "Unset module or payload options",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("unset " + args[0])
		},
	}
}

// Exploit command
func (c *CLI) createExploitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "exploit",
		Short: "Execute the current module",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("exploit")
		},
	}
}

// Context command
func (c *CLI) createContextCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "context",
		Short: "Show current context (workspace, identity, module, options)",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("context")
		},
	}
}

// Whoami command
func (c *CLI) createWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show current AWS identity information",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("whoami")
		},
	}
}
// Info command
func (c *CLI) createInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show detailed module and path information",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("info")
		},
	}
}

// Discover command
func (c *CLI) createDiscoverCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "discover [OPTION]",
		Short: "Auto-discover values for module options using AWS API calls",
		Long:  "Uses the current identity's permissions to enumerate valid values for discoverable module options",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				c.executeREPLCommand("discover " + strings.Join(args, " "))
			} else {
				c.executeREPLCommand("discover")
			}
		},
	}
}

// Identities command (alias for identity)
func (c *CLI) createIdentitiesCmd() *cobra.Command {
	cmd := c.createIdentityCmd()
	cmd.Use = "identities"
	cmd.Short = "Manage AWS identities (alias for identity)"
	return cmd
}

// Id command (alias for identity)
func (c *CLI) createIdCmd() *cobra.Command {
	cmd := c.createIdentityCmd()
	cmd.Use = "id"
	cmd.Short = "Manage AWS identities (alias for identity)"
	return cmd
}

// Ids command (alias for identity)
func (c *CLI) createIdsCmd() *cobra.Command {
	cmd := c.createIdentityCmd()
	cmd.Use = "ids"
	cmd.Short = "Manage AWS identities (alias for identity)"
	return cmd
}

// Workspaces command (alias for workspace)
func (c *CLI) createWorkspacesCmd() *cobra.Command {
	cmd := c.createWorkspaceCmd()
	cmd.Use = "workspaces"
	cmd.Short = "Manage pathrunner workspaces (alias for workspace)"
	return cmd
}

// AWS command (passthrough to AWS CLI)
func (c *CLI) createAWSCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "aws",
		Short:              "Execute AWS CLI commands with current identity credentials",
		Long:               "Passes through to the AWS CLI binary with current identity's credentials automatically injected",
		DisableFlagParsing: true, // Pass all args through to AWS CLI
		Run: func(cmd *cobra.Command, args []string) {
			// Build the command string
			cmdStr := "aws"
			if len(args) > 0 {
				cmdStr += " " + strings.Join(args, " ")
			}
			c.executeREPLCommand(cmdStr)
		},
	}
}

// PMapper command and subcommands
func (c *CLI) createPmapperCmd() *cobra.Command {
	pmapperCmd := &cobra.Command{
		Use:   "pmapper",
		Short: "Import and analyze PMapper privilege escalation graphs",
		Long:  "Import PMapper graph data, find escalation paths, and map them to pathrunner modules",
	}

	// pmapper import
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Import PMapper graph data",
		Run: func(cmd *cobra.Command, args []string) {
			var replArgs []string
			replArgs = append(replArgs, "pmapper", "import")

			if path, _ := cmd.Flags().GetString("path"); path != "" {
				replArgs = append(replArgs, "--path", path)
			}

			c.executeREPLCommand(strings.Join(replArgs, " "))
		},
	}
	importCmd.Flags().String("path", "", "PMapper data directory path")
	pmapperCmd.AddCommand(importCmd)

	// pmapper analyze
	analyzeCmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze escalation paths for current identity",
		Run: func(cmd *cobra.Command, args []string) {
			var replArgs []string
			replArgs = append(replArgs, "pmapper", "analyze")

			if all, _ := cmd.Flags().GetBool("all"); all {
				replArgs = append(replArgs, "--all")
			}

			c.executeREPLCommand(strings.Join(replArgs, " "))
		},
	}
	analyzeCmd.Flags().Bool("all", false, "Analyze all workspace identities")
	pmapperCmd.AddCommand(analyzeCmd)

	// pmapper status
	pmapperCmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show graph metadata and module coverage",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("pmapper status")
		},
	})

	return pmapperCmd
}

// Version command
func (c *CLI) createVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show pathrunner version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version.Info())
		},
	}
}

func (c *CLI) createAttackerCmd() *cobra.Command {
	attackerCmd := &cobra.Command{
		Use:   "attacker",
		Short: "Manage attacker account identity",
		Long:  "Configure an attacker-controlled AWS account for deploying resources used during exploitation",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("attacker")
		},
	}

	// attacker set
	setCmd := &cobra.Command{
		Use:   "set",
		Short: "Configure attacker account credentials",
	}

	setCmd.AddCommand(&cobra.Command{
		Use:   "profile [name]",
		Short: "Configure from AWS profile",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("attacker set profile " + args[0])
		},
	})

	keysCmd := &cobra.Command{
		Use:   "keys",
		Short: "Configure from access keys",
		Run: func(cmd *cobra.Command, args []string) {
			accessKey, _ := cmd.Flags().GetString("access")
			secretKey, _ := cmd.Flags().GetString("secret")
			if accessKey == "" || secretKey == "" {
				fmt.Println("Error: --access and --secret are required")
				return
			}
			replCmd := fmt.Sprintf("attacker set keys --access %s --secret %s", accessKey, secretKey)
			if token, _ := cmd.Flags().GetString("token"); token != "" {
				replCmd += " --token " + token
			}
			if region, _ := cmd.Flags().GetString("region"); region != "" {
				replCmd += " --region " + region
			}
			c.executeREPLCommand(replCmd)
		},
	}
	keysCmd.Flags().String("access", "", "AWS access key ID")
	keysCmd.Flags().String("secret", "", "AWS secret access key")
	keysCmd.Flags().String("token", "", "AWS session token (optional)")
	keysCmd.Flags().String("region", "", "AWS region (default: us-east-1)")
	setCmd.AddCommand(keysCmd)

	attackerCmd.AddCommand(setCmd)

	attackerCmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show current attacker identity",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("attacker show")
		},
	})

	attackerCmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Validate attacker credentials",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("attacker validate")
		},
	})

	attackerCmd.AddCommand(&cobra.Command{
		Use:   "clear",
		Short: "Remove attacker identity",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("attacker clear")
		},
	})

	// attacker listener
	listenerCmd := &cobra.Command{
		Use:   "listener",
		Short: "Manage the unified credential collector and shell listener",
	}

	listenerStartCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the unified listener (HTTPS creds + TLS shells)",
		Run: func(cmd *cobra.Command, args []string) {
			var replArgs []string
			replArgs = append(replArgs, "attacker", "listener", "start")

			if v, _ := cmd.Flags().GetInt("https-port"); v != 0 {
				replArgs = append(replArgs, "--https-port", fmt.Sprintf("%d", v))
			}
			if v, _ := cmd.Flags().GetInt("shell-port"); v != 0 {
				replArgs = append(replArgs, "--shell-port", fmt.Sprintf("%d", v))
			}
			if v, _ := cmd.Flags().GetString("host"); v != "" {
				replArgs = append(replArgs, "--host", v)
			}
			if v, _ := cmd.Flags().GetString("public-ip"); v != "" {
				replArgs = append(replArgs, "--public-ip", v)
			}
			c.executeREPLCommand(strings.Join(replArgs, " "))
		},
	}
	listenerStartCmd.Flags().Int("https-port", 0, "Credential collection port (default: 8443)")
	listenerStartCmd.Flags().Int("shell-port", 0, "Reverse shell port (default: 4444)")
	listenerStartCmd.Flags().String("host", "", "Bind address (default: 0.0.0.0)")
	listenerStartCmd.Flags().String("public-ip", "", "Override auto-detected public IP")
	listenerCmd.AddCommand(listenerStartCmd)

	listenerCmd.AddCommand(&cobra.Command{
		Use:   "stop",
		Short: "Stop the listener",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("attacker listener stop")
		},
	})

	listenerCmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show listener state and statistics",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("attacker listener status")
		},
	})

	listenerLogCmd := &cobra.Command{
		Use:   "log",
		Short: "Show recent listener events",
		Run: func(cmd *cobra.Command, args []string) {
			replArgs := []string{"attacker", "listener", "log"}
			if v, _ := cmd.Flags().GetInt("count"); v != 0 {
				replArgs = append(replArgs, "--count", fmt.Sprintf("%d", v))
			}
			c.executeREPLCommand(strings.Join(replArgs, " "))
		},
	}
	listenerLogCmd.Flags().Int("count", 50, "Number of recent events to show")
	listenerCmd.AddCommand(listenerLogCmd)

	attackerCmd.AddCommand(listenerCmd)

	// attacker infra
	infraCmd := &cobra.Command{
		Use:   "infra",
		Short: "Manage attacker infrastructure",
		Long:  "Deploy and manage attacker-side infrastructure (EC2 instances, S3 buckets)",
	}

	// attacker infra ec2
	infraEC2Cmd := &cobra.Command{
		Use:   "ec2",
		Short: "Deploy pathrunner to an EC2 instance",
	}

	infraEC2CreateCmd := &cobra.Command{
		Use:   "create",
		Short: "Create or update EC2 deployment",
		Run: func(cmd *cobra.Command, args []string) {
			var replArgs []string
			replArgs = append(replArgs, "attacker", "infra", "ec2", "create")

			if v, _ := cmd.Flags().GetString("region"); v != "" {
				replArgs = append(replArgs, "--region", v)
			}

			c.executeREPLCommand(strings.Join(replArgs, " "))
		},
	}
	infraEC2CreateCmd.Flags().String("region", "", "AWS region for the EC2 instance")
	infraEC2Cmd.AddCommand(infraEC2CreateCmd)

	infraEC2Cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show EC2 deployment status",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("attacker infra ec2 status")
		},
	})

	infraEC2Cmd.AddCommand(&cobra.Command{
		Use:   "destroy",
		Short: "Tear down EC2 deployment",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("attacker infra ec2 destroy")
		},
	})

	infraCmd.AddCommand(infraEC2Cmd)

	// attacker infra bucket
	infraBucketCmd := &cobra.Command{
		Use:   "bucket",
		Short: "Manage S3 bucket deployments",
	}
	infraBucketCreateCmd := &cobra.Command{
		Use:   "create",
		Short: "Create an S3 bucket for code hosting or exfiltration",
		Run: func(cmd *cobra.Command, args []string) {
			replArgs := []string{"attacker", "infra", "bucket", "create"}
			if bucketType, _ := cmd.Flags().GetString("type"); bucketType != "" {
				replArgs = append(replArgs, "--type", bucketType)
			}
			if region, _ := cmd.Flags().GetString("region"); region != "" {
				replArgs = append(replArgs, "--region", region)
			}
			c.executeREPLCommand(strings.Join(replArgs, " "))
		},
	}
	infraBucketCreateCmd.Flags().String("type", "", "Bucket type: code or exfil (default: exfil)")
	infraBucketCreateCmd.Flags().String("region", "", "AWS region for the bucket")
	infraBucketCmd.AddCommand(infraBucketCreateCmd)

	infraBucketCmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show deployed buckets",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("attacker infra bucket status")
		},
	})

	infraBucketDestroyCmd := &cobra.Command{
		Use:   "destroy",
		Short: "Destroy deployed bucket(s)",
		Run: func(cmd *cobra.Command, args []string) {
			replArgs := []string{"attacker", "infra", "bucket", "destroy"}
			if name, _ := cmd.Flags().GetString("name"); name != "" {
				replArgs = append(replArgs, "--name", name)
			}
			c.executeREPLCommand(strings.Join(replArgs, " "))
		},
	}
	infraBucketDestroyCmd.Flags().String("name", "", "Specific bucket name to destroy (destroys all if omitted)")
	infraBucketCmd.AddCommand(infraBucketDestroyCmd)

	infraCmd.AddCommand(infraBucketCmd)

	// attacker infra status (global)
	infraCmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show all deployed infrastructure",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("attacker infra status")
		},
	})

	// attacker infra destroy (global)
	infraCmd.AddCommand(&cobra.Command{
		Use:   "destroy",
		Short: "Tear down ALL deployed infrastructure",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("attacker infra destroy")
		},
	})

	attackerCmd.AddCommand(infraCmd)

	return attackerCmd
}

func (c *CLI) createSessionsCmd() *cobra.Command {
	sessionsCmd := &cobra.Command{
		Use:   "sessions",
		Short: "Manage reverse shell sessions",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("sessions")
		},
	}

	sessionsCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all shell sessions",
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand("sessions list")
		},
	})

	sessionsCmd.AddCommand(&cobra.Command{
		Use:   "interact [id]",
		Short: "Interact with a session",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand(fmt.Sprintf("sessions interact %s", args[0]))
		},
	})

	sessionsCmd.AddCommand(&cobra.Command{
		Use:   "kill [id]",
		Short: "Kill a session",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c.executeREPLCommand(fmt.Sprintf("sessions kill %s", args[0]))
		},
	})

	return sessionsCmd
}
