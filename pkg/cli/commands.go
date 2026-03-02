package cli

import (
	"fmt"
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
			} else if keys, _ := cmd.Flags().GetString("keys"); keys != "" {
				secretKey, _ := cmd.Flags().GetString("secret-key")
				if secretKey == "" {
					fmt.Println("Error: --secret-key is required when using --keys")
					return
				}
				replArgs = append(replArgs, "--keys", keys, secretKey)
				if sessionToken, _ := cmd.Flags().GetString("session-token"); sessionToken != "" {
					replArgs = append(replArgs, sessionToken)
				}
			} else if fromOutput, _ := cmd.Flags().GetBool("from-output"); fromOutput {
				replArgs = append(replArgs, "--from-output")
			} else if fromFile, _ := cmd.Flags().GetString("from-file"); fromFile != "" {
				replArgs = append(replArgs, "--from-file", fromFile)
			} else if fromClipboard, _ := cmd.Flags().GetBool("from-clipboard"); fromClipboard {
				replArgs = append(replArgs, "--from-clipboard")
			}

			if len(replArgs) == 0 {
				c.executeREPLCommand("identity add")
			} else {
				c.executeREPLCommand("identity add " + strings.Join(replArgs, " "))
			}
		},
	}
	addCmd.Flags().String("profile", "", "AWS profile name")
	addCmd.Flags().String("keys", "", "Access key ID (requires --secret-key)")
	addCmd.Flags().String("secret-key", "", "Secret access key")
	addCmd.Flags().String("session-token", "", "Session token (optional)")
	addCmd.Flags().Bool("from-output", false, "Extract credentials from last exploit output")
	addCmd.Flags().String("from-file", "", "Read credentials from file")
	addCmd.Flags().Bool("from-clipboard", false, "Read credentials from clipboard or stdin")
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
