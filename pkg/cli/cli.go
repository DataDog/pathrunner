package cli

import (
	"pathrunner/pkg/core"
	"pathrunner/pkg/core/repl"

	"github.com/spf13/cobra"
)

// CLI wraps the REPL functionality for command-line usage
type CLI struct {
	repl            *repl.REPL
	identityManager *core.IdentityManager
	sessionManager  *core.SessionManager
}

// NewCLI creates a new CLI instance
func NewCLI() *CLI {
	sessionManager := core.NewSessionManager()

	cli := &CLI{
		sessionManager: sessionManager,
	}

	// Create identity manager with callbacks
	identityManager := core.NewIdentityManager(
		func() string { return "" }, // getLastResult placeholder
		func() {},                    // updateCompletion placeholder
	)
	cli.identityManager = identityManager

	// Create adapters
	sessionAdapter := core.NewSessionAdapter(sessionManager)
	identityAdapter := core.NewIdentityManagerAdapter(identityManager)

	// Create modular REPL with adapters
	cli.repl = repl.NewREPL(identityAdapter, sessionAdapter)

	return cli
}

// CreateRootCommand creates the root cobra command with all subcommands
func (c *CLI) CreateRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "pathrunner",
		Short: "AWS Post-Exploitation Framework",
		Long:  "Pathrunner is a modular AWS post-exploitation framework for penetration testing",
		Run: func(cmd *cobra.Command, args []string) {
			c.repl.Start()
		},
	}

	// Define command groups matching the REPL help layout
	rootCmd.AddGroup(
		&cobra.Group{ID: "core", Title: "Core Commands:"},
		&cobra.Group{ID: "module", Title: "Module Commands:"},
	)

	// Core commands
	addToGroup := func(cmd *cobra.Command, groupID string) *cobra.Command {
		cmd.GroupID = groupID
		return cmd
	}

	rootCmd.AddCommand(addToGroup(c.createModulesCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createSearchCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createUseCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createIdentityCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createAWSCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createWhoamiCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createWorkspaceCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createPmapperCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createAttackerCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createSessionsCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createContextCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createVersionCmd(), "core"))

	// Module commands
	rootCmd.AddCommand(addToGroup(c.createInfoCmd(), "module"))
	rootCmd.AddCommand(addToGroup(c.createShowCmd(), "module"))
	rootCmd.AddCommand(addToGroup(c.createSetCmd(), "module"))
	rootCmd.AddCommand(addToGroup(c.createUnsetCmd(), "module"))
	rootCmd.AddCommand(addToGroup(c.createPayloadsCmd(), "module"))
	rootCmd.AddCommand(addToGroup(c.createDiscoverCmd(), "module"))
	rootCmd.AddCommand(addToGroup(c.createExploitCmd(), "module"))

	// Alias commands (hidden to keep help clean, but still functional)
	aliases := []*cobra.Command{
		c.createIdentitiesCmd(),
		c.createIdCmd(),
		c.createIdsCmd(),
		c.createWorkspacesCmd(),
	}
	for _, alias := range aliases {
		alias.Hidden = true
		rootCmd.AddCommand(alias)
	}

	return rootCmd
}

// Execute a REPL command and return the result
func (c *CLI) executeREPLCommand(command string) error {
	// Use the REPL's handleCommand to ensure proper state management and persistence
	return c.repl.ExecuteCommand(command)
}