package cli

import (
	"fmt"
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
			// If no subcommand, start REPL
			fmt.Println("Pathrunner AWS Post-Exploitation Framework")
			fmt.Println("=========================================")
			fmt.Println("Type 'help' for available commands")
			fmt.Println()
			c.repl.Start()
		},
	}

	// Add all subcommands
	rootCmd.AddCommand(c.createIdentityCmd())
	rootCmd.AddCommand(c.createIdentitiesCmd())
	rootCmd.AddCommand(c.createIdCmd())
	rootCmd.AddCommand(c.createIdsCmd())
	rootCmd.AddCommand(c.createWorkspaceCmd())
	rootCmd.AddCommand(c.createWorkspacesCmd())
	rootCmd.AddCommand(c.createShowCmd())
	rootCmd.AddCommand(c.createModulesCmd())
	rootCmd.AddCommand(c.createPayloadsCmd())
	rootCmd.AddCommand(c.createUseCmd())
	rootCmd.AddCommand(c.createSetCmd())
	rootCmd.AddCommand(c.createUnsetCmd())
	rootCmd.AddCommand(c.createExploitCmd())
	rootCmd.AddCommand(c.createContextCmd())
	rootCmd.AddCommand(c.createWhoamiCmd())
	rootCmd.AddCommand(c.createAWSCmd())

	return rootCmd
}

// Execute a REPL command and return the result
func (c *CLI) executeREPLCommand(command string) error {
	// Use the REPL's handleCommand to ensure proper state management and persistence
	return c.repl.ExecuteCommand(command)
}