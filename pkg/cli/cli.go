// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package cli

import (
	"fmt"
	"os"
	"github.com/DataDog/pathrunner/pkg/attacker"
	"github.com/DataDog/pathrunner/pkg/core"
	"github.com/DataDog/pathrunner/pkg/core/repl"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/utils"

	"github.com/spf13/cobra"
)

// exitCode is set to 1 by executeREPLCommand when a command fails. main.go
// reads it via ExitCode() after Cobra's Execute returns to propagate the
// correct process exit code even though Cobra Run handlers can't return errors.
var exitCode int

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

	// When a new identity is added, update deployed bucket policies if the
	// identity comes from a previously-unseen victim account.
	identityManager.SetOnIdentityAdded(func(identity *modules.Identity) {
		attackerIdentity := identityManager.GetAttackerIdentity()
		if attackerIdentity == nil {
			return
		}
		accountID := utils.ExtractAccountIDFromARN(identity.CallerARN)
		if accountID == "" {
			return
		}
		updated, err := attacker.EnsureBucketAccountAccess(attackerIdentity.GetConfig(), accountID)
		if err != nil {
			fmt.Printf("[!] Failed to update bucket policies for account %s: %v\n", accountID, err)
			return
		}
		if updated > 0 {
			fmt.Printf("[*] Updated %d bucket policy(ies) to include account %s\n", updated, accountID)
		}

		ecrUpdated, ecrErr := attacker.EnsureECRAccountAccess(attackerIdentity.GetConfig(), accountID)
		if ecrErr != nil {
			fmt.Printf("[!] Failed to update ECR repo policies for account %s: %v\n", accountID, ecrErr)
		} else if ecrUpdated > 0 {
			fmt.Printf("[*] Updated %d ECR repo policy(ies) to include account %s\n", ecrUpdated, accountID)
		}
	})

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
			if err := c.repl.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "REPL error: %v\n", err)
			}
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
	rootCmd.AddCommand(addToGroup(c.createCloudfoxCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createResourcesCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createAttackerCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createSessionsCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createContextCmd(), "core"))
	rootCmd.AddCommand(addToGroup(c.createVersionCmd(), "core"))

	// Module commands
	rootCmd.AddCommand(addToGroup(c.createInfoCmd(), "module"))
	rootCmd.AddCommand(addToGroup(c.createShowCmd(), "module"))
	rootCmd.AddCommand(addToGroup(c.createSetCmd(), "module"))
	rootCmd.AddCommand(addToGroup(c.createUnsetCmd(), "module"))
	rootCmd.AddCommand(addToGroup(c.createOptionsCmd(), "module"))
	rootCmd.AddCommand(addToGroup(c.createPayloadsCmd(), "module"))
	rootCmd.AddCommand(addToGroup(c.createDiscoverCmd(), "module"))
	rootCmd.AddCommand(addToGroup(c.createExploitCmd(), "module"))

	// Alias commands (hidden to keep help clean, but still functional)
	aliases := []*cobra.Command{
		c.createIdentitiesCmd(),
		c.createIdCmd(),
		c.createIdsCmd(),
		c.createWorkspacesCmd(),
		c.createListenerCmd(),
		c.createInfraCmd(),
	}
	for _, alias := range aliases {
		alias.Hidden = true
		rootCmd.AddCommand(alias)
	}

	return rootCmd
}

// ExitCode returns the process exit code. Call after Cobra's Execute returns.
func ExitCode() int {
	return exitCode
}

// executeREPLCommand runs a REPL command, prints any error to stderr, and sets
// the process exit code to 1 on failure. Every CLI subcommand delegates to this
// method, so centralizing the error handling here covers all 90+ call sites.
func (c *CLI) executeREPLCommand(command string) error {
	err := c.repl.ExecuteCommand(command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		exitCode = 1
	}
	return err
}