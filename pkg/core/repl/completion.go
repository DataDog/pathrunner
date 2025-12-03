package repl

import (
	"pathrunner/pkg/modules"
	"strings"

	"github.com/chzyer/readline"
)

// getCompleter returns the auto-completion system
func (r *REPL) getCompleter() readline.AutoCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("help",
			readline.PcItem("identity"),
			readline.PcItem("show"),
			readline.PcItem("use"),
			readline.PcItem("set"),
			readline.PcItem("unset"),
			readline.PcItem("exploit"),
			readline.PcItem("whoami"),
			readline.PcItem("workspace"),
			readline.PcItem("context"),
		),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
		r.buildIdentityCompleter(),
		// Add alias completers for identity
		r.buildIdentitiesCompleter(),
		r.buildIdCompleter(),
		r.buildIdsCompleter(),
		r.buildUseCompleter(),
		readline.PcItem("show",
			readline.PcItem("modules"),
			readline.PcItem("payloads"),
			readline.PcItem("options"),
			readline.PcItem("help"),
		),
		// Top-level aliases for show commands
		readline.PcItem("modules"),
		readline.PcItem("payloads"),
		r.buildSetCompleter(),
		r.buildUnsetCompleter(),
		readline.PcItem("exploit",
			readline.PcItem("help"),
		),
		readline.PcItem("whoami",
			readline.PcItem("help"),
		),
		r.buildWorkspaceCompleter(),
		// Add alias completers
		r.buildWorkspacesCompleter(),
		readline.PcItem("context",
			readline.PcItem("help"),
		),
	)
}

// buildUseCompleter builds completion for the use command
func (r *REPL) buildUseCompleter() readline.PrefixCompleterInterface {
	moduleNames := modules.ListModules()
	items := make([]readline.PrefixCompleterInterface, len(moduleNames)+1)
	items[0] = readline.PcItem("help")
	for i, name := range moduleNames {
		items[i+1] = readline.PcItem(name)
	}
	return readline.PcItem("use", items...)
}

// buildIdentityCompleter builds completion for identity commands
func (r *REPL) buildIdentityCompleter() readline.PrefixCompleterInterface {
	// Get list of existing identities for switch/clear commands
	var identityItems []readline.PrefixCompleterInterface

	// Get identities from identity manager
	identities := r.identityManager.GetIdentities()
	for name := range identities {
		identityItems = append(identityItems, readline.PcItem(name))
	}

	return readline.PcItem("identity",
		readline.PcItem("add",
			readline.PcItem("--profile"),
			readline.PcItem("--keys"),
			readline.PcItem("--from-output",
				readline.PcItem("--name"),
			),
			readline.PcItem("--from-file",
				readline.PcItem("--name"),
			),
			readline.PcItem("--from-clipboard",
				readline.PcItem("--name"),
			),
		),
		readline.PcItem("list"),
		readline.PcItem("show"),
		readline.PcItem("switch", identityItems...),
		readline.PcItem("refresh"),
		readline.PcItem("clear",
			readline.PcItem("--expired"),
		),
		readline.PcItem("remove",
			readline.PcItem("--expired"),
		),
		readline.PcItem("help"),
	)
}

// buildSetCompleter builds completion for the set command
func (r *REPL) buildSetCompleter() readline.PrefixCompleterInterface {
	if r.currentModule == nil {
		return readline.PcItem("set", readline.PcItem("help"))
	}

	options := r.currentModule.Options()
	items := make([]readline.PrefixCompleterInterface, 0)
	items = append(items, readline.PcItem("help"))

	for _, option := range options {
		// Special handling for PAYLOAD option
		if strings.ToUpper(option.Name) == "PAYLOAD" {
			payloads := r.currentModule.ListPayloads()
			payloadItems := make([]readline.PrefixCompleterInterface, len(payloads))
			for i, payload := range payloads {
				payloadItems[i] = readline.PcItem(payload.Name)
			}
			items = append(items, readline.PcItem(option.Name, payloadItems...))
		} else {
			items = append(items, readline.PcItem(option.Name))
		}
	}

	return readline.PcItem("set", items...)
}

// buildUnsetCompleter builds completion for the unset command
func (r *REPL) buildUnsetCompleter() readline.PrefixCompleterInterface {
	if r.currentModule == nil {
		return readline.PcItem("unset", readline.PcItem("help"))
	}

	options := r.currentModule.Options()
	items := make([]readline.PrefixCompleterInterface, len(options)+1)
	items[0] = readline.PcItem("help")
	for i, option := range options {
		items[i+1] = readline.PcItem(option.Name)
	}

	return readline.PcItem("unset", items...)
}

// buildWorkspaceCompleter builds completion for workspace commands
func (r *REPL) buildWorkspaceCompleter() readline.PrefixCompleterInterface {
	// Get workspace names for commands that need them
	var workspaceItems []readline.PrefixCompleterInterface

	// Get workspaces from session manager
	sessions, err := r.sessionManager.ListSessions()
	if err == nil {
		for _, session := range sessions {
			workspaceItems = append(workspaceItems, readline.PcItem(session.GetName()))
		}
	}

	return readline.PcItem("workspace",
		readline.PcItem("create"),
		readline.PcItem("list"),
		readline.PcItem("switch", workspaceItems...),
		readline.PcItem("save"),
		readline.PcItem("delete", workspaceItems...),
		readline.PcItem("cleanup"),
		readline.PcItem("history"),
		readline.PcItem("help"),
	)
}

// updateCompletion rebuilds the completion system
func (r *REPL) updateCompletion() {
	if r.rl != nil {
		r.rl.Config.AutoComplete = r.getCompleter()
		r.UpdatePrompt() // Update prompt when completion changes
	}
}

// buildIdentitiesCompleter builds completion for identities command (alias for identity)
func (r *REPL) buildIdentitiesCompleter() readline.PrefixCompleterInterface {
	// Get list of existing identities for switch/clear commands
	var identityItems []readline.PrefixCompleterInterface

	// Get identities from identity manager
	identities := r.identityManager.GetIdentities()
	for name := range identities {
		identityItems = append(identityItems, readline.PcItem(name))
	}

	return readline.PcItem("identities",
		readline.PcItem("add",
			readline.PcItem("--profile"),
			readline.PcItem("--keys"),
			readline.PcItem("--from-output",
				readline.PcItem("--name"),
			),
			readline.PcItem("--from-file",
				readline.PcItem("--name"),
			),
			readline.PcItem("--from-clipboard",
				readline.PcItem("--name"),
			),
		),
		readline.PcItem("list"),
		readline.PcItem("show"),
		readline.PcItem("switch", identityItems...),
		readline.PcItem("refresh"),
		readline.PcItem("clear",
			readline.PcItem("--expired"),
		),
		readline.PcItem("remove",
			readline.PcItem("--expired"),
		),
		readline.PcItem("help"),
	)
}

// buildIdCompleter builds completion for id command (alias for identity)
func (r *REPL) buildIdCompleter() readline.PrefixCompleterInterface {
	var identityItems []readline.PrefixCompleterInterface

	identities := r.identityManager.GetIdentities()
	for name := range identities {
		identityItems = append(identityItems, readline.PcItem(name))
	}

	return readline.PcItem("id",
		readline.PcItem("add",
			readline.PcItem("--profile"),
			readline.PcItem("--keys"),
			readline.PcItem("--from-output",
				readline.PcItem("--name"),
			),
			readline.PcItem("--from-file",
				readline.PcItem("--name"),
			),
			readline.PcItem("--from-clipboard",
				readline.PcItem("--name"),
			),
		),
		readline.PcItem("list"),
		readline.PcItem("show"),
		readline.PcItem("switch", identityItems...),
		readline.PcItem("refresh"),
		readline.PcItem("clear",
			readline.PcItem("--expired"),
		),
		readline.PcItem("remove",
			readline.PcItem("--expired"),
		),
		readline.PcItem("help"),
	)
}

// buildIdsCompleter builds completion for ids command (alias for identity)
func (r *REPL) buildIdsCompleter() readline.PrefixCompleterInterface {
	var identityItems []readline.PrefixCompleterInterface

	identities := r.identityManager.GetIdentities()
	for name := range identities {
		identityItems = append(identityItems, readline.PcItem(name))
	}

	return readline.PcItem("ids",
		readline.PcItem("add",
			readline.PcItem("--profile"),
			readline.PcItem("--keys"),
			readline.PcItem("--from-output",
				readline.PcItem("--name"),
			),
			readline.PcItem("--from-file",
				readline.PcItem("--name"),
			),
			readline.PcItem("--from-clipboard",
				readline.PcItem("--name"),
			),
		),
		readline.PcItem("list"),
		readline.PcItem("show"),
		readline.PcItem("switch", identityItems...),
		readline.PcItem("refresh"),
		readline.PcItem("clear",
			readline.PcItem("--expired"),
		),
		readline.PcItem("remove",
			readline.PcItem("--expired"),
		),
		readline.PcItem("help"),
	)
}

// buildWorkspacesCompleter builds completion for workspaces command (alias for workspace)
func (r *REPL) buildWorkspacesCompleter() readline.PrefixCompleterInterface {
	var workspaceItems []readline.PrefixCompleterInterface

	sessions, err := r.sessionManager.ListSessions()
	if err == nil {
		for _, session := range sessions {
			workspaceItems = append(workspaceItems, readline.PcItem(session.GetName()))
		}
	}

	return readline.PcItem("workspaces",
		readline.PcItem("create"),
		readline.PcItem("list"),
		readline.PcItem("switch", workspaceItems...),
		readline.PcItem("save"),
		readline.PcItem("delete", workspaceItems...),
		readline.PcItem("cleanup"),
		readline.PcItem("history"),
		readline.PcItem("help"),
	)
}
