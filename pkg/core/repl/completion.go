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
			readline.PcItem("attacker"),
			readline.PcItem("show"),
			readline.PcItem("use"),
			readline.PcItem("set"),
			readline.PcItem("unset"),
			readline.PcItem("exploit"),
			readline.PcItem("whoami"),
			readline.PcItem("workspace"),
			readline.PcItem("pmapper"),
			readline.PcItem("context"),
			readline.PcItem("search"),
			readline.PcItem("modules"),
			readline.PcItem("payloads"),
			readline.PcItem("discover"),
			readline.PcItem("version"),
			readline.PcItem("info"),
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
			readline.PcItem("info"),
			readline.PcItem("help"),
		),
		r.buildModulesCompleter(),
		r.buildPayloadsCompleter(),
		r.buildSearchCompleter(),
		r.buildSetCompleter(),
		r.buildUnsetCompleter(),
		readline.PcItem("exploit",
			readline.PcItem("help"),
		),
		readline.PcItem("whoami",
			readline.PcItem("help"),
		),
		r.buildAttackerCompleter(),
		r.buildWorkspaceCompleter(),
		// Add alias completers
		r.buildWorkspacesCompleter(),
		readline.PcItem("context",
			readline.PcItem("help"),
		),
		r.buildDiscoverCompleter(),
		readline.PcItem("info",
			readline.PcItem("help"),
		),
		r.buildPmapperCompleter(),
		readline.PcItem("version"),
	)
}

// buildUseCompleter builds completion for the use command
// Shows modules as "id/short-name" (e.g. "lambda-001/lambda-passrole")
func (r *REPL) buildUseCompleter() readline.PrefixCompleterInterface {
	infos := modules.ListPathInfos()

	items := make([]readline.PrefixCompleterInterface, 0, len(infos)+1)
	items = append(items, readline.PcItem("help"))

	for _, info := range infos {
		label := info.ID
		if len(info.Aliases) > 0 {
			label = info.ID + "/" + info.Aliases[0]
		}
		items = append(items, readline.PcItem(label))
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
			readline.PcItem("--access",
				readline.PcItem("--secret",
					readline.PcItem("--token"),
					readline.PcItem("--name"),
					readline.PcItem("--switch"),
					readline.PcItem("--check-admin"),
				),
			),
			readline.PcItem("--from-output",
				readline.PcItem("--name"),
				readline.PcItem("--switch"),
				readline.PcItem("--check-admin"),
			),
			readline.PcItem("--from-file",
				readline.PcItem("--name"),
				readline.PcItem("--switch"),
				readline.PcItem("--check-admin"),
			),
			readline.PcItem("--from-clipboard",
				readline.PcItem("--name"),
				readline.PcItem("--switch"),
				readline.PcItem("--check-admin"),
			),
			readline.PcItem("--switch"),
			readline.PcItem("--check-admin"),
		),
		readline.PcItem("list"),
		readline.PcItem("show"),
		readline.PcItem("switch", identityItems...),
		readline.PcItem("check", identityItems...),
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

	// Add payload-specific options when a payload is selected
	if selectedPayload, ok := r.options["PAYLOAD"]; ok && selectedPayload != "" {
		payloadOpts := r.currentModule.PayloadOptions(selectedPayload)
		for _, opt := range payloadOpts {
			items = append(items, readline.PcItem(opt.Name))
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
	items := make([]readline.PrefixCompleterInterface, 0, len(options)+1)
	items = append(items, readline.PcItem("help"))
	for _, option := range options {
		items = append(items, readline.PcItem(option.Name))
	}

	// Add payload-specific options when a payload is selected
	if selectedPayload, ok := r.options["PAYLOAD"]; ok && selectedPayload != "" {
		payloadOpts := r.currentModule.PayloadOptions(selectedPayload)
		for _, opt := range payloadOpts {
			items = append(items, readline.PcItem(opt.Name))
		}
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
		readline.PcItem("cleanup",
			readline.PcItem("--all"),
			readline.PcItem("--module"),
		),
		readline.PcItem("report",
			readline.PcItem("--module"),
		),
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
			readline.PcItem("--access",
				readline.PcItem("--secret",
					readline.PcItem("--token"),
					readline.PcItem("--name"),
					readline.PcItem("--switch"),
					readline.PcItem("--check-admin"),
				),
			),
			readline.PcItem("--from-output",
				readline.PcItem("--name"),
				readline.PcItem("--switch"),
				readline.PcItem("--check-admin"),
			),
			readline.PcItem("--from-file",
				readline.PcItem("--name"),
				readline.PcItem("--switch"),
				readline.PcItem("--check-admin"),
			),
			readline.PcItem("--from-clipboard",
				readline.PcItem("--name"),
				readline.PcItem("--switch"),
				readline.PcItem("--check-admin"),
			),
			readline.PcItem("--switch"),
			readline.PcItem("--check-admin"),
		),
		readline.PcItem("list"),
		readline.PcItem("show"),
		readline.PcItem("switch", identityItems...),
		readline.PcItem("check", identityItems...),
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
			readline.PcItem("--access",
				readline.PcItem("--secret",
					readline.PcItem("--token"),
					readline.PcItem("--name"),
					readline.PcItem("--switch"),
					readline.PcItem("--check-admin"),
				),
			),
			readline.PcItem("--from-output",
				readline.PcItem("--name"),
				readline.PcItem("--switch"),
				readline.PcItem("--check-admin"),
			),
			readline.PcItem("--from-file",
				readline.PcItem("--name"),
				readline.PcItem("--switch"),
				readline.PcItem("--check-admin"),
			),
			readline.PcItem("--from-clipboard",
				readline.PcItem("--name"),
				readline.PcItem("--switch"),
				readline.PcItem("--check-admin"),
			),
			readline.PcItem("--switch"),
			readline.PcItem("--check-admin"),
		),
		readline.PcItem("list"),
		readline.PcItem("show"),
		readline.PcItem("switch", identityItems...),
		readline.PcItem("check", identityItems...),
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
			readline.PcItem("--access",
				readline.PcItem("--secret",
					readline.PcItem("--token"),
					readline.PcItem("--name"),
					readline.PcItem("--switch"),
					readline.PcItem("--check-admin"),
				),
			),
			readline.PcItem("--from-output",
				readline.PcItem("--name"),
				readline.PcItem("--switch"),
				readline.PcItem("--check-admin"),
			),
			readline.PcItem("--from-file",
				readline.PcItem("--name"),
				readline.PcItem("--switch"),
				readline.PcItem("--check-admin"),
			),
			readline.PcItem("--from-clipboard",
				readline.PcItem("--name"),
				readline.PcItem("--switch"),
				readline.PcItem("--check-admin"),
			),
			readline.PcItem("--switch"),
			readline.PcItem("--check-admin"),
		),
		readline.PcItem("list"),
		readline.PcItem("show"),
		readline.PcItem("switch", identityItems...),
		readline.PcItem("check", identityItems...),
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

// buildAttackerCompleter builds completion for the attacker command
func (r *REPL) buildAttackerCompleter() readline.PrefixCompleterInterface {
	return readline.PcItem("attacker",
		readline.PcItem("set",
			readline.PcItem("profile"),
			readline.PcItem("keys",
				readline.PcItem("--access"),
				readline.PcItem("--secret"),
				readline.PcItem("--token"),
				readline.PcItem("--region"),
			),
			readline.PcItem("help"),
		),
		readline.PcItem("show"),
		readline.PcItem("validate"),
		readline.PcItem("clear"),
		readline.PcItem("help"),
	)
}

// buildModulesCompleter builds completion for the top-level modules command
func (r *REPL) buildModulesCompleter() readline.PrefixCompleterInterface {
	return readline.PcItem("modules",
		readline.PcItem("list"),
		readline.PcItem("search"),
		readline.PcItem("help"),
	)
}

// buildPayloadsCompleter builds completion for the top-level payloads command
func (r *REPL) buildPayloadsCompleter() readline.PrefixCompleterInterface {
	return readline.PcItem("payloads",
		readline.PcItem("list"),
		readline.PcItem("help"),
	)
}

// buildSearchCompleter builds completion for the search command
func (r *REPL) buildSearchCompleter() readline.PrefixCompleterInterface {
	return readline.PcItem("search",
		readline.PcItem("help"),
	)
}

// buildDiscoverCompleter builds completion for the discover command
func (r *REPL) buildDiscoverCompleter() readline.PrefixCompleterInterface {
	items := []readline.PrefixCompleterInterface{readline.PcItem("help")}

	// If module implements Discoverable, include option names
	if r.currentModule != nil {
		if discoverable, ok := r.currentModule.(modules.Discoverable); ok {
			for _, opt := range discoverable.DiscoverableOptions() {
				items = append(items, readline.PcItem(opt))
			}
		}
	}

	return readline.PcItem("discover", items...)
}

// buildPmapperCompleter builds completion for the pmapper command
func (r *REPL) buildPmapperCompleter() readline.PrefixCompleterInterface {
	return readline.PcItem("pmapper",
		readline.PcItem("import",
			readline.PcItem("--path"),
			readline.PcItem("help"),
		),
		readline.PcItem("analyze",
			readline.PcItem("--all"),
			readline.PcItem("help"),
		),
		readline.PcItem("status",
			readline.PcItem("help"),
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
		readline.PcItem("cleanup",
			readline.PcItem("--all"),
			readline.PcItem("--module"),
		),
		readline.PcItem("report",
			readline.PcItem("--module"),
		),
		readline.PcItem("history"),
		readline.PcItem("help"),
	)
}
