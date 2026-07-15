package repl

import (
	"pathrunner/pkg/modules"
	"strings"

	"github.com/chzyer/readline"
)

// aliasCompleter creates a completer for an alias by reusing the children of an existing completer.
// This avoids duplicating the entire subtree for each alias (e.g., identities, id, ids all share identity's subtree).
func aliasCompleter(aliasName string, original readline.PrefixCompleterInterface) readline.PrefixCompleterInterface {
	return readline.PcItem(aliasName, original.GetChildren()...)
}

// getCompleter returns the auto-completion system
func (r *REPL) getCompleter() readline.AutoCompleter {
	identityTree := r.buildIdentityCompleter()
	workspaceTree := r.buildWorkspaceCompleter()
	sessionsTree := r.buildSessionsCompleter()
	attackerTree := r.buildAttackerCompleter()

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
			readline.PcItem("sessions"),
			readline.PcItem("listener"),
			readline.PcItem("infra"),
			readline.PcItem("run"),
		),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
		identityTree,
		aliasCompleter("identities", identityTree),
		aliasCompleter("id", identityTree),
		aliasCompleter("ids", identityTree),
		r.buildUseCompleter(),
		readline.PcItem("show",
			readline.PcItem("modules",
				readline.PcItem("--wide"),
			),
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
		readline.PcItem("run",
			readline.PcItem("help"),
		),
		readline.PcItem("whoami",
			readline.PcItem("help"),
		),
		attackerTree,
		sessionsTree,
		aliasCompleter("session", sessionsTree),
		workspaceTree,
		aliasCompleter("workspaces", workspaceTree),
		// Top-level aliases for deeply nested attacker subcommands
		r.buildListenerCompleter(),
		r.buildInfraCompleter(),
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
	var identityItems []readline.PrefixCompleterInterface

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
	items := []readline.PrefixCompleterInterface{
		readline.PcItem("help"),
		readline.PcItem("module"),
		readline.PcItem("identity"),
	}

	if r.currentModule != nil {
		options := r.currentModule.Options()
		for _, option := range options {
			items = append(items, readline.PcItem(option.Name))
		}

		if selectedPayload, ok := r.options["PAYLOAD"]; ok && selectedPayload != "" {
			payloadOpts := r.currentModule.PayloadOptions(selectedPayload)
			for _, opt := range payloadOpts {
				items = append(items, readline.PcItem(opt.Name))
			}
		}
	}

	return readline.PcItem("unset", items...)
}

// buildWorkspaceCompleter builds completion for workspace commands
func (r *REPL) buildWorkspaceCompleter() readline.PrefixCompleterInterface {
	var workspaceItems []readline.PrefixCompleterInterface

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
		r.UpdatePrompt()
	}
}

// buildAttackerCompleter builds completion for the attacker command
func (r *REPL) buildAttackerCompleter() readline.PrefixCompleterInterface {
	return readline.PcItem("attacker",
		r.buildAttackerIdentitySubtree(),
		// Legacy aliases
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
		r.buildListenerSubtree(),
		r.buildInfraSubtree(),
		readline.PcItem("help"),
	)
}

// buildAttackerIdentitySubtree returns the identity subtree for the attacker completer
func (r *REPL) buildAttackerIdentitySubtree() readline.PrefixCompleterInterface {
	return readline.PcItem("identity",
		readline.PcItem("show"),
		readline.PcItem("add",
			readline.PcItem("profile"),
			readline.PcItem("keys",
				readline.PcItem("--access"),
				readline.PcItem("--secret"),
				readline.PcItem("--token"),
				readline.PcItem("--region"),
			),
			readline.PcItem("help"),
		),
		readline.PcItem("remove"),
		readline.PcItem("validate"),
		readline.PcItem("help"),
	)
}

// buildListenerSubtree returns the listener subtree for use inside the attacker completer
func (r *REPL) buildListenerSubtree() readline.PrefixCompleterInterface {
	return readline.PcItem("listener",
		readline.PcItem("start",
			readline.PcItem("--https-port"),
			readline.PcItem("--shell-port"),
			readline.PcItem("--host"),
			readline.PcItem("--public-ip"),
		),
		readline.PcItem("stop"),
		readline.PcItem("status"),
		readline.PcItem("log",
			readline.PcItem("--count"),
		),
		readline.PcItem("help"),
	)
}

// buildInfraSubtree returns the infra subtree for use inside the attacker completer
func (r *REPL) buildInfraSubtree() readline.PrefixCompleterInterface {
	return readline.PcItem("infra",
		readline.PcItem("ec2",
			readline.PcItem("create",
				readline.PcItem("--region"),
			),
			readline.PcItem("update"),
			readline.PcItem("status"),
			readline.PcItem("destroy"),
			readline.PcItem("help"),
		),
		readline.PcItem("bucket",
			readline.PcItem("create",
				readline.PcItem("--type"),
				readline.PcItem("--region"),
			),
			readline.PcItem("status"),
			readline.PcItem("destroy",
				readline.PcItem("--name"),
			),
			readline.PcItem("help"),
		),
		readline.PcItem("ecr",
			readline.PcItem("create",
				readline.PcItem("--region"),
			),
			readline.PcItem("status"),
			readline.PcItem("destroy"),
			readline.PcItem("help"),
		),
		readline.PcItem("status"),
		readline.PcItem("destroy"),
		readline.PcItem("help"),
	)
}

// buildListenerCompleter builds the top-level "listener" alias completer
func (r *REPL) buildListenerCompleter() readline.PrefixCompleterInterface {
	return r.buildListenerSubtree()
}

// buildInfraCompleter builds the top-level "infra" alias completer
func (r *REPL) buildInfraCompleter() readline.PrefixCompleterInterface {
	return r.buildInfraSubtree()
}

// buildModulesCompleter builds completion for the top-level modules command
func (r *REPL) buildModulesCompleter() readline.PrefixCompleterInterface {
	return readline.PcItem("modules",
		readline.PcItem("list",
			readline.PcItem("--wide"),
		),
		readline.PcItem("search"),
		readline.PcItem("status"),
		readline.PcItem("mark-tested"),
		readline.PcItem("mark-results"),
		readline.PcItem("mark-status"),
		readline.PcItem("help"),
	)
}

// buildPayloadsCompleter builds completion for the top-level payloads command
func (r *REPL) buildPayloadsCompleter() readline.PrefixCompleterInterface {
	return readline.PcItem("payloads",
		readline.PcItem("list",
			readline.PcItem("--all"),
		),
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

// buildSessionsCompleter builds completion for the sessions command
func (r *REPL) buildSessionsCompleter() readline.PrefixCompleterInterface {
	return readline.PcItem("sessions",
		readline.PcItem("list"),
		readline.PcItem("interact"),
		readline.PcItem("kill"),
		readline.PcItem("-i"),
		readline.PcItem("-k"),
		readline.PcItem("help"),
	)
}
