package repl

import (
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/pmapper"
	"pathrunner/pkg/ui"
	"sort"
	"strings"
)

// cmdPmapper handles pmapper commands
func (r *REPL) cmdPmapper(repl *REPL, args []string) error {
	if len(args) == 0 {
		return r.showPmapperHelp()
	}

	switch args[0] {
	case "import":
		return r.pmapperImport(args[1:])
	case "analyze":
		return r.pmapperAnalyze(args[1:])
	case "status":
		return r.pmapperStatus(args[1:])
	case "help":
		return r.showPmapperHelp()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown pmapper subcommand: %s. Use 'pmapper help' for available commands", args[0]))
	}
}

// pmapperImport imports PMapper graph data
func (r *REPL) pmapperImport(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showPmapperImportHelp()
	}

	// Parse flags
	dirPath := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--path":
			if i+1 < len(args) {
				i++
				dirPath = args[i]
			} else {
				return NewInvalidArgumentsError("--path requires a directory path")
			}
		default:
			return NewInvalidArgumentsError(fmt.Sprintf("unknown flag: %s", args[i]))
		}
	}

	// Auto-detect: collect account IDs from all workspace identities
	seen := make(map[string]bool)
	var accountIDs []string
	for _, identity := range r.identityManager.GetIdentities() {
		if identity.CallerARN == "" {
			continue
		}
		accountID := pmapper.ExtractAccountIDFromARN(identity.CallerARN)
		if accountID != "" && !seen[accountID] {
			seen[accountID] = true
			accountIDs = append(accountIDs, accountID)
		}
	}

	if dirPath == "" {
		dirPath = pmapper.DefaultPMapperDir()
		if dirPath == "" {
			return NewExecutionError("could not find PMapper data directory. Use --path to specify", nil)
		}
	}

	fmt.Printf("Importing PMapper data from %s...\n", dirPath)

	imported, err := r.pmapperManager.Import(dirPath, accountIDs)
	if err != nil {
		return NewExecutionError("import failed", err)
	}

	for _, accountID := range imported {
		g, err := r.pmapperManager.GetGraph(accountID)
		if err != nil {
			continue
		}
		status := g.GetStatus()
		fmt.Printf("Imported account %s: %d nodes (%d admin), %d edges\n",
			accountID, status.NodeCount, status.AdminCount, status.EdgeCount)
	}

	fmt.Println()
	fmt.Println("Run 'pmapper analyze' to view escalation paths for the current identity.")

	return nil
}

// pmapperAnalyze analyzes escalation paths for current or all identities
func (r *REPL) pmapperAnalyze(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showPmapperAnalyzeHelp()
	}

	// Parse flags
	analyzeAll := false
	for _, arg := range args {
		switch arg {
		case "--all":
			analyzeAll = true
		default:
			return NewInvalidArgumentsError(fmt.Sprintf("unknown flag: %s", arg))
		}
	}

	if analyzeAll {
		return r.pmapperAnalyzeAll()
	}

	// Analyze current identity
	identity := r.identityManager.GetCurrent()
	if identity == nil {
		return NewIdentityRequiredError()
	}

	if identity.CallerARN == "" {
		return NewExecutionError("current identity has no ARN. Run 'whoami' first to resolve it", nil)
	}

	accountID := pmapper.ExtractAccountIDFromARN(identity.CallerARN)
	if accountID == "" {
		return NewExecutionError("could not extract account ID from identity ARN", nil)
	}

	// Try auto-load from disk
	r.pmapperManager.TryAutoLoad(accountID)

	g, err := r.pmapperManager.GetGraph(accountID)
	if err != nil {
		return NewExecutionError("no PMapper graph for account "+accountID+". Run 'pmapper import' first", nil)
	}

	normalizedARN := pmapper.NormalizeARN(identity.CallerARN)
	if !g.HasNode(normalizedARN) {
		fmt.Printf("Identity ARN %s not found in PMapper graph.\n", normalizedARN)
		fmt.Println("The graph may have been generated with a different set of principals.")
		return nil
	}

	// Check if source is already admin (self-escalation capable)
	var paths []pmapper.PrivescPath
	if g.IsAdmin(normalizedARN) {
		paths = g.FindPathsToAdmin(normalizedARN)
		if len(paths) == 0 {
			fmt.Printf("\n  %s is marked admin but no self-escalation actions found.\n",
				ui.BoldCyan.Render(pmapper.ShortARN(normalizedARN)))
			fmt.Println("  Import policies.json alongside nodes/edges for self-escalation analysis.")
			fmt.Println()
			return nil
		}
	} else {
		paths = g.FindAllReachable(normalizedARN)
	}
	if len(paths) == 0 {
		fmt.Print("\n  No reachable targets found from this identity.\n\n")
		return nil
	}

	rows := r.buildPathViewRows(paths, g, "")

	if !ui.IsTTY() {
		r.printAnalysis(identity.Name, normalizedARN, g)
		return nil
	}

	title := fmt.Sprintf("Escalation Paths — %s (%s)", identity.Name, pmapper.ShortARN(normalizedARN))
	return ui.RunPathView(title, rows, false)
}

// pmapperAnalyzeAll analyzes paths for all workspace identities
func (r *REPL) pmapperAnalyzeAll() error {
	identities := r.identityManager.GetIdentities()
	if len(identities) == 0 {
		return NewIdentityRequiredError()
	}

	// For non-TTY, use the original plain-text output
	if !ui.IsTTY() {
		for name, identity := range identities {
			if identity.CallerARN == "" {
				fmt.Printf("Skipping '%s': no ARN resolved (run 'whoami' after switching)\n\n", name)
				continue
			}
			accountID := pmapper.ExtractAccountIDFromARN(identity.CallerARN)
			if accountID == "" {
				continue
			}
			r.pmapperManager.TryAutoLoad(accountID)
			g, err := r.pmapperManager.GetGraph(accountID)
			if err != nil {
				fmt.Printf("Skipping '%s': no PMapper graph for account %s\n\n", name, accountID)
				continue
			}
			normalizedARN := pmapper.NormalizeARN(identity.CallerARN)
			if !g.HasNode(normalizedARN) {
				fmt.Printf("Skipping '%s': ARN %s not in graph\n\n", name, normalizedARN)
				continue
			}
			r.printAnalysis(name, normalizedARN, g)
		}
		return nil
	}

	// Build combined rows for all identities
	var allRows []ui.PathViewRow
	for name, identity := range identities {
		if identity.CallerARN == "" {
			continue
		}
		accountID := pmapper.ExtractAccountIDFromARN(identity.CallerARN)
		if accountID == "" {
			continue
		}
		r.pmapperManager.TryAutoLoad(accountID)
		g, err := r.pmapperManager.GetGraph(accountID)
		if err != nil {
			continue
		}
		normalizedARN := pmapper.NormalizeARN(identity.CallerARN)
		if !g.HasNode(normalizedARN) {
			continue
		}
		var paths []pmapper.PrivescPath
		if g.IsAdmin(normalizedARN) {
			paths = g.FindPathsToAdmin(normalizedARN)
		} else {
			paths = g.FindAllReachable(normalizedARN)
		}
		rows := r.buildPathViewRows(paths, g, name)
		allRows = append(allRows, rows...)
	}

	if len(allRows) == 0 {
		fmt.Print("\n  No reachable targets found for any workspace identity.\n\n")
		return nil
	}

	return ui.RunPathView("Escalation Paths — All Identities", allRows, true)
}

// printAnalysis displays escalation paths for a single principal
func (r *REPL) printAnalysis(identityName, principalARN string, g *pmapper.PrivescGraph) {
	paths := g.FindPathsToAdmin(principalARN)

	fmt.Println()
	ui.Section(fmt.Sprintf("Analyzing paths for '%s' (%s)", identityName, principalARN))
	fmt.Println()

	if len(paths) == 0 {
		fmt.Println("  No escalation paths to admin found.")
		fmt.Println()
		return
	}

	for _, path := range paths {
		targetShort := pmapper.ShortARN(path.Target)
		fmt.Printf("  %s (%d hop%s):\n\n",
			ui.BoldCyan.Render(fmt.Sprintf("Escalation Chain to %s", targetShort)),
			len(path.Steps),
			pluralize(len(path.Steps)))

		for i, step := range path.Steps {
			srcShort := pmapper.ShortARN(step.Source)
			dstShort := pmapper.ShortARN(step.Destination)

			fmt.Printf("    %s  %s\n",
				ui.Accent.Render(fmt.Sprintf("Step %d:", i+1)),
				ui.Bold.Render(step.ShortReason))
			fmt.Printf("      %s -> %s\n", srcShort, dstShort)

			if step.Reason != "" {
				fmt.Printf("      %s %s\n", ui.Muted.Render("Reason:"), step.Reason)
			}

			if len(step.ModuleIDs) > 0 {
				fmt.Printf("      %s %s\n",
					ui.Success.Render("Module:"),
					strings.Join(step.ModuleIDs, ", "))

				// Show quick start for first module
				moduleID := step.ModuleIDs[0]
				fmt.Printf("      %s\n", ui.Muted.Render("Quick start:"))
				fmt.Printf("        use %s\n", moduleID)

				// If destination is a role, suggest setting ROLE_ARN
				if strings.Contains(step.Destination, ":role/") {
					fmt.Printf("        set ROLE_ARN %s\n", step.Destination)
				}
			} else {
				// Find unmapped edges for this hop
				edges := g.GetEdgesBetween(step.Source, step.Destination)
				if len(edges) > 0 {
					reasons := make([]string, 0, len(edges))
					for _, e := range edges {
						reasons = append(reasons, e.Reason)
					}
					fmt.Printf("      %s %s\n",
						ui.Warning.Render("No module:"),
						strings.Join(reasons, "; "))
				} else {
					fmt.Printf("      %s\n", ui.Warning.Render("No pathrunner module available"))
				}
			}

			fmt.Println()
		}
	}
}

// pmapperStatus shows graph metadata and module coverage
func (r *REPL) pmapperStatus(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showPmapperStatusHelp()
	}

	// Try auto-load for current identity's account
	if identity := r.identityManager.GetCurrent(); identity != nil && identity.CallerARN != "" {
		accountID := pmapper.ExtractAccountIDFromARN(identity.CallerARN)
		if accountID != "" {
			r.pmapperManager.TryAutoLoad(accountID)
		}
	}

	statuses := r.pmapperManager.Status()
	if len(statuses) == 0 {
		fmt.Println("No PMapper graphs loaded.")
		fmt.Println("Run 'pmapper import' to import PMapper data.")
		return nil
	}

	fmt.Println()
	ui.Section("PMapper Graph Status")
	fmt.Println()

	for _, status := range statuses {
		ui.KeyValueTable("", []ui.KV{
			{Key: "Account", Value: status.AccountID},
			{Key: "Imported", Value: status.ImportedAt.Format("2006-01-02 15:04:05")},
			{Key: "Nodes", Value: fmt.Sprintf("%d (%d admin)", status.NodeCount, status.AdminCount)},
			{Key: "Edges", Value: fmt.Sprintf("%d", status.EdgeCount)},
		})
		fmt.Println()

		if len(status.EdgePatterns) > 0 {
			withModule := 0
			for _, ep := range status.EdgePatterns {
				if ep.HasModule {
					withModule++
				}
			}

			fmt.Printf("  Module Coverage: %d/%d edge patterns have pathrunner modules\n\n",
				withModule, len(status.EdgePatterns))

			rows := make([][]string, 0, len(status.EdgePatterns))
			for _, ep := range status.EdgePatterns {
				moduleStr := ui.Warning.Render("(no module)")
				if ep.HasModule {
					moduleStr = ui.Success.Render(strings.Join(ep.ModuleIDs, ", "))
				} else if len(ep.ModuleIDs) > 0 {
					moduleStr = ui.Muted.Render(strings.Join(ep.ModuleIDs, ", ") + " (not installed)")
				}

				rows = append(rows, []string{
					ep.ShortReason,
					fmt.Sprintf("%d", ep.Count),
					moduleStr,
				})
			}

			ui.Table([]string{"Edge Type", "Count", "Modules"}, rows)
			fmt.Println()
		}
	}

	return nil
}

// buildPathViewRows converts PrivescPaths into UI rows for the interactive viewer.
func (r *REPL) buildPathViewRows(paths []pmapper.PrivescPath, g *pmapper.PrivescGraph, identityName string) []ui.PathViewRow {
	var rows []ui.PathViewRow

	for _, path := range paths {
		row := ui.PathViewRow{
			Identity:   identityName,
			Target:     pmapper.ShortARN(path.Target),
			TargetFull: path.Target,
			IsAdmin:    g.IsAdmin(path.Target),
			Hops:       len(path.Steps),
		}

		var moduleIDs []string
		withModule := 0

		for _, step := range path.Steps {
			vs := ui.PathViewStep{
				Source:      step.Source,
				Destination: step.Destination,
				SourceShort: pmapper.ShortARN(step.Source),
				DestShort:   pmapper.ShortARN(step.Destination),
				Reason:      step.Reason,
			}

			if len(step.ModuleIDs) > 0 {
				vs.ModuleID = step.ModuleIDs[0]
				vs.Commands = generateStepCommands(step.ModuleIDs[0], step)
				moduleIDs = append(moduleIDs, step.ModuleIDs[0])
				withModule++
			}

			row.Steps = append(row.Steps, vs)
		}

		// Determine exploitability and module chain
		switch {
		case withModule == len(path.Steps) && withModule > 0:
			row.Exploitable = "full"
			row.ModuleChain = strings.Join(moduleIDs, " → ")
		case withModule > 0:
			row.Exploitable = "partial"
			parts := make([]string, len(path.Steps))
			for i, step := range path.Steps {
				if len(step.ModuleIDs) > 0 {
					parts[i] = step.ModuleIDs[0]
				} else {
					parts[i] = "(?)"
				}
			}
			row.ModuleChain = strings.Join(parts, " → ")
		default:
			row.Exploitable = "none"
			row.ModuleChain = "(no module)"
		}

		rows = append(rows, row)
	}

	// Sort: admin+full first, then non-admin+full, then partial, then none; within group by hops
	sort.SliceStable(rows, func(i, j int) bool {
		ri, rj := rows[i], rows[j]
		gi, gj := exploitGroup(ri), exploitGroup(rj)
		if gi != gj {
			return gi < gj
		}
		return ri.Hops < rj.Hops
	})

	return rows
}

// exploitGroup returns a sort key: lower = higher priority.
func exploitGroup(row ui.PathViewRow) int {
	switch {
	case row.Exploitable == "full" && row.IsAdmin:
		return 0
	case row.Exploitable == "full":
		return 1
	case row.Exploitable == "partial" && row.IsAdmin:
		return 2
	case row.Exploitable == "partial":
		return 3
	case row.IsAdmin:
		return 4
	default:
		return 5
	}
}

// generateStepCommands builds the list of REPL commands for a step with a module.
func generateStepCommands(moduleID string, step pmapper.PrivescStep) []string {
	cmds := []string{fmt.Sprintf("use %s", moduleID)}

	// Self-escalation steps: pre-fill options based on the target resource
	if step.SelfEscalation != nil {
		cmds = append(cmds, generateSelfEscalationOptions(moduleID, step.SelfEscalation)...)
		cmds = append(cmds, "exploit")
		return cmds
	}

	mod, err := modules.LoadModule(moduleID)
	if err != nil {
		cmds = append(cmds, "exploit")
		return cmds
	}

	for _, opt := range mod.Options() {
		if !opt.Required {
			continue
		}
		if opt.Name == "ROLE_ARN" && strings.Contains(step.Destination, ":role/") {
			cmds = append(cmds, fmt.Sprintf("set ROLE_ARN %s", step.Destination))
		} else if opt.Default == "" {
			cmds = append(cmds, fmt.Sprintf("set %s <required>", opt.Name))
		}
	}

	cmds = append(cmds, "exploit")
	return cmds
}

// generateSelfEscalationOptions returns set commands for self-escalation module options.
func generateSelfEscalationOptions(moduleID string, result *pmapper.SelfEscalationResult) []string {
	var cmds []string

	mod, err := modules.LoadModule(moduleID)
	if err != nil {
		// Module not installed — suggest the resource as a hint
		if result.Resource != "" {
			cmds = append(cmds, fmt.Sprintf("# target: %s", result.Resource))
		}
		return cmds
	}

	for _, opt := range mod.Options() {
		if !opt.Required {
			continue
		}
		switch opt.Name {
		case "POLICY_ARN":
			if strings.Contains(result.Action, "PolicyVersion") || strings.Contains(result.Action, "AttachGroupPolicy") || strings.Contains(result.Action, "AttachUserPolicy") || strings.Contains(result.Action, "AttachRolePolicy") {
				cmds = append(cmds, fmt.Sprintf("set POLICY_ARN %s", result.Resource))
			} else if opt.Default == "" {
				cmds = append(cmds, fmt.Sprintf("set %s <required>", opt.Name))
			}
		case "GROUP_NAME":
			// Extract group name from group ARN
			if strings.Contains(result.Resource, ":group/") {
				parts := strings.Split(result.Resource, "/")
				if len(parts) > 0 {
					cmds = append(cmds, fmt.Sprintf("set GROUP_NAME %s", parts[len(parts)-1]))
				}
			} else if opt.Default == "" {
				cmds = append(cmds, fmt.Sprintf("set %s <required>", opt.Name))
			}
		default:
			if opt.Default == "" {
				cmds = append(cmds, fmt.Sprintf("set %s <required>", opt.Name))
			}
		}
	}

	return cmds
}

// Help text methods

func (r *REPL) showPmapperHelp() error {
	fmt.Println("PMapper Commands:")
	fmt.Println("  pmapper import                    - Import PMapper data (auto-detect)")
	fmt.Println("  pmapper import --path <dir>       - Import from a specific directory")
	fmt.Println("  pmapper analyze                   - Show escalation paths for current identity")
	fmt.Println("  pmapper analyze --all             - Show escalation paths for all workspace identities")
	fmt.Println("  pmapper status                    - Show graph metadata and module coverage")
	fmt.Println("  pmapper help                      - Show this help message")
	fmt.Println()
	fmt.Println("PMapper (Principal Mapper) maps IAM privilege escalation paths in AWS.")
	fmt.Println("Import its graph data to see which pathrunner modules can be used to")
	fmt.Println("escalate privileges for your current identities.")
	fmt.Println()
	fmt.Println("Use 'pmapper <subcommand> help' for detailed help on a specific subcommand.")
	return nil
}

func (r *REPL) showPmapperImportHelp() error {
	fmt.Println("PMapper Import Command:")
	fmt.Println("  pmapper import                    - Auto-detect PMapper data directory")
	fmt.Println("  pmapper import --path <dir>       - Import from a specific directory")
	fmt.Println()
	fmt.Println("Imports PMapper graph data (nodes.json and edges.json) and builds an")
	fmt.Println("in-memory directed graph for path analysis. Data is persisted to")
	fmt.Println("~/.pathrunner/graphs/ for reuse across sessions.")
	fmt.Println()
	fmt.Println("Auto-detects the PMapper data directory on macOS (~/.local/share/pmapper/)")
	fmt.Println("and Linux (~/.local/share/principalmapper/). If workspace identities are")
	fmt.Println("configured, import scopes to accounts matching those identities.")
	fmt.Println("Otherwise, all found accounts are imported.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  pmapper import")
	fmt.Println("  pmapper import --path /tmp/pmapper-output/")
	fmt.Println("  pmapper import --path /tmp/pmapper-output/123456789012/")
	return nil
}

func (r *REPL) showPmapperAnalyzeHelp() error {
	fmt.Println("PMapper Analyze Command:")
	fmt.Println("  pmapper analyze          - Show escalation paths for current identity")
	fmt.Println("  pmapper analyze --all    - Show escalation paths for all workspace identities")
	fmt.Println()
	fmt.Println("Finds shortest paths from the identity's principal to any admin node")
	fmt.Println("in the PMapper graph. For each hop, shows the escalation technique")
	fmt.Println("and which pathrunner module(s) can exploit it.")
	fmt.Println()
	fmt.Println("Requires:")
	fmt.Println("  - PMapper data imported ('pmapper import')")
	fmt.Println("  - Active identity with resolved ARN ('whoami')")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  pmapper analyze")
	fmt.Println("  pmapper analyze --all")
	return nil
}

func (r *REPL) showPmapperStatusHelp() error {
	fmt.Println("PMapper Status Command:")
	fmt.Println("  pmapper status    - Show graph metadata and module coverage")
	fmt.Println()
	fmt.Println("Displays information about imported PMapper graphs including")
	fmt.Println("node/edge counts, admin nodes, and which edge patterns have")
	fmt.Println("corresponding pathrunner modules available.")
	return nil
}

// showPmapperHint shows a contextual hint after identity events if graph data exists.
func (r *REPL) showPmapperHint() {
	identity := r.identityManager.GetCurrent()
	if identity == nil || identity.CallerARN == "" {
		return
	}

	accountID := pmapper.ExtractAccountIDFromARN(identity.CallerARN)
	if accountID == "" {
		return
	}

	if !r.pmapperManager.TryAutoLoad(accountID) {
		return
	}

	count := r.pmapperManager.CountPathsToAdmin(accountID, identity.CallerARN)
	if count > 0 {
		fmt.Printf("%s %d escalation path(s) to admin available. Run 'pmapper analyze' to view.\n",
			ui.Muted.Render("Tip:"), count)
	}
}

// pluralize returns "s" for counts != 1
func pluralize(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
