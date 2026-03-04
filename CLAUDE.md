# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Related Projects

Pathrunner is one of three projects sharing the `{service}-{number}` identifier convention for AWS privilege escalation paths:

- **pathfinding.cloud** (`/Users/seth.art/Documents/projects/pathfinding.cloud`) — Source of truth. 69 YAML path definitions in `data/paths/{service}/{service}-{number}.yaml` with permissions, prerequisites, exploitation steps. Schema v1.6.0.
- **pathfinding-labs** (`/Users/seth.art/Documents/projects/pathfinding-labs`) — Terraform lab environments. 97 scenarios in `modules/scenarios/`, each with `scenario.yaml`, `demo_attack.sh`, `cleanup_attack.sh`, and Terraform modules.
- **pathrunner** (this repo) — Automates exploitation. Currently implements 4 paths (lambda-001, lambda-002, ec2-001, sts-001) with architecture to scale to all 69+.

```
pathfinding.cloud (YAML) → pathfinding-labs (Terraform) → pathrunner (execution)
  lambda-001.yaml           scenario.yaml / demo_attack.sh   pkg/exploits/lambda_passrole/
```

The `{service}-{number}` ID links path definition → deployable lab → automated exploit module. Pathrunner's `PathInfo` struct mirrors the subset of pathfinding.cloud fields useful at runtime.

## Build and Development Commands

```bash
go build -o pathrunner cmd/pathrunner/main.go   # Build
go run cmd/pathrunner/main.go                    # Dev mode
./pathrunner [command] [subcommand] [flags]      # CLI mode
./pathrunner                                     # REPL mode
go test ./tests/unit/                            # Unit tests
go test ./tests/integration/                     # Integration tests
go test ./tests/...                              # All tests
go test -v ./tests/... -run TestName             # Specific test
```

## Architecture Overview

Modular AWS post-exploitation framework with dual CLI/REPL interfaces sharing the same business logic.

### Packages

- **pkg/core/** — REPL shell (`repl/`), identity management (`identity.go`), session persistence (`session.go`), adapter pattern (`repl_adapters.go`). The REPL handles command parsing, tab completion, and dispatching.
- **pkg/cli/** — Cobra CLI wrapper mapping 1:1 with REPL commands via adapters.
- **pkg/modules/** — Module system: `Module` interface, `BaseModule` embeddable struct, `PathInfo` metadata, global registry with alias support and search/filter. Optional interfaces: `PayloadCompatible`, `Discoverable`.
- **pkg/payloads/** — Centralized payload registry: `Payload` interface, tag-based filtering (`TagFilter`), service subdirectories (`ec2/`, `lambda/`). Optional interfaces: `Verifiable`, `SideEffectReporter`.
- **pkg/exploits/** — Exploit modules, each embedding `BaseModule`. Current: `lambda_passrole/` (lambda-001), `lambda_passrole_esm/` (lambda-002), `ec2_passrole/` (ec2-001), `sts_assume_role/` (sts-001).
- **pkg/discovery/** — Reusable AWS enumeration: IAM roles by trust policy, instance profiles, DynamoDB streams. Used by modules implementing `Discoverable`.
- **pkg/utils/** — Credential extraction from env vars, JSON, Python dicts.
- **pkg/config/** — Application configuration.

### Key Design Patterns

**Dual Interface**: REPL and CLI share command handlers via `ExecuteCommand()`. CLI uses adapter pattern to bridge concrete types with REPL interfaces.

**Workspace-Scoped Identities**: Each workspace maintains isolated AWS identities. `loadSessionState()` replaces (not merges) identities on switch. Workspaces persist as JSON in `~/.pathrunner/sessions/`.

**Identity Management**: Supports AWS profiles, env vars, static keys, credential extraction. Auto-refreshes SSO via `RefreshConfig()`. Auto-imports credentials from exploit output (structured `--- PATHFINDER_IDENTITY_DATA ---` markers or general extraction via `utils.ExtractCredentialsFromText()`). AWS CLI passthrough injects current identity as env vars.

**Payload Registry**: Payloads are decoupled from modules and self-register via `init()`. Modules query by tags at runtime (`GetPayloadsByTags()`). Each payload implements `GenerateCode(options)` (Python for Lambda, bash for EC2) and `ProcessResult(result)`. Modules declare compatibility via `PayloadCompatible` interface.

**Optional Payload Interfaces** (in `pkg/payloads/interface.go`):
- `Verifiable`: For event-triggered modules — verify payload effect (e.g., check if policy attached). Used in trigger-and-verify retry loops.
- `SideEffectReporter`: For payloads modifying existing resources — reports modifications for cleanup tracking. Modules call `ReportSideEffects()` after execution and set `ModuleID`/`Region` on returned resources.

**Optional Module Interfaces** (in `pkg/modules/interface.go`):
- `Discoverable`: Auto-discover option values via AWS API. Methods: `DiscoverableOptions()`, `Discover()`. Uses `pkg/discovery/` utilities. Auto-triggered at exploit time if required options are missing.

**Lambda Environment Variables**: Event-triggered payloads read parameters from `os.environ`; modules set them via `CreateFunctionInput.Environment` — never hardcode values in Python source.

**Module Output for Auto-Import**: Modules outputting credentials should include structured data between `--- PATHFINDER_IDENTITY_DATA ---` / `--- END_PATHFINDER_IDENTITY_DATA ---` markers with NAME, TYPE, ACCESS_KEY_ID, SECRET_ACCESS_KEY, SESSION_TOKEN, REGION, EXPIRES_AT, AUTO_SWITCH fields. See `/create-module` skill's module-patterns.md for the full template.

**Registration**: Both modules and payloads self-register via `init()`. Modules: `modules.Register(id, constructor)` with pathfinding.cloud ID as primary key; aliases auto-registered from `PathInfo.Aliases`. Payloads: `payloads.Register()`. All registered via blank imports in `cmd/pathrunner/main.go`.

**Command Aliases**: `identities` -> `identity`, `workspaces` -> `workspace`, `quit` -> `exit`. All have full tab completion.

### AWS Integration

**Credential Refresh**: Profile names persisted, AWS configs rebuilt on-demand via `RefreshConfig()`.

**Resource Tracking**: Modules must call `tracker.TrackResource()` for created resources and check for `SideEffectReporter` on payloads to track modifications. Cleanup is region-aware, interactive via `survey/v2`, with permission error guidance.

**Cleanup Report**: `workspace report` generates handoff report with manual AWS CLI cleanup commands. Supports `--module <id>` filtering.

**Timeouts**: 30-second timeouts for AWS operations (SSO credential resolution).

## Testing Strategy

**IMPORTANT**: All new commands and features MUST have both unit and integration tests.

### Test Structure

```
tests/
├── unit/          # Business logic in isolation (config, identity, session, REPL commands, payloads, pathinfo, discovery)
└── integration/   # End-to-end command workflows (identity, workspace, commands, pathinfo, cleanup, report, discovery)
```

Common test setup uses `setupTest(t)` in `tests/integration/setup_test.go` which creates a temp HOME, initializes managers and adapters, and returns a cleanup function.

### Requirements

- Unit tests: test initialization, core logic, validation, error handling
- Integration tests: test successful execution, validation errors, error scenarios, aliases
- State-related features: test workspace isolation (setup in workspace A, switch to B, verify clean, switch back, verify restored)
- All CLI/REPL commands need end-to-end tests through `r.ExecuteCommand()`

## Session Data Storage

Workspaces persist as JSON in `~/.pathrunner/sessions/`: identities map (aws.Config rebuilt on load), current identity, command log, created resources, current module, options.

## Common Gotchas

**AWS Config Persistence**: `aws.Config` has `json:"-"` tag. Must call `RefreshConfig()` when loading from JSON.

**Module Execution Signature**: Modules embed `BaseModule`, implement `Options()` and `Execute(identity, options, tracker)`. Override `PayloadOptions()` and `ListPayloads()` if supporting payloads.

**Payload Code Generation**: Lambda payloads generate Python, EC2 payloads generate bash. Use `'''` for multiline JSON in Python, not backticks. Pass runtime params via `os.environ.get()`, not string concatenation.

**Import Cycles**: Module interfaces in `pkg/modules/` stay separate from core. Payloads depend on `pkg/modules/` for `Option` type but never import core or exploits.

**Workspace Isolation**: Features storing state must respect workspace boundaries via `loadSessionState()` / `saveCurrentState()`.

**Command Naming**: Singular form (e.g., `identity`, `workspace`), aliases handle plurals.

**Error Types**: `NewCommandNotFoundError()`, `NewInvalidArgumentsError()`, `NewIdentityRequiredError()`, `NewExecutionError()`.

**Keeping CLI and REPL in Sync**: When adding any command/subcommand/option/flag, update THREE places:
1. Handler in `pkg/core/repl/*.go`
2. Help text in `pkg/core/repl/commands.go` (`show*Help()` functions)
3. Tab completion in `pkg/core/repl/completion.go`

Common mistakes: forgetting REPL help text, forgetting tab completion, forgetting alias completers, missing `help` subcommand handler.

**Subcommand Help**: Every command/subcommand MUST support trailing `help`. Help checks go at top of handler, before validation.

**Checklist for New Commands/Options**:
- [ ] Handler in `pkg/core/repl/*.go`
- [ ] Registered in `pkg/core/repl/commands.go` `getCommands()` map
- [ ] CLI wrapper in `pkg/cli/commands.go` (and `cli.go`)
- [ ] Help text + subcommand help handler
- [ ] Tab completion (including alias completers)
- [ ] Unit tests + integration tests
- [ ] Manual tab completion verification

## Development Workflow

### Adding a New Command

1. Add handler in appropriate `pkg/core/repl/*.go` file
2. Register in `pkg/core/repl/commands.go` `getCommands()` map
3. Add Cobra command in `pkg/cli/commands.go`
4. Update help text in `show*Help()` functions
5. Add `help` argument check + dedicated `show*Help()` for each subcommand
6. Update tab completion in `pkg/core/repl/completion.go` (and alias completers)
7. Add unit tests in `tests/unit/` and integration tests in `tests/integration/`
8. Manually verify tab completion

### Adding a New Module or Payload

Use the `/create-module` skill, which has complete step-by-step workflows, Go templates, and a verification checklist in its supporting files (module-patterns.md, payload-patterns.md, checklist.md).

## Code Style

- **Error Messages**: Lowercase, no trailing punctuation
- **User Messages**: Capitalized sentences, proper punctuation
- **Variable Naming**: Descriptive (e.g., `identityManager` not `im`)
- **Comments**: Exported functions must have godoc comments
- **Test Names**: `TestFeatureSpecificBehavior` format
