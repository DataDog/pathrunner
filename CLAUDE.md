# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

```bash
# Build the main executable
go build -o pathrunner cmd/pathrunner/main.go

# Run in development mode
go run cmd/pathrunner/main.go

# Run as CLI command
./pathrunner [command] [subcommand] [flags]

# Run in REPL mode (interactive)
./pathrunner

# Add dependencies
go get github.com/example/package
go mod tidy

# Run tests
go test ./tests/unit/          # Unit tests only
go test ./tests/integration/   # Integration tests only
go test ./tests/...            # All tests
go test -v ./tests/...         # Verbose output
go test -cover ./pkg/...       # With coverage
```

## Architecture Overview

Pathrunner is a modular AWS post-exploitation framework with dual CLI/REPL interfaces that share the same underlying business logic.

### Core Components

**pkg/core/** - Central framework components:
- `repl/`: Interactive shell package with command parsing, tab completion, and command execution
  - `repl.go`: Main REPL loop and command dispatcher
  - `commands.go`: Command handlers for all REPL commands
  - `completion.go`: Tab completion logic with dynamic updates
  - `identity.go`: Identity management command handlers
  - `session.go`: Workspace command handlers (renamed from session)
  - `module.go`: Module-related command handlers
- `identity.go`: Multi-identity AWS credential management with automatic refresh for profiles/SSO
- `session.go`: Session persistence with command logging, resource tracking, and state management
- `repl_adapters.go`: Adapter pattern to bridge concrete types with REPL interfaces
- Each component provides both internal methods and public methods for integration

**pkg/cli/** - Cobra CLI wrapper that maps 1:1 with REPL commands:
- `cli.go`: Main CLI wrapper around REPL functionality using adapters
- `commands.go`: All Cobra command definitions that execute REPL handlers
- Supports complex flag parsing (e.g., `--profile`, `--keys`, `--from-output`, `--expired`)

**pkg/modules/** - Module system interfaces and shared types:
- `interface.go`: Core interfaces for Module, Identity, ResourceTracker, PayloadCompatible, and shared data structures
- `registry.go`: Module registration and loading system
- Modules must implement the Module interface with Execute(), PayloadOptions(), and ListPayloads() methods
- Modules can optionally implement `PayloadCompatible` to declare supported payload tags/service context

**pkg/payloads/** - Centralized payload registry system (service-based, reusable across modules):
- `interface.go`: Core `Payload` interface (GetName, GetTags, GetOptions, GenerateCode, ProcessResult, Validate)
- `registry.go`: Thread-safe global registry with tag-based filtering (GetPayloadsByTags, GetPayloadsByContext, GetPayloadsByFilter)
- `tags.go`: Standardized tag constants organized by category (service, language, technique, transport)
- `ec2/`: EC2 bash payloads — `exfil_webhook.go`, `direct_elevation.go`, `reverse_shell.go`
- `lambda/`: Lambda Python payloads — `exfil_output.go`, `exfil_https.go`, `backdoor_role.go`, `backdoor_user.go`
- Payloads self-register via `init()` functions, same pattern as modules
- Tag categories: service (`lambda`, `ec2`, `ecs`, ...), language (`python`, `bash`, ...), technique (`exfil`, `backdoor`, `reverse_shell`, `direct_action`), transport (`webhook`, `output`, `network`)

**pkg/exploits/** - Exploitation modules:
- `lambda_passrole/`: Lambda/PassRole privilege escalation module (refactored to use payload registry)
  - `module.go`: Implements `PayloadCompatible` with tags `[lambda, python]`; queries registry for Lambda payloads
- `ec2_passrole/`: EC2/PassRole privilege escalation via RunInstances with user-data scripts
  - `module.go`: Implements `PayloadCompatible` with tags `[ec2, bash]`; auto-detects AMI and subnet, launches instances with payload as user-data
- `sts_assume_role/`: STS AssumeRole module for role assumption and credential handling

**pkg/utils/** - Utility functions:
- `credentials.go`: Credential extraction from various formats (env vars, JSON, etc.)

**pkg/config/** - Configuration management:
- `config.go`: Application configuration with validation

### Key Design Patterns

**Dual Interface Architecture**:
- REPL and CLI share the same command handlers via REPL's `ExecuteCommand()` method
- No code duplication - same business logic handles both interfaces
- State management works identically in both modes
- CLI uses adapter pattern to bridge concrete types with REPL interfaces

**Workspace-Scoped Identities** (Critical Feature):
- Each workspace maintains its own completely isolated set of AWS identities
- Switching workspaces automatically loads/saves identity state
- `loadSessionState()` always replaces (not merges) identities when switching
- Prevents accidentally using wrong credentials in wrong projects

**Identity Management**:
- Supports AWS profiles, environment variables, static keys, and credential extraction
- Auto-refreshes AWS configs from profiles to handle SSO token expiration
- `RefreshConfig()` method rebuilds AWS SDK configs from stored profile names
- Identity operations: add, list, show, switch, remove (specific or --expired), refresh
- **Auto-Import**: Automatically detects and imports credentials from exploit output
  - Handles structured data (between `--- PATHFINDER_IDENTITY_DATA ---` markers)
  - Also attempts general credential extraction using `utils.ExtractCredentialsFromText()`
  - Supports AWS_* env vars, JSON, Python dict formats, and base64-encoded creds
  - Modules should include structured data for auto-switch support
- **AWS CLI Passthrough**: `aws` command passes through to AWS CLI with current identity
  - Automatically injects current identity credentials as environment variables
  - Transparently switches credentials when you switch identities
  - Works in both REPL and CLI modes
  - Requires AWS CLI to be installed and in PATH

**Session System** (Workspaces):
- JSON persistence in `~/.pathrunner/sessions/` with auto-save after each command
- Tracks AWS identities (workspace-scoped), created resources, command history, and module state
- `ResourceTracker` interface allows modules to register created AWS resources for cleanup
- Workspace commands: create, list, switch, save, delete, cleanup, history

**Command Aliases**:
- `identities` → `identity` (for convenience)
- `workspaces` → `workspace` (for convenience)
- `quit` → `exit`
- Both forms work identically and have full tab completion

**Payload Registry System** (Reusable Service-Based Payloads):
- Payloads are decoupled from modules and registered in a global registry
- Modules query the registry by tags to discover compatible payloads at runtime
- Each payload implements `GenerateCode(options)` to produce service-specific code (Python for Lambda, bash for EC2)
- Each payload implements `ProcessResult(result)` to parse and format execution output
- `TagFilter` supports advanced queries: `RequireAll`, `RequireAny`, `Exclude`
- Modules implement `PayloadCompatible` interface to declare their service context and compatible tags
- The `Module` interface includes `PayloadOptions(payloadName)` and `ListPayloads()` for dynamic UI

**Module and Payload Registration**:
- Both modules and payloads self-register using `init()` functions
- Modules use `modules.Register()`, payloads use `payloads.Register()`
- Import in `main.go` with blank imports for both:
  ```go
  _ "pathrunner/pkg/payloads/ec2"      // Register EC2 payloads
  _ "pathrunner/pkg/payloads/lambda"    // Register Lambda payloads
  _ "pathrunner/pkg/exploits/ec2_passrole"
  _ "pathrunner/pkg/exploits/lambda_passrole"
  _ "pathrunner/pkg/exploits/sts_assume_role"
  ```
- Dynamic loading via `modules.LoadModule()` with error handling

**Module Output Format for Auto-Import**:
Modules that output credentials should include structured data for automatic import:

```go
// In module's Execute() method, append to output:
outputBuilder.WriteString("\n--- PATHFINDER_IDENTITY_DATA ---\n")
outputBuilder.WriteString(fmt.Sprintf("NAME=%s\n", identityName))
outputBuilder.WriteString(fmt.Sprintf("TYPE=assumed_role\n"))
outputBuilder.WriteString(fmt.Sprintf("ACCESS_KEY_ID=%s\n", accessKeyID))
outputBuilder.WriteString(fmt.Sprintf("SECRET_ACCESS_KEY=%s\n", secretKey))
outputBuilder.WriteString(fmt.Sprintf("SESSION_TOKEN=%s\n", sessionToken))
outputBuilder.WriteString(fmt.Sprintf("REGION=%s\n", region))
outputBuilder.WriteString(fmt.Sprintf("EXPIRES_AT=%s\n", expiresAt.Format(time.RFC3339)))
outputBuilder.WriteString(fmt.Sprintf("AUTO_SWITCH=%s\n", "true")) // optional
outputBuilder.WriteString("--- END_PATHFINDER_IDENTITY_DATA ---\n")
```

Alternatively, credentials in any common format (AWS_* env vars, JSON, Python dicts) will be auto-detected using the `utils.ExtractCredentialsFromText()` utility.

### AWS Integration Specifics

**Credential Refresh**: For AWS SSO profiles, credentials are not stored statically. Instead, profile names are persisted and AWS configs are rebuilt on-demand using `identity.RefreshConfig()`.

**Resource Tracking**: Modules must call `tracker.TrackResource()` for any AWS resources they create. The session manager implements ResourceTracker and can clean up resources by type (Lambda functions, IAM roles/users, EC2 instances).

**Interactive Resource Cleanup**: The `workspace cleanup` command uses `survey/v2` for interactive multi-select, allowing users to choose which tracked resources to delete rather than bulk-deleting everything. Cleanup is region-aware.

**Timeouts**: AWS operations use 30-second timeouts to accommodate SSO credential resolution delays.

## Testing Strategy

**IMPORTANT**: All new commands and features MUST have both unit and integration tests before being considered complete.

### Test Structure

```
tests/
├── unit/
│   ├── config_test.go              # Configuration tests
│   ├── context_test.go             # Contextual prompt tests
│   ├── repl_test.go                # Basic REPL tests
│   ├── identity_manager_test.go    # IdentityManager unit tests
│   ├── session_manager_test.go     # SessionManager unit tests
│   ├── repl_commands_test.go       # REPL command handler tests
│   └── payload_registry_test.go    # Payload registry and tag filtering tests
└── integration/
    ├── setup_test.go               # Common test setup
    ├── identity_integration_test.go     # Identity command workflows
    ├── workspace_integration_test.go    # Workspace command workflows
    └── commands_integration_test.go     # General command workflows
```

### Testing Requirements for New Features

When adding a new CLI/REPL command, you MUST create:

#### 1. Unit Tests
Test the individual components in isolation using mocks:

```go
// Example: tests/unit/feature_test.go
func TestFeatureManagerCreation(t *testing.T) {
    // Test initialization
}

func TestFeatureOperation(t *testing.T) {
    // Test core business logic
}

func TestFeatureValidation(t *testing.T) {
    // Test input validation
}

func TestFeatureErrorHandling(t *testing.T) {
    // Test error cases
}
```

#### 2. Integration Tests
Test the complete command workflow through the REPL:

```go
// Example: tests/integration/feature_integration_test.go
func TestFeatureCommand(t *testing.T) {
    r, _, _, cleanup := setupTest(t)
    defer cleanup()

    // Test successful execution
    err := r.ExecuteCommand("feature do-something")
    if err != nil {
        t.Errorf("Expected no error, got: %v", err)
    }
}

func TestFeatureCommandValidation(t *testing.T) {
    r, _, _, cleanup := setupTest(t)
    defer cleanup()

    // Test validation (missing arguments, invalid values, etc.)
    err := r.ExecuteCommand("feature")
    if err == nil {
        t.Error("Expected error for missing arguments")
    }
}

func TestFeatureCommandErrorHandling(t *testing.T) {
    // Test error scenarios (not found, permission denied, etc.)
}

func TestFeatureCommandAliases(t *testing.T) {
    // If command has aliases, test them
}
```

### Test Patterns and Best Practices

**Setup with Temporary Environment**:
```go
func setupTest(t *testing.T) (*repl.REPL, *core.SessionManager, *core.IdentityManager, func()) {
    tempDir := t.TempDir()
    originalHome := os.Getenv("HOME")
    os.Setenv("HOME", tempDir)

    sessionManager := core.NewSessionManager()
    identityManager := core.NewIdentityManager(nil, nil)

    sessionAdapter := core.NewSessionAdapter(sessionManager)
    identityAdapter := core.NewIdentityManagerAdapter(identityManager)

    r := repl.NewREPL(identityAdapter, sessionAdapter)

    cleanup := func() {
        os.Setenv("HOME", originalHome)
    }

    return r, sessionManager, identityManager, cleanup
}
```

**Test Command Validation**:
```go
testCases := []struct {
    name        string
    command     string
    expectError bool
    errorCheck  func(error) bool
}{
    {
        name:        "missing argument",
        command:     "mycommand",
        expectError: true,
        errorCheck: func(err error) bool {
            return strings.Contains(err.Error(), "requires")
        },
    },
    // ... more cases
}

for _, tc := range testCases {
    t.Run(tc.name, func(t *testing.T) {
        err := r.ExecuteCommand(tc.command)
        // Assert expectations
    })
}
```

**Test Workspace Isolation** (for identity-related features):
```go
func TestFeatureWorkspaceIsolation(t *testing.T) {
    r, sm, im, cleanup := setupTest(t)
    defer cleanup()

    // Setup in default workspace
    // ... configure feature

    // Create and switch to new workspace
    r.ExecuteCommand("workspace create isolated")
    r.ExecuteCommand("workspace switch isolated")

    // Verify isolation - feature state should be clean
    // ... assert clean state

    // Switch back
    r.ExecuteCommand("workspace switch default")

    // Verify restoration - feature state should be restored
    // ... assert restored state
}
```

### Test Coverage Goals

- **Unit Tests**: 70%+ coverage of business logic
- **Integration Tests**: All CLI/REPL commands must have end-to-end tests
- **Critical Features**: 100% coverage (identity management, workspace isolation, state persistence)

### Running Tests

```bash
# Run all tests
go test ./tests/...

# Run only unit tests
go test ./tests/unit/

# Run only integration tests
go test ./tests/integration/

# Run with verbose output
go test -v ./tests/...

# Run specific test
go test -v ./tests/integration/ -run TestWorkspaceIsolation

# Run with coverage
go test -cover ./pkg/...
```

### Mocking AWS SDK

For features that interact with AWS, mock the AWS SDK:

```go
// TODO: Add AWS SDK mocking patterns when implementing
// Use aws-sdk-go-v2/aws/smithy/testing or similar
```

## Session Data Storage

Sessions (workspaces) are stored as JSON files in `~/.pathrunner/sessions/` with this structure:
- **Identities map**: Full credential configs per workspace (except aws.Config is rebuilt on load)
- **CurrentIdentity**: Name of active identity in this workspace
- **Command log**: Timestamps, success/failure, and output
- **Created resources**: Cleanup metadata for AWS resources
- **Current module**: Selected module name
- **Options**: Module option key-value pairs

## Common Gotchas

**AWS Config Persistence**: The `aws.Config` struct has `json:"-"` tag so it's not serialized. Must call `RefreshConfig()` when loading identities from JSON.

**Module Execution Signature**: Modules must implement `Execute(identity, options, tracker)` with the ResourceTracker parameter for resource cleanup integration. Modules must also implement `PayloadOptions(payloadName)` and `ListPayloads()`.

**Payload Code Generation**: Lambda payloads generate Python code, EC2 payloads generate bash scripts, both as Go string literals. Use triple quotes `'''` for multiline JSON in Python, not backticks.

**Import Cycles**: Keep module interfaces in `pkg/modules/` separate from core logic to avoid import cycles between core and specific modules. Payloads in `pkg/payloads/` depend on `pkg/modules/` for the `Option` type but never import core or specific exploits.

**Workspace Isolation**: When adding features that store state, ensure they respect workspace boundaries. Use `loadSessionState()` and `saveCurrentState()` to persist state per workspace.

**Command Naming**: Use singular form for command names (e.g., `identity`, `workspace`), aliases handle plural forms automatically.

**Error Types**: Use the REPL's custom error types for consistent error messages:
- `NewCommandNotFoundError()` - Command doesn't exist
- `NewInvalidArgumentsError()` - Invalid/missing arguments
- `NewIdentityRequiredError()` - Operation requires identity
- `NewExecutionError()` - Wraps underlying error with context

**Tab Completion Updates**: When adding new commands or options, update `pkg/core/repl/completion.go` to include them in tab completion. Call `updateCompletion()` when state changes.

**Keeping CLI and REPL in Sync**: This is CRITICAL! When adding any new command, subcommand, option, or flag, you MUST update THREE places:
1. **Implementation**: Add to the actual command handler (e.g., `pkg/core/repl/identity.go`)
2. **Help Text**: Add to `pkg/core/repl/commands.go` in the appropriate `show*Help()` function
3. **Tab Completion**: Add to `pkg/core/repl/completion.go` in the appropriate completer function

Common mistakes to avoid:
- ❌ Adding a command to CLI but forgetting REPL help text
- ❌ Adding a flag to the implementation but forgetting tab completion
- ❌ Documenting in help text but not implementing the actual handler
- ❌ Forgetting to update both `identity` AND its aliases (`identities`, `id`, `ids`) completers

**Checklist for New Commands/Options**:
- [ ] Handler implemented in `pkg/core/repl/*.go`
- [ ] CLI wrapper added in `pkg/cli/commands.go`
- [ ] Help text updated in `pkg/core/repl/commands.go`
- [ ] Tab completion updated in `pkg/core/repl/completion.go`
- [ ] If command has aliases, update all alias completers
- [ ] Unit tests added
- [ ] Integration tests added
- [ ] Manual testing with tab completion verified

## Development Workflow

### Adding a New Command

1. **Design**: Determine if command is identity/workspace/module/general
2. **REPL Handler**: Add command handler in appropriate file in `pkg/core/repl/`
3. **Command Registry**: Register command in `pkg/core/repl/commands.go`
4. **CLI Wrapper**: Add Cobra command in `pkg/cli/commands.go`
5. **Help Text**: Update `pkg/core/repl/commands.go` in appropriate `show*Help()` function
6. **Tab Completion**: Update `pkg/core/repl/completion.go` in appropriate completer(s)
7. **Aliases**: If command has aliases, update ALL alias completers
8. **Unit Tests**: Create tests in `tests/unit/` for business logic
9. **Integration Tests**: Create tests in `tests/integration/` for end-to-end workflow
10. **Documentation**: Update help text and README if needed
11. **Verification**: Manually test tab completion works for new command/options

### Adding a New Module

1. **Module Structure**: Create directory in `pkg/exploits/`
2. **Implement Interface**: Implement `modules.Module` interface (including `PayloadOptions()` and `ListPayloads()`)
3. **Implement PayloadCompatible**: Declare compatible tags and service context
4. **Register Module**: Add `init()` function with `modules.Register()`
5. **Import**: Add blank import in `cmd/pathrunner/main.go`
6. **Payload Integration**: Query `payloads.GetPayloadsByTags()` to discover compatible payloads; delegate code generation to `payload.GenerateCode()` and result parsing to `payload.ProcessResult()`
7. **Tests**: Add unit and integration tests
8. **Documentation**: Update README with module usage

### Adding a New Payload

1. **Choose Service Directory**: Create file in `pkg/payloads/ec2/`, `pkg/payloads/lambda/`, or a new service directory
2. **Implement Payload Interface**: Must implement `GetName()`, `GetDescription()`, `GetTags()`, `GetOptions()`, `GenerateCode()`, `ProcessResult()`, `Validate()`
3. **Assign Tags**: Use standard tag constants from `pkg/payloads/tags.go` (service, language, technique, transport)
4. **Register Payload**: Add `init()` function calling `payloads.Register()`
5. **Import**: If new service directory, add blank import in `cmd/pathrunner/main.go`
6. **Tests**: Add tests for code generation, validation, and result processing
7. **Naming Convention**: Use `technique/method` format (e.g., `exfil/webhook`, `backdoor/role`, `shell/reverse`, `elevation/direct`)

## Code Style

- **Error Messages**: Use lowercase, no trailing punctuation for errors returned to user
- **User Messages**: Capitalize sentences, use proper punctuation for informational output
- **Variable Naming**: Use descriptive names (e.g., `identityManager` not `im` in function params)
- **Comments**: Exported functions must have godoc comments
- **Test Names**: Use `TestFeatureSpecificBehavior` format

## Current Test Statistics

- **Total Tests**: 103 (58 unit + 45 integration)
- **Test Files**: 10
- **Lines of Test Code**: 2,510
- **Pass Rate**: 100%
- **Coverage**: Unit tests cover core business logic, integration tests cover all commands

**Test Coverage by Component**:
- ✅ IdentityManager: 14 unit tests
- ✅ SessionManager: 14 unit tests
- ✅ REPL Commands: 16 unit tests
- ✅ Identity Commands: 7 integration tests
- ✅ Workspace Commands: 10 integration tests
- ✅ General Commands: 28 integration tests

## Recent Updates

**Centralized Payload Registry** (Major Architecture Change - In Progress):
- Payloads decoupled from modules into `pkg/payloads/` with global registry
- Tag-based discovery system replaces hardcoded payload references
- `lambda_passrole` refactored to query registry instead of embedding payload code
- Enables payload reuse across modules targeting the same AWS service
- `Module` interface expanded with `PayloadOptions()` and `ListPayloads()` methods
- New `PayloadCompatible` interface for modules to declare service context

**EC2 PassRole Module** (New - In Progress):
- `exploit/ec2_passrole` module for privilege escalation via RunInstances
- Auto-detects Amazon Linux AMI and default VPC subnet
- Injects payload as base64-encoded user-data script
- Three EC2 payloads: `exfil/webhook`, `elevation/direct`, `shell/reverse`
- Tracks launched instances in ResourceTracker for cleanup

**Interactive Resource Cleanup** (In Progress):
- `workspace cleanup` now uses `survey/v2` for interactive multi-select
- Users choose which tracked resources to delete
- Region-aware cleanup; supports EC2 instance termination

**Workspace-Scoped Identities**:
- Identities are completely isolated per workspace
- `loadSessionState()` replaces (not merges) identities on workspace switch
- `saveCurrentState()` persists all identities and current selection
- Critical for preventing credential mix-ups across projects

**Command Aliases**:
- Added pluralized aliases: `identities`, `workspaces`
- Added `quit` as alias for `exit`
- Full tab completion support for all aliases

**Identity Management**:
- Added `identity clear <name>` to remove specific identity
- Added `identity clear --expired` to bulk remove expired identities
- Protection prevents removing current identity

**Session to Workspace Rename**:
- Renamed "session" command to "workspace" throughout
- Updated all user-facing messages and documentation
- Old terminology removed from codebase

**Testing Infrastructure**:
- Comprehensive test suite with unit and integration tests
- Payload registry tests added (`tests/unit/payload_registry_test.go`)
- All new features must include unit and integration tests
