# Pathrunner

A modular AWS post-exploitation framework with dual CLI/REPL interfaces for authorized security testing and penetration testing scenarios.

## Features

- **Dual Interface**: Both CLI and interactive REPL modes sharing the same business logic
- **Multi-Identity Management**: Manage multiple AWS credential sets with automatic refresh for profiles/SSO
- **Session Persistence**: JSON-based session storage with command logging and resource tracking
- **Lambda/PassRole Exploitation**: Privilege escalation through Lambda functions with four payload types:
  - Credential exfiltration (CloudWatch output)
  - HTTPS exfiltration to attacker endpoints
  - Backdoor IAM role creation
  - Backdoor IAM user creation
- **Resource Tracking**: Automatic tracking of created AWS resources for cleanup
- **AWS Integration**: Full SDK v2 support including profiles, environment variables, static keys, and SSO

## Installation

```bash
# Build the executable
go build -o pathrunner cmd/pathrunner/main.go

# Or run directly
go run cmd/pathrunner/main.go
```

## Usage

### REPL Mode (Interactive)

```bash
# Start interactive shell
./pathrunner

# Available commands in REPL
pathrunner> identity add --profile my-aws-profile
pathrunner> identity list
pathrunner> session new test-session
pathrunner> use lambda_passrole
pathrunner> show options
pathrunner> set TargetRole arn:aws:iam::123456789012:role/TargetRole
pathrunner> run
```

### CLI Mode

```bash
# Add identity
./pathrunner identity add --profile my-aws-profile

# Create session
./pathrunner session new test-session

# Execute module
./pathrunner use lambda_passrole
./pathrunner set TargetRole arn:aws:iam::123456789012:role/TargetRole
./pathrunner run
```

## Architecture

Pathrunner follows a modular architecture with clear separation of concerns:

### Core Components

- **pkg/core/**: Framework core
  - `repl.go`: Interactive shell with tab completion and command execution
  - `identity.go`: Multi-identity AWS credential management
  - `session.go`: Session persistence with resource tracking

- **pkg/cli/**: Cobra CLI wrapper that maps 1:1 with REPL commands

- **pkg/modules/**: Module system interfaces and registry
  - `interface.go`: Core interfaces (Module, Identity, ResourceTracker)
  - `registry.go`: Dynamic module loading

- **pkg/exploits/**: Exploitation modules
  - `lambda_passrole/`: Lambda privilege escalation with multiple payload types

### Key Design Patterns

- **Dual Interface**: CLI and REPL share identical command handlers
- **Identity Refresh**: Auto-refreshes AWS SSO tokens from stored profile names
- **Resource Tracking**: Modules register created resources for potential cleanup
- **Module Registry**: Self-registering modules using `init()` functions

## Session Management

Sessions are stored as JSON in `~/.pathrunner/sessions/` containing:
- AWS identities with credential configurations
- Command history with timestamps and outputs
- Created resources with cleanup metadata
- Current module state and options

## Extending Pathrunner

Add new modules by:

1. Implement the `Module` interface in `pkg/modules/interface.go`
2. Register in `init()` function: `modules.Register("module_name", &YourModule{})`
3. Add blank import in `cmd/pathrunner/main.go`
4. Track resources via `ResourceTracker.TrackResource()`

## Security Notice

**This tool is designed exclusively for authorized security testing and penetration testing activities.**

Users are responsible for:
- Ensuring proper authorization before testing any AWS infrastructure
- Compliance with all applicable laws and regulations
- Proper handling and disposal of any credentials or sensitive data accessed
- Understanding that unauthorized access to computer systems is illegal

The developers assume no liability for misuse of this tool.