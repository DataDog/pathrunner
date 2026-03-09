# Pathrunner

A modular AWS privilege escalation exploitation framework with dual CLI/REPL interfaces.

![pathrunner - demo](https://github.com/user-attachments/assets/1cac76ca-9347-4aa7-b961-0a59bf400b43)

## Features

- **Dual Interface**: Includes a Metasploit style REPL for interactive use and a non-interactive CLI for automation use cases
- **Multi-Identity Management**: Import, use, and switch between multiple AWS identities seamlessly
- **Workspace Persistence**: JSON-based workspace storage with command logging and resource tracking
- **Resource Tracking**: Automatic tracking of created AWS resources with interactive cleanup when permissions allow
- **Auto-Discovery**: Modules automatically enumerate valid option values (roles, subnets, instance profiles) via AWS APIs when permissions allow
- **PMapper Integration**: Import pmapper graph data to see which possible paths you can currently exploit with pathrunner
- **Credential Auto-Import**: When a payload captures new credentials, they're automatically extracted and added to your identity store for continued escalation

### Coverage

Pathrunner currently includes **29 exploit modules** across **4 AWS services** (EC2, IAM, Lambda, STS) with **8 interchangeable payloads** (credential exfiltration, HTTPS exfiltration, backdoor role/user/policy creation, reverse shells). 

## Quick Start

```bash
# Clone and build
git clone https://github.com/your-org/pathrunner.git
cd pathrunner
make build

# Start the interactive shell
./pathrunner

# Add your AWS identity
pathrunner> identity add --profile my-aws-profile

# Browse available modules
pathrunner> search lambda
pathrunner> info lambda-001

# Select and configure a module
pathrunner> use lambda-001
pathrunner> show options
pathrunner> set ROLE_ARN arn:aws:iam::123456789012:role/TargetRole

# Choose a payload and execute
pathrunner> show payloads
pathrunner> set PAYLOAD exfil/response
pathrunner> exploit
```

After a successful exploit that captures credentials, they're auto-extracted and available as a new identity:

```bash
pathrunner> identity list          # New identity appears automatically
pathrunner> identity switch lambda_AB12
pathrunner> pmapper import         # Auto-detects PMapper data directory
pathrunner> pmapper analyze        # See what's next from here
```

Requires Go 1.21+ and valid AWS credentials.

## PMapper Integration

Import [Principal Mapper](https://github.com/nccgroup/PMapper) graph data to identify escalation paths and get actionable next steps:

```bash
pathrunner> pmapper import           # Auto-detects PMapper data directory
pathrunner> pmapper analyze          # Show escalation paths for current identity
pathrunner> pmapper analyze --all    # Show paths for all workspace identities
pathrunner> pmapper status           # Graph metadata and module coverage
```

For each escalation hop, pathrunner shows the matching module and suggested commands to execute it.

## Architecture

```
pkg/
├── core/        # REPL shell, identity management, workspace persistence
├── cli/         # Cobra CLI wrapper (1:1 with REPL commands)
├── modules/     # Module system: interfaces, registry, search/filter
├── payloads/    # Payload registry: tag-based filtering, service subdirectories
├── exploits/    # Exploit modules (29), each embedding BaseModule
├── discovery/   # Reusable AWS enumeration (roles, subnets, streams, etc.)
├── pmapper/     # PMapper graph import, querying, and module mapping
├── utils/       # Credential extraction from env vars, JSON, Python dicts
└── config/      # Application configuration
```

Key design patterns:
- **Dual Interface** — CLI and REPL share identical command handlers via adapter pattern
- **Decoupled Payloads** — Modules query payloads by tags at runtime; payloads self-register via `init()`
- **Workspace Isolation** — Each workspace maintains isolated identities, history, and tracked resources
- **Auto-Refresh** — SSO tokens and profile credentials are rebuilt on-demand

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing requirements, and how to add new modules and payloads.

## Security Notice

**This tool is designed exclusively for authorized security testing and penetration testing activities.**

Users are responsible for:
- Ensuring proper authorization before testing any AWS infrastructure
- Compliance with all applicable laws and regulations
- Proper handling and disposal of any credentials or sensitive data accessed
- Understanding that unauthorized access to computer systems is illegal

The developers assume no liability for misuse of this tool.
