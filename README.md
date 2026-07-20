# Pathrunner

A modular AWS privilege escalation exploitation framework with dual CLI/REPL interfaces.

![pathrunner - demo](https://github.com/user-attachments/assets/1cac76ca-9347-4aa7-b961-0a59bf400b43)

## Overview

Pathrunner automates exploitation of AWS IAM privilege escalation paths. It's the execution layer of a three-project ecosystem:

```
pathfinding.cloud (path definitions) → pathfinding-labs (deployable labs) → pathrunner (automated exploitation)
```

- **[pathfinding.cloud](https://pathfinding.cloud)** documents each privilege escalation path (prerequisites, permissions, manual exploitation steps)
- **[pathfinding-labs](https://github.com/DataDog/pathfinding-labs)** deploys the vulnerable AWS infrastructure to practice against
- **pathrunner** (this project) automates the exploitation itself, chaining modules and payloads to escalate from an initial identity to elevated access

Modules reference a pathfinding.cloud path ID when they implement a documented path, and are validated against deployed pathfinding-labs scenarios.

## Features

- **Dual Interface**: Includes a Metasploit style REPL for interactive use and a non-interactive CLI for automation use cases
- **Multi-Identity Management**: Import, use, and switch between multiple AWS identities seamlessly
- **Workspace Persistence**: JSON-based workspace storage with command logging and resource tracking
- **Resource Tracking**: Automatic tracking of created AWS resources with interactive cleanup when permissions allow
- **Auto-Discovery**: Modules automatically enumerate valid option values (roles, subnets, instance profiles) via AWS APIs when permissions allow
- **PMapper Integration**: Import pmapper graph data to see which possible paths you can currently exploit with pathrunner
- **Credential Auto-Import**: When a payload captures new credentials, they're automatically extracted and added to your identity store for continued escalation

### Coverage

Pathrunner currently includes **83 exploit modules** across **22 AWS services** (IAM, EC2, Lambda, STS, ECS, Glue, CloudFormation, SSM, and more) with **37 interchangeable payloads** (credential exfiltration, HTTPS exfiltration, backdoor role/user/policy creation, reverse shells).

## Installation

Requires Go 1.25+ and valid AWS credentials.

#### Direct Install
```bash
go install github.com/DataDog/pathrunner/cmd/pathrunner@latest
```

#### Homebrew
```bash
brew tap DataDog/pathrunner https://github.com/DataDog/pathrunner
brew install DataDog/pathrunner/pathrunner
```

#### Download from GitHub Releases
```bash
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | sed 's/x86_64/amd64/')
VERSION=$(curl -fsSL https://api.github.com/repos/DataDog/pathrunner/releases/latest | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v')
curl -fsSL "https://github.com/DataDog/pathrunner/releases/download/v${VERSION}/pathrunner_${VERSION}_${OS}_${ARCH}.tar.gz" | tar -xz pathrunner
sudo mv pathrunner /usr/local/bin/
```

#### Build from source
```bash
git clone https://github.com/DataDog/pathrunner.git
cd pathrunner
make build
cp pathrunner /usr/local/bin/
```

## Quick Start

```bash
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
├── exploits/    # Exploit modules (83), each embedding BaseModule
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

## Related Projects

**Ecosystem:**
- [pathfinding.cloud](https://pathfinding.cloud) - The source-of-truth library of AWS IAM privilege escalation paths that pathrunner modules implement
- [pathfinding-labs](https://github.com/DataDog/pathfinding-labs) - Terraform lab environments used to deploy and validate pathrunner modules against

**Other tools:**
- [PMapper](https://github.com/nccgroup/PMapper) - AWS IAM privilege escalation analysis; pathrunner can import its graph output
- [Pacu](https://github.com/RhinoSecurityLabs/pacu) - AWS exploitation framework
- [Stratus Red Team](https://github.com/DataDog/stratus-red-team) - Adversary emulation for cloud, by Datadog

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contact

- **Issues**: Open an issue in this repository
- **Discussions**: Use GitHub Discussions for questions
- **Security**: For security concerns about this repository, please open a private security advisory

---

**Maintained by Seth Art from Datadog**
