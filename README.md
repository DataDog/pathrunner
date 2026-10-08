<div align="center">

<!--
  HERO BANNER: upload your banner image via the GitHub web UI (drag it into an issue
  or the repo's README editor) and paste the resulting github.com/user-attachments/...
  URL here, matching the pathfinding-labs style:
  <img src="https://github.com/user-attachments/assets/REPLACE-ME" alt="Pathrunner" width="820"/>
-->

# Pathrunner

**A modular AWS privilege escalation exploitation framework with a Metasploit-style REPL, a scriptable CLI, 80+ exploit modules, and interchangeable payloads.**

![Modules](https://img.shields.io/badge/Modules-80%2B-9D4EDD?style=for-the-badge)
![AWS](https://img.shields.io/badge/Cloud-AWS-232F3E?style=for-the-badge)
![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge)

[Quick Start](#quick-start) • [Install](#installation) • [Command Reference ↗](https://pathfinding.cloud/pathrunner) • [Contributing](#contributing)

<!--
  DEMO GIF: the image below is the existing demo. Replace the URL with the GIF
  converted from pathrunner-blog.mp4 when ready (upload it the same way as the banner).
-->
![pathrunner - demo](https://github.com/user-attachments/assets/1cac76ca-9347-4aa7-b961-0a59bf400b43)

---

**Full documentation and command reference:** **[pathfinding.cloud/pathrunner](https://pathfinding.cloud/pathrunner)**

<a href="https://pathfinding.cloud/pathrunner">
  <img width="1133" height="587" alt="pathfinding-cloud-pathrunner2" src="https://github.com/user-attachments/assets/087fb7e6-d410-4911-9c05-891f3eec8905" />
</a>
</div>


## Why pathrunner

Defenders have more misconfigurations than time to fix them. Unlike software CVEs, IAM misconfigurations are hard to triage. How do we know what's actually exploitable versus merely a missing best practice? Pathrunner answers that by *demonstrating* the escalation, so teams can prioritize the paths that are genuinely exploitable and impactful, and build detections for each step along the way.

### Coverage

Pathrunner has 80+ exploit modules across 20+ AWS services (IAM, EC2, Lambda, STS, ECS, Glue, CloudFormation, SSM, Bedrock, and more) with dozens of interchangeable payloads (credential and HTTPS exfiltration, backdoor role/user/policy creation, reverse shells). The authoritative, always-current counts and the full catalog live at **[pathfinding.cloud/pathrunner](https://pathfinding.cloud/pathrunner)**.

## Installation

Requires Go 1.26+ and valid AWS credentials.

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
pathrunner> pmapper analyze        # See what's reachable from here
```

See the [command reference](https://pathfinding.cloud/pathrunner) for every command, module, and payload in detail.




## Key design patterns:
- **Dual Interface** — CLI and REPL share identical command handlers via adapter pattern
- **Decoupled Payloads** — Modules query payloads by tags at runtime; payloads self-register via `init()`
- **Workspace Isolation** — Each workspace maintains isolated identities, history, and tracked resources


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing requirements, and how to add new modules and payloads.

## Security Notice

**This tool is designed exclusively for authorized security testing and penetration testing activities.**

Users are responsible for:
- Ensuring proper authorization before testing any AWS infrastructure
- Compliance with all applicable laws and regulations
- Proper handling and disposal of any credentials or sensitive data accessed
- Understanding that unauthorized access to computer systems is illegal


## Related Projects

**Ecosystem:**
- [pathfinding.cloud](https://pathfinding.cloud) - The source-of-truth library of AWS IAM privilege escalation paths that pathrunner modules implement
- [pathfinding-labs](https://github.com/DataDog/pathfinding-labs) - Terraform lab environments used to deploy and validate pathrunner modules against

**Other tools:**
- [PMapper](https://github.com/nccgroup/PMapper) - AWS IAM privilege escalation analysis; pathrunner can import its graph output
- [CloudFox](https://github.com/BishopFox/cloudfox) - AWS attack surface enumeration; pathrunner can import its output as a resource store
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
