# `codebuild-002` — codebuild:StartBuild (buildspec-override)

|  |  |
|---|---|
| ID | `codebuild-002` |
| Category | existing-passrole |
| Services | codebuild, iam |
| Author | Seth Art |
| Aliases | `codebuild-startbuild`, `exploit/codebuild_startbuild` |
| pathfinding.cloud | https://pathfinding.cloud/paths/codebuild-002 |

Start a build on an existing CodeBuild project using --buildspec-override to inject malicious commands that execute with the project's privileged service role. Does not require iam:PassRole or codebuild:CreateProject.

## Required permissions

- `codebuild:StartBuild` — Must have permission to start builds on the target CodeBuild project

## Additional permissions

- `codebuild:ListProjects` — Helpful for discovering existing CodeBuild projects with privileged roles
- `codebuild:BatchGetProjects` — Useful for viewing project details including service role ARN
- `codebuild:BatchGetBuilds` — Helpful for monitoring build execution status and verifying success

## Prerequisites

**Admin:**
- A CodeBuild project must already exist in the account
- The existing project must have a service role with administrative permissions
- The project must allow buildspec overrides (default behavior unless explicitly disabled)

**Lateral:**
- A CodeBuild project must already exist in the account
- The existing project must have a service role with any level of permissions
- The project must allow buildspec overrides (default behavior unless explicitly disabled)

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `PROJECT_NAME` | yes | — | Name of the existing CodeBuild project to exploit |
| `PAYLOAD` | yes | — | Payload type (backdoor/attach-policy) |
| `TARGET_ARN` | no | — | IAM user or role name/ARN to attach AdministratorAccess to (auto-resolved from caller identity if not set) |
| `REGION` | no | `us-east-1` | AWS region |
| `CLEANUP` | no | `false` | Clean up tracked side effects after execution (the payload's IAM change is the goal; default false) |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess (or any managed policy) to an IAM user or role via CodeBuild buildspec

## References

- [Pathfinding Cloud - codebuild-002](https://pathfinding.cloud/paths/codebuild-002)
- [HackTricks - AWS CodeBuild Privesc](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-codebuild-privesc/index.html)
- [PMapper CodeBuild Edges](https://github.com/nccgroup/PMapper/blob/91d2e60102bdadf346d77b60d90ddaa4a678f037/principalmapper/graphing/codebuild_edges.py#L165-L173)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1651 - Cloud Administration Command

