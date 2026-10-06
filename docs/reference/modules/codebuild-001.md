# `codebuild-001` — iam:PassRole + codebuild:CreateProject + codebuild:StartBuild

|  |  |
|---|---|
| ID | `codebuild-001` |
| Category | new-passrole |
| Services | iam, codebuild |
| Author | Seth Art |
| Aliases | `codebuild-passrole`, `exploit/codebuild_passrole` |
| pathfinding.cloud | https://pathfinding.cloud/paths/codebuild-001 |

Create a CodeBuild project with a privileged role and execute an inline buildspec to run code with the role's permissions. The buildspec runs with full access to the service role credentials, allowing privilege escalation by attaching policies to IAM principals.

## Required permissions

- `iam:PassRole` — Target role ARN must trust codebuild.amazonaws.com
- `codebuild:CreateProject`
- `codebuild:StartBuild`

## Additional permissions

- `iam:ListRoles` — Discover roles trusting CodeBuild for auto-discovery
- `codebuild:BatchGetBuilds` — Poll build completion status
- `codebuild:DeleteProject` — Clean up created project (gained after escalation)

## Prerequisites

**Admin:**
- IAM role with desired permissions and trust policy allowing codebuild.amazonaws.com
- The role must trust codebuild.amazonaws.com as a service principal

**Lateral:**
- Principal with iam:PassRole, codebuild:CreateProject, codebuild:StartBuild

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | Target IAM role ARN to pass to the CodeBuild project (must trust codebuild.amazonaws.com) |
| `PAYLOAD` | yes | — | Payload type (backdoor/attach-policy) |
| `TARGET_ARN` | no | — | IAM user or role name/ARN to attach AdministratorAccess to (auto-resolved from caller identity if not set) |
| `REGION` | no | `us-east-1` | AWS region for CodeBuild project deployment |
| `PROJECT_NAME` | no | — | Name of the CodeBuild project to create |
| `CLEANUP` | no | `true` | Delete the CodeBuild project after execution (uses escalated privileges gained by the payload) |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess (or any managed policy) to an IAM user or role via CodeBuild buildspec

## References

- [Pathfinding Cloud - codebuild-001](https://pathfinding.cloud/paths/codebuild-001)
- [HackTricks - AWS CodeBuild Privesc](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-codebuild-privesc/index.html)
- [PMapper - CodeBuild Edges](https://github.com/nccgroup/PMapper/blob/91d2e60102bdadf346d77b60d90ddaa4a678f037/principalmapper/graphing/codebuild_edges.py#L216)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1651 - Cloud Administration Command

