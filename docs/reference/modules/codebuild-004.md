# `codebuild-004` — iam:PassRole + codebuild:CreateProject + codebuild:StartBuildBatch

|  |  |
|---|---|
| ID | `codebuild-004` |
| Category | new-passrole |
| Services | iam, codebuild |
| Author | Seth Art |
| Aliases | `codebuild-passrole-startbuildbatch`, `exploit/codebuild_passrole_startbuildbatch` |
| pathfinding.cloud | https://pathfinding.cloud/paths/codebuild-004 |

Create a CodeBuild project configured for batch builds with a privileged role, then start a build batch to execute malicious buildspec commands with that role's permissions. This variation uses codebuild:StartBuildBatch instead of codebuild:StartBuild.

## Required permissions

- `iam:PassRole` — Target role ARN must trust codebuild.amazonaws.com
- `codebuild:CreateProject`
- `codebuild:StartBuildBatch`

## Additional permissions

- `iam:ListRoles` — Discover roles trusting CodeBuild for auto-discovery
- `codebuild:BatchGetBuildBatches` — Poll build batch completion status
- `codebuild:DeleteProject` — Clean up created project (gained after escalation)

## Prerequisites

**Admin:**
- IAM role with administrative permissions and trust policy allowing codebuild.amazonaws.com

**Lateral:**
- IAM role with any permissions and trust policy allowing codebuild.amazonaws.com

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | Target IAM role ARN to pass to the CodeBuild project (must trust codebuild.amazonaws.com) [auto] |
| `PAYLOAD` | yes | — | Payload type (backdoor/attach-policy) |
| `TARGET_ARN` | no | — | IAM user or role name/ARN to attach AdministratorAccess to (auto-resolved from caller identity if not set) |
| `REGION` | no | `us-east-1` | AWS region for CodeBuild project deployment |
| `PROJECT_NAME` | no | — | Name of the CodeBuild project to create |
| `CLEANUP` | no | `true` | Delete the CodeBuild project after execution (uses escalated privileges gained by the payload) |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess (or any managed policy) to an IAM user or role via CodeBuild buildspec

## References

- [Pathfinding Cloud - codebuild-004](https://pathfinding.cloud/paths/codebuild-004)
- [HackTricks - AWS CodeBuild Privesc (StartBuildBatch)](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-codebuild-privesc/index.html#codebuildstartbuild--codebuildstartbuildbatch)
- [PMapper - CodeBuild Edges](https://github.com/nccgroup/PMapper/blob/91d2e60102bdadf346d77b60d90ddaa4a678f037/principalmapper/graphing/codebuild_edges.py#L186)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1651 - Cloud Administration Command

