# `glue-007` — iam:PassRole + glue:CreateSession + glue:RunStatement

|  |  |
|---|---|
| ID | `glue-007` |
| Category | new-passrole |
| Services | iam, glue |
| Author | Seth Art |
| Aliases | `glue-passrole-createsession`, `exploit/glue_passrole_createsession` |
| pathfinding.cloud | https://pathfinding.cloud/paths/glue-007 |

Create a Glue Interactive Session with a privileged role passed via iam:PassRole, then run inline Python via glue:RunStatement. The boto3 client in the session automatically uses the passed role's credentials — no S3 script or job definition required.

## Required permissions

- `iam:PassRole` — Target admin IAM role ARN
- `glue:CreateSession`
- `glue:RunStatement`

## Additional permissions

- `glue:GetSession` — Poll session status until READY
- `glue:GetStatement` — Poll statement status until AVAILABLE
- `glue:DeleteSession` — Clean up the interactive session
- `iam:ListAttachedUserPolicies` — Verify privilege escalation success

## Prerequisites

**Admin:**
- IAM role with administrative permissions and trust policy allowing glue.amazonaws.com

**Lateral:**
- IAM role trusting glue.amazonaws.com with elevated permissions

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | IAM role ARN to pass to the Glue Interactive Session (must trust glue.amazonaws.com) |
| `PAYLOAD` | yes | — | Payload type (backdoor/attach-policy, backdoor/create-user, backdoor/create-access-key, exfil/cloudwatch) |
| `REGION` | no | `us-east-1` | AWS region for the Glue Interactive Session |
| `SESSION_ID` | no | — | Glue Interactive Session ID (auto-generated if not set) |
| `CLEANUP` | no | `true` | Delete the Glue Interactive Session after execution (requires glue:DeleteSession) |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess policy to an existing IAM user or role via Glue job
- `backdoor/create-access-key` — Create new access keys for an existing IAM user via Glue job
- `backdoor/create-role` — Create an IAM role with administrator privileges and a custom trust policy via Glue job
- `backdoor/create-user` — Create an IAM user with administrator privileges and access keys via Glue job
- `backdoor/update-role-trust` — Update a role's trust policy to add a trusted principal via Glue job
- `exfil/cloudwatch` — Extract execution role credentials and print to CloudWatch Logs via Glue job
- `exfil/https` — Exfiltrate execution role credentials to an attacker-controlled HTTPS endpoint via Glue job
- `exfil/s3` — Exfiltrate execution role credentials to an attacker-controlled S3 bucket via Glue job
- `revshell/tls` — Establish a TLS-encrypted reverse shell to the attacker listener's shell port via Glue job

## References

- [Pathfinding Cloud - glue-007](https://pathfinding.cloud/paths/glue-007)
- [Interactive sessions with IAM - AWS Glue](https://docs.aws.amazon.com/glue/latest/dg/glue-is-security.html)
- [Getting started with AWS Glue interactive sessions](https://docs.aws.amazon.com/glue/latest/dg/interactive-sessions.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation
- **Techniques:** T1098 - Account Manipulation

