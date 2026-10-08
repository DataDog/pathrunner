# `glue-003` — iam:PassRole + glue:CreateJob + glue:StartJobRun

|  |  |
|---|---|
| ID | `glue-003` |
| Category | new-passrole |
| Services | iam, glue |
| Author | Seth Art |
| Aliases | `glue-passrole-job`, `exploit/glue_passrole_job` |
| pathfinding.cloud | https://pathfinding.cloud/paths/glue-003 |

Create a Glue Python Shell job with a privileged role, run it to execute code with the role's permissions

## Required permissions

- `iam:PassRole` — Target role ARN
- `glue:CreateJob`
- `glue:StartJobRun`

## Additional permissions

- `glue:GetJobRun` — Monitor job execution status
- `glue:GetJob` — Verify job configuration

## Prerequisites

**Admin:**
- IAM role with desired permissions and trust policy allowing glue.amazonaws.com

**Lateral:**
- Principal with iam:PassRole, glue:CreateJob, glue:StartJobRun
- S3 bucket accessible to the victim account containing the Glue script (attacker account auto-provisions this)

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | Target IAM role ARN to pass to the Glue job |
| `PAYLOAD` | yes | — | Payload type (backdoor/attach-policy, backdoor/create-user, backdoor/create-access-key, exfil/cloudwatch) |
| `SCRIPT_S3_URI` | no | — | S3 URI of the Glue script (e.g., s3://bucket/script.py). Auto-provisioned if attacker identity is set. |
| `REGION` | no | `us-east-1` | AWS region for Glue job deployment |
| `JOB_NAME` | no | — | Glue job name |
| `CLEANUP` | no | `true` | Clean up created resources after execution |

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

- [Pathfinding Cloud - glue-003](https://pathfinding.cloud/paths/glue-003)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts

