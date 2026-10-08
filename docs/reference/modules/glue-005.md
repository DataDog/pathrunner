# `glue-005` — iam:PassRole + glue:UpdateJob + glue:StartJobRun

|  |  |
|---|---|
| ID | `glue-005` |
| Category | existing-passrole |
| Services | iam, glue |
| Author | Seth Art |
| Aliases | `glue-updatejob-startjobrun`, `exploit/glue_updatejob_startjobrun` |
| pathfinding.cloud | https://pathfinding.cloud/paths/glue-005 |

Modify an existing Glue job to use a privileged role and a malicious script, then execute it to run code with the role's permissions. Stealthier than creating a new job because it blends with normal ETL maintenance activity.

## Required permissions

- `iam:PassRole` — Must be able to pass a role to glue.amazonaws.com
- `glue:UpdateJob` — Must be able to update existing Glue job configurations
- `glue:StartJobRun` — Must be able to start Glue job runs

## Additional permissions

- `glue:GetJob` — Helpful for retrieving current job configuration before modification
- `glue:ListJobs` — Useful for discovering existing Glue jobs that can be modified
- `glue:GetJobRun` — Helpful for monitoring job execution details
- `iam:ListRoles` — Helpful for discovering available privileged roles to pass

## Prerequisites

**Admin:**
- An existing Glue job must be present in the environment that can be modified
- A role must exist that trusts glue.amazonaws.com and has administrative permissions

**Lateral:**
- An existing Glue job must be present in the environment that can be modified
- A role must exist that trusts glue.amazonaws.com with the desired permissions

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `JOB_NAME` | yes | — | Name of the existing Glue job to modify |
| `ROLE_ARN` | yes | — | Target IAM role ARN to pass to the Glue job (must trust glue.amazonaws.com) |
| `PAYLOAD` | yes | — | Payload type (backdoor/attach-policy, backdoor/create-user, backdoor/create-access-key, exfil/cloudwatch) |
| `SCRIPT_S3_URI` | no | — | S3 URI of the Glue script (e.g., s3://bucket/script.py). Auto-provisioned if attacker identity is set. |
| `REGION` | no | `us-east-1` | AWS region for the Glue job |
| `CLEANUP` | no | `true` | Restore the original job configuration (role and script) after execution |

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

- [Pathfinding Cloud - glue-005](https://pathfinding.cloud/paths/glue-005)
- [HackTricks - AWS Glue Privesc](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-glue-privesc/)
- [Rhino Security Labs - AWS IAM Privilege Escalation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1565.001 - Data Manipulation: Stored Data Manipulation

