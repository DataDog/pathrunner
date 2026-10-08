# `glue-006` — iam:PassRole + glue:UpdateJob + glue:CreateTrigger

|  |  |
|---|---|
| ID | `glue-006` |
| Category | new-passrole |
| Services | iam, glue |
| Author | Seth Art |
| Aliases | `glue-updatejob-createtrigger`, `exploit/glue_updatejob_createtrigger` |
| pathfinding.cloud | https://pathfinding.cloud/paths/glue-006 |

Update an existing Glue job to use a privileged role and malicious script, then create a scheduled trigger with --start-on-creation to execute the job automatically. Unlike glue:CreateJob which creates new resources, this path modifies existing infrastructure for stealth, and the scheduled trigger provides persistence — it re-executes the job every minute, re-granting access even after manual remediation attempts.

## Required permissions

- `iam:PassRole` — Must be able to pass a role to glue.amazonaws.com
- `glue:UpdateJob` — Must be able to update existing Glue job configurations
- `glue:CreateTrigger` — Must be able to create Glue triggers with --start-on-creation flag

## Additional permissions

- `glue:GetJob` — Retrieve current job configuration before modification
- `glue:ListJobs` — Discover existing Glue jobs that can be modified
- `glue:GetTrigger` — Monitor trigger state and activation status
- `glue:GetJobRun` — Monitor job execution details
- `glue:GetJobRuns` — List job runs to track execution history
- `iam:ListRoles` — Discover available privileged roles to pass

## Prerequisites

**Admin:**
- An existing Glue job must be present in the environment that can be modified
- IAM role with administrative permissions and trust policy allowing glue.amazonaws.com

**Lateral:**
- Principal with iam:PassRole, glue:UpdateJob, glue:CreateTrigger
- An existing Glue job that can be modified
- S3 bucket accessible to the victim account containing the Glue script (attacker account auto-provisions this)

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | Target IAM role ARN to pass to the Glue job (must trust glue.amazonaws.com) |
| `JOB_NAME` | yes | — | Name of the existing Glue job to update (required; use 'discover JOB_NAME' to list available jobs) |
| `PAYLOAD` | yes | — | Payload type (backdoor/attach-policy, backdoor/create-user, backdoor/create-access-key, exfil/cloudwatch) |
| `SCRIPT_S3_URI` | no | — | S3 URI of the Glue script (e.g., s3://bucket/script.py). Auto-provisioned if attacker identity is set. |
| `REGION` | no | `us-east-1` | AWS region for Glue job and trigger operations |
| `TRIGGER_NAME` | no | — | Glue trigger name (auto-generated if empty) |
| `CLEANUP` | no | `true` | Stop and delete the trigger and restore the job to its original configuration after the first run completes |

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

- [Pathfinding Cloud - glue-006](https://pathfinding.cloud/paths/glue-006)
- [HackTricks - AWS Glue Privesc](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-glue-privesc/index.html)
- [Rhino Security Labs - CloudGoat Glue privesc Walkthrough](https://rhinosecuritylabs.com/cloud-security/cloudgoat-walkthrough-glue_privesc/)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0003 - Persistence
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1053 - Scheduled Task/Job, T1565.001 - Data Manipulation: Stored Data Manipulation

