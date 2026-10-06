# `glue-004` — iam:PassRole + glue:CreateJob + glue:CreateTrigger

|  |  |
|---|---|
| ID | `glue-004` |
| Category | new-passrole |
| Services | iam, glue |
| Author | Seth Art |
| Aliases | `glue-passrole-job-createtrigger`, `exploit/glue_passrole_job_createtrigger` |
| pathfinding.cloud | https://pathfinding.cloud/paths/glue-004 |

Create a Glue Python Shell job with a privileged role, then create a scheduled trigger with --start-on-creation to execute the job automatically. Unlike glue:StartJobRun, this approach establishes a persistent scheduled backdoor: the trigger fires every minute and re-executes the payload even after manual remediation attempts.

## Required permissions

- `iam:PassRole` — Must be able to pass a role to glue.amazonaws.com
- `glue:CreateJob`
- `glue:CreateTrigger` — Create trigger with --start-on-creation flag

## Additional permissions

- `glue:GetJob` — Retrieve job details and verify configuration
- `glue:GetTrigger` — Monitor trigger state and activation status
- `glue:GetJobRun` — Monitor job execution details
- `glue:GetJobRuns` — List job runs to track execution history

## Prerequisites

**Admin:**
- IAM role with administrative permissions and trust policy allowing glue.amazonaws.com

**Lateral:**
- Principal with iam:PassRole, glue:CreateJob, glue:CreateTrigger
- S3 bucket accessible to the victim account containing the Glue script (attacker account auto-provisions this)

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | Target IAM role ARN to pass to the Glue job (must trust glue.amazonaws.com) |
| `PAYLOAD` | yes | — | Payload type (backdoor/attach-policy, backdoor/create-user, backdoor/create-access-key, exfil/cloudwatch) |
| `SCRIPT_S3_URI` | no | — | S3 URI of the Glue script (e.g., s3://bucket/script.py). Auto-provisioned if attacker identity is set. |
| `REGION` | no | `us-east-1` | AWS region for Glue job and trigger deployment |
| `JOB_NAME` | no | — | Glue job name (auto-generated if empty) |
| `TRIGGER_NAME` | no | — | Glue trigger name (auto-generated if empty) |
| `CLEANUP` | no | `true` | Stop and delete the trigger and job after the first run completes |

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

- [Pathfinding Cloud - glue-004](https://pathfinding.cloud/paths/glue-004)
- [HackTricks - AWS Glue Privesc](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-glue-privesc/index.html)
- [Rhino Security Labs - CloudGoat Glue privesc Walkthrough](https://rhinosecuritylabs.com/cloud-security/cloudgoat-walkthrough-glue_privesc/)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0003 - Persistence
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1053 - Scheduled Task/Job

