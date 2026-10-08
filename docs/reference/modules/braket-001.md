# `braket-001` — iam:PassRole + braket:CreateJob

|  |  |
|---|---|
| ID | `braket-001` |
| Category | new-passrole |
| Services | iam, braket |
| Author | Seth Art |
| Aliases | `braket-passrole`, `exploit/braket_passrole` |
| pathfinding.cloud | https://pathfinding.cloud/paths/braket-001 |

Create a Braket Hybrid Job with a privileged IAM role as the execution role. The job runs a Python entry-point script from an attacker-controlled S3 bucket; that script uses the job execution role's credentials to attach AdministratorAccess to the starting user.

## Required permissions

- `iam:PassRole` — Must be able to pass the target admin IAM role to braket.amazonaws.com
- `braket:CreateJob`

## Additional permissions

- `braket:GetJob` — Poll job execution status
- `braket:SearchJobs` — Discover existing jobs
- `s3:GetObject` — Read the pre-staged exploit script from S3
- `iam:ListAttachedUserPolicies` — Verify privilege escalation success

## Prerequisites

**Admin:**
- IAM role trusting braket.amazonaws.com with administrative permissions
- S3 bucket accessible by the Braket job for output (attacker code bucket works)

**Lateral:**
- IAM role trusting braket.amazonaws.com with elevated permissions
- S3 bucket accessible by the Braket job for output

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | Target IAM role ARN to pass to the Braket job as jobExecutionRoleArn |
| `PAYLOAD` | yes | — | Payload type to run inside the Braket job (backdoor/attach-policy) |
| `SCRIPT_S3_URI` | no | — | S3 URI of the exploit script (e.g., s3://bucket/prefix/exploit.py). Auto-provisioned if attacker identity is set. |
| `OUTPUT_S3_PATH` | no | — | S3 path for Braket job output (e.g., s3://bucket/braket-output). Defaults to code bucket if unset. |
| `REGION` | no | `us-east-1` | AWS region for Braket job deployment |
| `JOB_NAME` | no | — | Braket job name |
| `CLEANUP` | no | `true` | Clean up created resources after execution (default: true). Note: policy attachment is tracked separately for workspace cleanup. |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess policy to an existing IAM user or role via Braket Hybrid Job

## References

- [Pathfinding Cloud - braket-001](https://pathfinding.cloud/paths/braket-001)
- [Actions defined by Amazon Braket](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonbraket.html)
- [IAM roles for Amazon Braket](https://docs.aws.amazon.com/braket/latest/developerguide/braket-manage-access.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1578 - Modify Cloud Compute Infrastructure

