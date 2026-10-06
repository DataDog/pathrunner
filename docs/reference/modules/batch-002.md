# `batch-002` — batch:SubmitJob

|  |  |
|---|---|
| ID | `batch-002` |
| Category | existing-passrole |
| Services | iam, batch |
| Author | Seth Art |
| Aliases | `batch-submitjob`, `exploit/batch_submitjob` |
| pathfinding.cloud | https://pathfinding.cloud/paths/batch-002 |

A principal with only batch:SubmitJob can escalate privileges by submitting a job to an existing Batch job queue using a pre-existing job definition that already has an admin jobRoleArn. The ContainerOverrides.Command field allows the submitter to replace the container's default command with any arbitrary command — including iam:AttachUserPolicy — which executes using the job definition's admin role credentials. No iam:PassRole or batch:RegisterJobDefinition is required because the privileged role was already assigned to the existing job definition.

## Required permissions

- `batch:SubmitJob` — Must be able to submit to the target job queue

## Additional permissions

- `batch:DescribeJobDefinitions` — Helpful for discovering job definitions with privileged jobRoleArns
- `batch:DescribeJobQueues` — Helpful for discovering available job queues
- `batch:DescribeJobs` — Useful for polling job execution status
- `batch:DescribeComputeEnvironments` — Helpful for understanding compute environment configuration

## Prerequisites

**Admin:**
- An existing Batch job definition must already have an admin IAM role set as the jobRoleArn
- An existing Batch job queue must be available to submit jobs to

**Lateral:**
- An existing Batch job definition must have an elevated IAM role set as the jobRoleArn
- An existing Batch job queue must be available

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `JOB_DEFINITION` | yes | — | Name or ARN of the existing Batch job definition with privileged jobRoleArn |
| `JOB_QUEUE` | yes | — | Name or ARN of the Batch job queue to submit the job to |
| `PAYLOAD` | yes | `backdoor/attach-policy` | Payload type to execute inside the Batch job container (backdoor/attach-policy, exfil/https) |
| `CONTAINER_RUNTIME` | no | `aws-cli` | Container entrypoint type: 'aws-cli' (default, container entrypoint is 'aws' — e.g. amazon/aws-cli:latest) or 'generic' (container has sh + aws CLI — e.g. Ubuntu, Debian). exfil/https requires 'generic'. |
| `TARGET_PRINCIPAL` | no | — | IAM username or role name to attach AdministratorAccess to (auto-resolved from caller identity if not set) |
| `REGION` | no | `us-east-1` | AWS region for Batch and IAM operations |
| `CLEANUP` | no | `false` | Detach AdministratorAccess from TARGET_PRINCIPAL after execution. Requires iam:DetachUserPolicy or iam:DetachRolePolicy. |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess (or any managed policy) to an IAM user or role via Batch job container command
- `backdoor/create-access-key` — Create programmatic access keys for an IAM user via Batch job container command
- `backdoor/create-role` — Create an IAM role with AdministratorAccess and a custom trust policy via Batch job (requires CONTAINER_RUNTIME=generic)
- `backdoor/create-user` — Create an IAM user with AdministratorAccess and optional console/programmatic access via Batch job (requires CONTAINER_RUNTIME=generic)
- `backdoor/update-role-trust` — Append a trust policy statement to an existing IAM role via Batch job (requires CONTAINER_RUNTIME=generic with jq)
- `exfil/https` — Exfiltrate Batch task role credentials to an attacker HTTPS endpoint; detects curl/wget/python at runtime (requires CONTAINER_RUNTIME=generic)

## References

- [Pathfinding Cloud - batch-002](https://pathfinding.cloud/paths/batch-002)
- [Messing Around With AWS Batch For Privilege Escalations - Doyensec](https://blog.doyensec.com/2023/06/13/messing-around-with-aws-batch-for-privilege-escalations.html)
- [How AWS Batch works with IAM](https://docs.aws.amazon.com/batch/latest/userguide/security_iam_service-with-iam.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1610 - Deploy Container

