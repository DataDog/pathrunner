# `batch-001` — iam:PassRole + batch:RegisterJobDefinition + batch:SubmitJob

|  |  |
|---|---|
| ID | `batch-001` |
| Category | new-passrole |
| Services | iam, batch |
| Author | Seth Art |
| Aliases | `batch-passrole`, `batch-passrole-registerjobdefinition`, `exploit/batch_passrole_registerjobdefinition_submitjob` |
| pathfinding.cloud | https://pathfinding.cloud/paths/batch-001 |

A principal with iam:PassRole, batch:RegisterJobDefinition, and batch:SubmitJob can escalate privileges by registering a new AWS Batch job definition that passes an admin IAM role as the jobRoleArn, then submitting a job that overrides the container command to call iam:AttachUserPolicy, attaching AdministratorAccess to the starting user. The Fargate container runs with the admin role's credentials and performs the IAM escalation.

## Required permissions

- `iam:PassRole` — Must be able to pass the target admin IAM role and a Batch execution role to the Batch service
- `batch:RegisterJobDefinition` — No resource constraints required
- `batch:SubmitJob` — No resource constraints required

## Additional permissions

- `batch:DescribeJobs` — Useful for polling job status to confirm execution
- `batch:DescribeJobQueues` — Helpful for discovering available job queues to submit to
- `batch:DescribeComputeEnvironments` — Helpful for discovering available compute environments
- `batch:DeregisterJobDefinition` — Useful for cleaning up the malicious job definition after exploitation
- `iam:ListAttachedUserPolicies` — Useful for verifying privilege escalation success

## Prerequisites

**Admin:**
- A role must exist that trusts batch.amazonaws.com to assume it (or can be assumed via the Batch Fargate execution chain)
- The role must have administrative permissions (e.g., AdministratorAccess or an equivalent custom policy)
- An existing Batch job queue and compute environment must be available in the account

**Lateral:**
- A role must exist that trusts the Batch service and has elevated permissions
- An existing Batch job queue and compute environment must be available in the account

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ADMIN_ROLE_ARN` | yes | — | ARN of the IAM role to pass as jobRoleArn — the container will run with this role's credentials |
| `EXECUTION_ROLE_ARN` | yes | — | ARN of the Fargate execution role (must trust batch.amazonaws.com and have ecr/logs permissions) |
| `JOB_QUEUE` | yes | — | Name or ARN of the Batch job queue to submit the job to |
| `PAYLOAD` | yes | `backdoor/attach-policy` | Payload type to execute inside the Batch job container. aws-cli runtime: backdoor/attach-policy, backdoor/create-access-key. generic runtime: backdoor/create-user, backdoor/create-role, backdoor/update-role-trust, exfil/https |
| `CONTAINER_RUNTIME` | no | `aws-cli` | Container entrypoint type: 'aws-cli' (default, registers amazon/aws-cli:latest) or 'generic' (registers IMAGE with sh + aws CLI — e.g. Ubuntu, Debian). exfil/https requires 'generic'. |
| `IMAGE` | no | — | Container image to use in the registered job definition. Defaults to 'amazon/aws-cli:latest' for aws-cli runtime, or 'ubuntu:latest' for generic runtime. The image must be accessible from the Fargate compute environment. |
| `TARGET_PRINCIPAL` | no | — | IAM username or role name to attach AdministratorAccess to (auto-resolved from caller identity if not set) |
| `JOB_DEF_NAME` | no | — | Name for the new Batch job definition to register |
| `REGION` | no | `us-east-1` | AWS region for Batch and IAM operations |
| `CLEANUP` | no | `false` | Deregister the job definition and detach AdministratorAccess from TARGET_PRINCIPAL after execution. Requires batch:DeregisterJobDefinition and iam:DetachUserPolicy/iam:DetachRolePolicy. Defaults to false because the lab's starting principal does not have these permissions; use 'workspace cleanup' with an elevated identity instead. |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess (or any managed policy) to an IAM user or role via Batch job container command
- `backdoor/create-access-key` — Create programmatic access keys for an IAM user via Batch job container command
- `backdoor/create-role` — Create an IAM role with AdministratorAccess and a custom trust policy via Batch job (requires CONTAINER_RUNTIME=generic)
- `backdoor/create-user` — Create an IAM user with AdministratorAccess and optional console/programmatic access via Batch job (requires CONTAINER_RUNTIME=generic)
- `backdoor/update-role-trust` — Append a trust policy statement to an existing IAM role via Batch job (requires CONTAINER_RUNTIME=generic with jq)
- `exfil/https` — Exfiltrate Batch task role credentials to an attacker HTTPS endpoint; detects curl/wget/python at runtime (requires CONTAINER_RUNTIME=generic)

## References

- [Pathfinding Cloud - batch-001](https://pathfinding.cloud/paths/batch-001)
- [Messing Around With AWS Batch For Privilege Escalations - Doyensec](https://blog.doyensec.com/2023/06/13/messing-around-with-aws-batch-for-privilege-escalations.html)
- [How AWS Batch works with IAM](https://docs.aws.amazon.com/batch/latest/userguide/security_iam_service-with-iam.html)
- [Actions defined by AWS Batch - Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsbatch.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1610 - Deploy Container

