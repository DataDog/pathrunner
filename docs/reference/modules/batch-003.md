# `batch-003` — iam:PassRole + batch:CreateComputeEnvironment + batch:CreateJobQueue + batch:RegisterJobDefinition + batch:SubmitJob

|  |  |
|---|---|
| ID | `batch-003` |
| Category | new-passrole |
| Services | iam, batch |
| Author | Seth Art |
| Aliases | `batch-full-pipeline`, `batch-createcomputeenvironment`, `exploit/batch_passrole_createcomputeenvironment_createjobqueue_registerjobdefinition_submitjob` |
| pathfinding.cloud | https://pathfinding.cloud/paths/batch-003 |

A principal with iam:PassRole and broad Batch permissions can escalate privileges by creating the entire AWS Batch pipeline from scratch — a Fargate compute environment, a job queue, and a job definition that passes an admin IAM role as the jobRoleArn — then submitting a job whose container runs with the admin role's credentials. Unlike batch-001, no pre-existing Batch infrastructure is required. batch:CreateComputeEnvironment auto-creates an ECS cluster via the Batch service-linked role, so the attacker gets ECS task execution capability without any ECS permissions.

## Required permissions

- `iam:PassRole` — Must be able to pass the target admin IAM role and a Batch execution role to the Batch service
- `batch:CreateComputeEnvironment` — Creates a managed Fargate compute environment (auto-creates an ECS cluster via the Batch service-linked role)
- `batch:CreateJobQueue` — Creates a job queue wired to the attacker-created compute environment
- `batch:RegisterJobDefinition` — Registers a job definition with the admin role as jobRoleArn
- `batch:SubmitJob` — Submits the job to the attacker-created queue

## Additional permissions

- `batch:DescribeComputeEnvironments` — Polls compute environment status during creation (CREATING -> VALID)
- `batch:DescribeJobQueues` — Verifies job queue creation and state
- `batch:DescribeJobs` — Polls job execution status to confirm completion
- `batch:DescribeJobDefinitions` — Verifies job definition registration
- `iam:ListAttachedUserPolicies` — Verifies privilege escalation success
- `iam:ListRoles` — Discovers IAM roles to identify passable admin and execution roles
- `ec2:DescribeSubnets` — Discovers available VPC subnets for the Fargate compute environment
- `ec2:DescribeSecurityGroups` — Discovers available security groups for the Fargate compute environment

## Prerequisites

**Admin:**
- A role must exist that trusts ecs-tasks.amazonaws.com and has administrative permissions (e.g., AdministratorAccess)
- An ECS task execution role must exist that trusts ecs-tasks.amazonaws.com with AmazonECSTaskExecutionRolePolicy
- A VPC subnet with internet access (public subnet or NAT gateway) for Fargate tasks
- A security group allowing outbound traffic for container image pulls and API calls

**Lateral:**
- A role must exist that trusts ecs-tasks.amazonaws.com and has elevated permissions
- An ECS task execution role must exist
- A VPC subnet with internet access and an appropriate security group

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ADMIN_ROLE_ARN` | yes | — | ARN of the IAM role to pass as jobRoleArn — the container will run with this role's credentials |
| `EXECUTION_ROLE_ARN` | yes | — | ARN of the Fargate execution role (must trust ecs-tasks.amazonaws.com and have AmazonECSTaskExecutionRolePolicy) |
| `SUBNET_ID` | yes | — | VPC subnet ID for the Fargate compute environment (must have internet access for image pulls and API calls) |
| `SECURITY_GROUP_ID` | yes | — | Security group ID for the Fargate compute environment (must allow outbound traffic) |
| `PAYLOAD` | yes | `backdoor/attach-policy` | Payload type to execute inside the Batch job container. aws-cli runtime: backdoor/attach-policy, backdoor/create-access-key. generic runtime: backdoor/create-user, backdoor/create-role, backdoor/update-role-trust, exfil/https |
| `CONTAINER_RUNTIME` | no | `aws-cli` | Container entrypoint type: 'aws-cli' (default, registers amazon/aws-cli:latest) or 'generic' (registers IMAGE with sh + aws CLI — e.g. Ubuntu, Debian). exfil/https requires 'generic'. |
| `IMAGE` | no | — | Container image to use in the registered job definition. Defaults to 'amazon/aws-cli:latest' for aws-cli runtime, or 'ubuntu:latest' for generic runtime. The image must be accessible from the Fargate compute environment. |
| `TARGET_PRINCIPAL` | no | — | IAM username or role name to attach AdministratorAccess to (auto-resolved from caller identity if not set) |
| `COMPUTE_ENV_NAME` | no | — | Name for the new Batch compute environment to create |
| `JOB_QUEUE_NAME` | no | — | Name for the new Batch job queue to create |
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

- [Pathfinding Cloud - batch-003](https://pathfinding.cloud/paths/batch-003)
- [Messing Around With AWS Batch For Privilege Escalations - Doyensec](https://blog.doyensec.com/2023/06/13/messing-around-with-aws-batch-for-privilege-escalations.html)
- [How AWS Batch works with IAM](https://docs.aws.amazon.com/batch/latest/userguide/security_iam_service-with-iam.html)
- [Actions defined by AWS Batch - Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsbatch.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1610 - Deploy Container

