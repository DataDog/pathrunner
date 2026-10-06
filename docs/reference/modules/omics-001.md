# `omics-001` — iam:PassRole + omics:CreateWorkflow + omics:StartRun

|  |  |
|---|---|
| ID | `omics-001` |
| Category | new-passrole |
| Services | iam, omics, s3 |
| Author | Seth Art |
| Aliases | `omics-passrole`, `exploit/omics_passrole` |
| pathfinding.cloud | https://pathfinding.cloud/paths/omics-001 |

Create an AWS HealthOmics WDL workflow that exfiltrates the execution role's temporary credentials to an attacker-controlled S3 bucket. The module starts a run passing an admin role via iam:PassRole, waits for completion, retrieves the exfiltrated credentials from S3, and uses them to attach AdministratorAccess to the starting user. HealthOmics tasks have network isolation from the public internet but retain S3 access.

## Required permissions

- `iam:PassRole` — Must be able to pass the target admin IAM execution role to the HealthOmics service
- `omics:CreateWorkflow`
- `omics:StartRun`
- `s3:GetObject` — Read exfiltrated credentials from the attacker-controlled S3 bucket after the workflow completes

## Additional permissions

- `omics:GetWorkflow` — Poll workflow creation status
- `omics:GetRun` — Monitor run status and verify completion
- `omics:ListRuns` — Discover existing runs
- `iam:ListAttachedUserPolicies` — Verify privilege escalation success

## Prerequisites

**Admin:**
- A role must exist that trusts omics.amazonaws.com with administrative permissions
- An attacker-controlled S3 bucket must be accessible from HealthOmics (execution role needs s3:PutObject)
- A private ECR repository must contain a container image suitable for running AWS CLI commands (HealthOmics requires private ECR images)

**Lateral:**
- A role must exist that trusts omics.amazonaws.com with elevated permissions
- An attacker-controlled S3 bucket accessible from HealthOmics execution environment

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | Target IAM role ARN to pass to the HealthOmics workflow run as the execution role |
| `CONTAINER_URI` | yes | — | Private ECR image URI for the WDL task container (e.g., 123456789012.dkr.ecr.us-east-1.amazonaws.com/aws-cli:latest). HealthOmics does not support public Docker Hub images. |
| `EXFIL_BUCKET` | no | — | Attacker-controlled S3 bucket for credential exfiltration. Auto-populated from attacker infra if not set. The execution role must have s3:PutObject on this bucket. |
| `EXFIL_KEY` | no | `exfil/creds.json` | S3 object key for the exfiltrated credentials |
| `TARGET_ARN` | no | — | IAM user or role name/ARN to attach AdministratorAccess to (auto-resolved from caller identity if not set) |
| `REGION` | no | `us-east-1` | AWS region for HealthOmics workflow deployment |
| `WORKFLOW_NAME` | no | — | Name for the HealthOmics workflow |
| `CLEANUP` | no | `true` | Delete the HealthOmics workflow and run after execution. Note: policy attachment is tracked separately via workspace cleanup. |

## References

- [Pathfinding Cloud - omics-001](https://pathfinding.cloud/paths/omics-001)
- [Actions defined by AWS HealthOmics](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awshealthomics.html)
- [IAM roles and policies for AWS HealthOmics](https://docs.aws.amazon.com/omics/latest/dev/security-iam-roles.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1578 - Modify Cloud Compute Infrastructure

