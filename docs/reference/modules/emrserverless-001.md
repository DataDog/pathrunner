# `emrserverless-001` — iam:PassRole + emr-serverless:CreateApplication + emr-serverless:StartJobRun

|  |  |
|---|---|
| ID | `emrserverless-001` |
| Category | new-passrole |
| Services | iam, emrserverless |
| Author | Seth Art |
| Aliases | `emrserverless-passrole`, `exploit/emrserverless_passrole` |
| pathfinding.cloud | https://pathfinding.cloud/paths/emrserverless-001 |

A principal with iam:PassRole, emr-serverless:CreateApplication, and emr-serverless:StartJobRun can escalate privileges by creating an EMR Serverless Spark application and starting a job run that passes an admin IAM execution role. The Spark job exfiltrates the execution role's credentials to S3 (IAM is not reachable without a VPC), and the module uses those credentials to attach AdministratorAccess to the starting user.

## Required permissions

- `iam:PassRole` — Must be able to pass the target admin IAM role to emr-serverless.amazonaws.com
- `emr-serverless:CreateApplication`
- `emr-serverless:StartJobRun`

## Additional permissions

- `emr-serverless:GetApplication` — Poll application state before starting job run
- `emr-serverless:GetJobRun` — Monitor job run status and verify completion
- `emr-serverless:ListApplications` — Discover existing applications
- `iam:ListAttachedUserPolicies` — Verify privilege escalation success

## Prerequisites

**Admin:**
- IAM role trusting emr-serverless.amazonaws.com with administrative permissions
- AWS EMR Serverless service-linked role (AWSServiceRoleForAmazonEMRServerless) must exist in the account
- S3 bucket accessible by the execution role for script hosting and credential exfil

**Lateral:**
- IAM role trusting emr-serverless.amazonaws.com with elevated permissions
- S3 bucket accessible by the execution role for script hosting

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `EXECUTION_ROLE_ARN` | yes | — | IAM role ARN to pass as the EMR Serverless job execution role (must trust emr-serverless.amazonaws.com) |
| `BUCKET` | no | — | S3 bucket for hosting the exploit script and receiving exfiltrated credentials. Must be readable and writable by the execution role. If not set, uses attacker code bucket for script and attacker exfil bucket for credentials. |
| `BUCKET_REGION` | no | — | AWS region of BUCKET (defaults to REGION if not set) |
| `TARGET_ARN` | no | — | IAM user or role name/ARN to attach AdministratorAccess to (auto-resolved from caller identity if not set) |
| `REGION` | no | `us-east-1` | AWS region for EMR Serverless (defaults to us-east-1) |
| `APP_NAME` | no | — | Name for the EMR Serverless application (auto-generated if not set) |
| `CLEANUP` | no | `false` | Stop and delete the EMR Serverless application after execution. Default false because the starting user typically lacks emr-serverless:DeleteApplication. |

## References

- [Pathfinding Cloud - emrserverless-001](https://pathfinding.cloud/paths/emrserverless-001)
- [Actions defined by Amazon EMR Serverless](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonemrserverless.html)
- [IAM roles for EMR Serverless](https://docs.aws.amazon.com/emr/latest/EMR-Serverless-UserGuide/security-iam-role.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1578 - Modify Cloud Compute Infrastructure

