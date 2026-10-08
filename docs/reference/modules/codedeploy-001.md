# `codedeploy-001` — codedeploy:CreateDeployment

|  |  |
|---|---|
| ID | `codedeploy-001` |
| Category | existing-passrole |
| Services | iam, codedeploy, ec2 |
| Author | Seth Art |
| Aliases | `codedeploy-createdeployment`, `exploit/codedeploy_createdeployment` |
| pathfinding.cloud | https://pathfinding.cloud/paths/codedeploy-001 |

A principal with codedeploy:CreateDeployment and codedeploy:RegisterApplicationRevision can escalate privileges by deploying a malicious revision to an existing CodeDeploy deployment group that targets EC2 instances already configured with an admin IAM instance profile. The revision's BeforeInstall lifecycle hook runs a shell script on the target EC2 instance; because the instance already has the admin instance profile attached, the script runs with admin credentials and calls iam:AttachUserPolicy to attach AdministratorAccess to the starting user. No iam:PassRole is required — the privileged instance profile was already assigned to the existing EC2 instance.

## Required permissions

- `codedeploy:CreateDeployment` — Must have access to the target CodeDeploy application and deployment group
- `codedeploy:RegisterApplicationRevision` — Must be able to register a new revision in the target S3 bucket
- `codedeploy:GetDeploymentConfig` — Required to resolve the deployment configuration when creating a deployment

## Additional permissions

- `codedeploy:GetDeployment` — Useful for monitoring deployment status to know when lifecycle hooks have executed
- `codedeploy:ListDeployments` — Helpful for discovering existing deployments
- `codedeploy:GetDeploymentGroup` — Useful for viewing deployment group configuration and target EC2 instances
- `codedeploy:GetApplication` — Useful for verifying application configuration
- `codedeploy:ListDeploymentInstances` — Useful for tracking deployment progress across instances
- `codedeploy:GetDeploymentInstance` — Useful for viewing per-instance deployment lifecycle hook output

## Prerequisites

**Admin:**
- An existing CodeDeploy deployment group must be configured to target EC2 instances
- The target EC2 instances must already have an admin IAM instance profile attached
- The CodeDeploy agent must be installed and running on the target instances
- An S3 bucket must be accessible to the EC2 instance to read the malicious revision

**Lateral:**
- An existing CodeDeploy deployment group must target EC2 instances with an elevated IAM instance profile
- The CodeDeploy agent must be running on the target instances

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `APP_NAME` | yes | — | Name of the existing CodeDeploy application to target |
| `DEPLOYMENT_GROUP` | yes | — | Name of the existing CodeDeploy deployment group to target |
| `BUCKET` | yes | — | S3 bucket containing the pre-staged malicious revision ZIP |
| `REVISION_KEY` | no | `codedeploy-001-revision.zip` | S3 object key of the malicious revision ZIP (appspec.yml + lifecycle hook script) |
| `TARGET_ARN` | no | — | IAM user or role name/ARN to attach AdministratorAccess to (auto-resolved from caller identity if not set) |
| `REGION` | no | `us-east-1` | AWS region for CodeDeploy and IAM operations |
| `CLEANUP` | no | `false` | Detach AdministratorAccess from TARGET_ARN after confirming escalation. Requires iam:DetachUserPolicy permission. The policy attachment is the goal of this exploit — set false to keep access after the module runs. |

## References

- [Pathfinding Cloud - codedeploy-001](https://pathfinding.cloud/paths/codedeploy-001)
- [Actions defined by AWS CodeDeploy - Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awscodedeploy.html)
- [CodeDeploy permissions reference - AWS CodeDeploy](https://docs.aws.amazon.com/codedeploy/latest/userguide/auth-and-access-control-permissions-reference.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1072 - Software Deployment Tools, T1078.004 - Valid Accounts: Cloud Accounts

