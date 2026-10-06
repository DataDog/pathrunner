# `apprunner-001` — iam:PassRole + apprunner:CreateService

|  |  |
|---|---|
| ID | `apprunner-001` |
| Category | new-passrole |
| Services | iam, apprunner |
| Author | Seth Art |
| Aliases | `apprunner-passrole`, `exploit/apprunner_passrole` |
| pathfinding.cloud | https://pathfinding.cloud/paths/apprunner-001 |

A principal with iam:PassRole and apprunner:CreateService can create an AWS App Runner service with a privileged IAM role attached. The service's StartCommand executes as args to the aws CLI (ENTRYPOINT), running with the instance role's permissions. The container exits after the command; App Runner marks the service CREATE_FAILED, but the payload effect has already occurred.

## Required permissions

- `iam:PassRole` — Target role ARN must be in the Resource section
- `apprunner:CreateService` — Must have permission to create App Runner services

## Additional permissions

- `iam:CreateServiceLinkedRole` — Needed on first App Runner use in an account to create the service-linked role
- `iam:ListRoles` — Helpful for discovering available roles to pass
- `iam:GetRole` — Useful for viewing role trust policies
- `apprunner:ListServices` — List App Runner services to verify service creation
- `apprunner:DescribeService` — Check service status and configuration

## Prerequisites

**Admin:**
- A role must exist that trusts tasks.apprunner.amazonaws.com to assume it
- The role must have administrative permissions (e.g., AdministratorAccess)

**Lateral:**
- A role must exist that trusts tasks.apprunner.amazonaws.com to assume it

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | Target IAM role ARN to pass to App Runner as the instance role (must trust tasks.apprunner.amazonaws.com) |
| `PAYLOAD` | yes | — | Payload type (backdoor/attach-policy) |
| `REGION` | no | `us-east-1` | AWS region for App Runner service deployment |
| `SERVICE_NAME` | no | — | App Runner service name (auto-generated if not specified) |
| `CONTAINER_IMAGE` | no | `public.ecr.aws/aws-cli/aws-cli:latest` | Container image with aws-cli ENTRYPOINT (StartCommand becomes args) |
| `CLEANUP` | no | `false` | Delete the App Runner service after execution (starting user may lack apprunner:DeleteService; use 'workspace cleanup' with admin credentials instead) |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess policy to an IAM user or role via App Runner service StartCommand

## References

- [Pathfinding Cloud - apprunner-001](https://pathfinding.cloud/paths/apprunner-001)
- [Getting Shell and Data Access in AWS App Runner](https://blog.appsecco.com/getting-shell-and-data-access-in-aws-app-runner-3632e844bc77)
- [HackTricks Cloud - AWS App Runner Privilege Escalation](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-apprunner-privesc/index.html#iampassrole-apprunnercreateservice)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1651 - Cloud Administration Command

