# `apprunner-002` — apprunner:UpdateService

|  |  |
|---|---|
| ID | `apprunner-002` |
| Category | existing-passrole |
| Services | iam, apprunner |
| Author | Seth Art |
| Aliases | `apprunner-updateservice`, `exploit/apprunner_updateservice` |
| pathfinding.cloud | https://pathfinding.cloud/paths/apprunner-002 |

A principal with apprunner:UpdateService can modify an existing App Runner service's configuration. If the target service has a privileged IAM role attached, the attacker can update the service to use the aws-cli image with a StartCommand that executes with the service role's permissions. Unlike creating a new service, this does not require iam:PassRole since the role is already attached to the existing service.

## Required permissions

- `apprunner:UpdateService` — Target App Runner service ARN must be in the Resource section

## Additional permissions

- `apprunner:DescribeService` — Check service configuration and confirm the attached role
- `apprunner:ListServices` — Discover existing App Runner services to target

## Prerequisites

**Admin:**
- An App Runner service must exist with an IAM role attached
- The service's role must have administrative permissions

**Lateral:**
- An App Runner service must exist with an IAM role attached

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `SERVICE_ARN` | no | — | ARN of the existing App Runner service to update (must have a privileged role attached); auto-discovered when not set and a single service with a 'pl-' prefix exists in the region |
| `PAYLOAD` | yes | — | Payload type (backdoor/attach-policy) |
| `TARGET_ARN` | no | — | IAM user or role ARN to target (auto-resolved from caller identity if not set) |
| `REGION` | no | `us-east-1` | AWS region of the target App Runner service |
| `CONTAINER_IMAGE` | no | `public.ecr.aws/aws-cli/aws-cli:latest` | Container image to use for the exploit (aws-cli ENTRYPOINT; StartCommand becomes args) |
| `CLEANUP` | no | `false` | Restore the original App Runner service configuration after execution (starting user has apprunner:UpdateService so restoration is possible) |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess policy to an IAM user or role via App Runner service StartCommand

## References

- [Pathfinding Cloud - apprunner-002](https://pathfinding.cloud/paths/apprunner-002)
- [Getting Shell and Data Access in AWS App Runner](https://blog.appsecco.com/getting-shell-and-data-access-in-aws-app-runner-3632e844bc77)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1651 - Cloud Administration Command

