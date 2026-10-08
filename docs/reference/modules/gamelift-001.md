# `gamelift-001` — iam:PassRole + gamelift:CreateBuild + gamelift:CreateFleet

|  |  |
|---|---|
| ID | `gamelift-001` |
| Category | new-passrole |
| Services | iam, gamelift |
| Author | Seth Art |
| Aliases | `gamelift-passrole`, `exploit/gamelift_passrole` |
| pathfinding.cloud | https://pathfinding.cloud/paths/gamelift-001 |

Upload a malicious game server build to GameLift, then create a fleet with an admin IAM instance role using SHARED_CREDENTIAL_FILE. The game server process reads the instance role credentials from /local/credentials/credentials and attaches AdministratorAccess to the starting user. Fleet provisioning typically takes 5-15 minutes.

## Required permissions

- `iam:PassRole` — Must be able to pass the target admin role to GameLift
- `gamelift:CreateBuild`
- `gamelift:CreateFleet`
- `gamelift:RequestUploadCredentials` — Required to get temporary S3 upload credentials

## Additional permissions

- `gamelift:DescribeBuild` — Poll build status until READY
- `gamelift:DescribeFleetAttributes` — Monitor fleet provisioning status
- `gamelift:ListFleets` — Discover existing fleets
- `gamelift:DescribeInstances` — Confirm instance provisioning
- `iam:ListAttachedUserPolicies` — Verify privilege escalation success

## Prerequisites

**Admin:**
- IAM role that trusts ec2.amazonaws.com with administrative permissions

**Lateral:**
- IAM role that trusts ec2.amazonaws.com with elevated permissions

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | Target IAM role ARN to pass as the GameLift fleet instance role (must trust ec2.amazonaws.com) |
| `PAYLOAD` | yes | — | Payload type (backdoor/attach-policy) |
| `TARGET_ARN` | no | — | IAM user or role name/ARN to attach AdministratorAccess to (auto-resolved from caller identity if not set) |
| `REGION` | no | `us-east-1` | AWS region for GameLift build and fleet |
| `BUILD_NAME` | no | — | Name tag for the GameLift build |
| `FLEET_NAME` | no | — | Name tag for the GameLift fleet |
| `INSTANCE_TYPE` | no | `c5.large` | EC2 instance type for the fleet |
| `CLEANUP` | no | `false` | Delete build and fleet after execution. The starting user typically lacks gamelift:DeleteFleet and gamelift:DeleteBuild; use workspace cleanup with admin credentials instead. |

## Compatible payloads

- `backdoor/attach-policy` — Attach an IAM policy to a user or role via a GameLift game server process that reads SHARED_CREDENTIAL_FILE instance role credentials

## References

- [Pathfinding Cloud - gamelift-001](https://pathfinding.cloud/paths/gamelift-001)
- [Actions defined by Amazon GameLift - Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazongamelift.html)
- [Set up an IAM service role for Amazon GameLift Servers](https://docs.aws.amazon.com/gamelift/latest/developerguide/setting-up-role.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1578 - Modify Cloud Compute Infrastructure

