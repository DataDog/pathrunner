# `cognitoidentity-001` — iam:PassRole + cognito-identity:SetIdentityPoolRoles

|  |  |
|---|---|
| ID | `cognitoidentity-001` |
| Category | new-passrole |
| Services | iam, cognitoidentity |
| Author | Seth Art |
| Aliases | `cognitoidentity-passrole`, `exploit/cognitoidentity_passrole` |
| pathfinding.cloud | https://pathfinding.cloud/paths/cognitoidentity-001 |

A principal with iam:PassRole and cognito-identity:SetIdentityPoolRoles can bind an admin IAM role to an existing Cognito Identity Pool's unauthenticated identity slot. Once bound, any caller — including the attacker — can obtain temporary admin credentials via the public Cognito STS endpoint (GetId + GetOpenIdToken + AssumeRoleWithWebIdentity) without any IAM credentials. No separate execution environment is required.

## Required permissions

- `iam:PassRole` — Must be able to pass the target admin role to cognito-identity.amazonaws.com
- `cognito-identity:SetIdentityPoolRoles` — Must have access to the target identity pool ID

## Additional permissions

- `cognito-identity:ListIdentityPools` — Discover existing identity pools to target
- `cognito-identity:DescribeIdentityPool` — View pool configuration and current role assignments
- `cognito-identity:GetIdentityPoolRoles` — Verify current role assignments before and after exploitation
- `iam:ListRoles` — Discover available roles to pass
- `iam:GetRole` — Inspect role trust policies to find roles trusting cognito-identity.amazonaws.com

## Prerequisites

**Admin:**
- An existing Cognito Identity Pool with unauthenticated access enabled (AllowUnauthenticatedIdentities=true)
- An IAM role that trusts cognito-identity.amazonaws.com and has administrative permissions

**Lateral:**
- An existing Cognito Identity Pool with unauthenticated access enabled
- An IAM role that trusts cognito-identity.amazonaws.com with elevated permissions

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | ARN of the IAM role to bind to the pool's unauthenticated slot (must trust cognito-identity.amazonaws.com) [auto] |
| `IDENTITY_POOL_ID` | yes | — | Cognito Identity Pool ID in format region:GUID (must have AllowUnauthenticatedIdentities=true) [auto] |
| `REGION` | no | `us-east-1` | AWS region for Cognito and STS operations (auto-detected from IDENTITY_POOL_ID if not set) |
| `SESSION_NAME` | no | `cognito-escalation` | RoleSessionName for the AssumeRoleWithWebIdentity call |
| `AUTO_SWITCH` | no | `true` | Automatically switch to the obtained admin identity after exploitation (true/false) |
| `CLEANUP` | no | `false` | Restore the original unauthenticated role binding after obtaining credentials (true/false) |

## References

- [Pathfinding Cloud - cognitoidentity-001](https://pathfinding.cloud/paths/cognitoidentity-001)
- [Abusing Overpermissioned AWS Cognito Identity Pools - Hacking The Cloud](https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges/)
- [Using role-based access control - Amazon Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/role-based-access-control.html)
- [Actions defined by Amazon Cognito Identity - Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncognitoidentity.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation
- **Techniques:** T1098 - Account Manipulation, T1078.004 - Cloud Accounts

