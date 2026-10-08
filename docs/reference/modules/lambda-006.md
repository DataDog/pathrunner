# `lambda-006` — iam:PassRole + lambda:CreateFunction + lambda:AddPermission

|  |  |
|---|---|
| ID | `lambda-006` |
| Category | new-passrole |
| Services | iam, lambda |
| Author | Seth Art |
| Aliases | `lambda-createfunction-addpermission`, `exploit/lambda_createfunction_addpermission` |
| pathfinding.cloud | https://pathfinding.cloud/paths/lambda-006 |

Create a new Lambda function with a privileged execution role and grant self-invocation permission via the resource-based policy to execute malicious code under the role's credentials

## Required permissions

- `iam:PassRole` — Must have permission to pass a privileged role to Lambda service
- `lambda:CreateFunction` — Must have permission to create Lambda functions
- `lambda:AddPermission` — Must have permission to modify Lambda function resource-based policies

## Additional permissions

- `iam:ListRoles` — Helpful for discovering available privileged roles to pass
- `iam:GetRole` — Useful for viewing role trust policies and attached permissions
- `iam:ListAttachedRolePolicies` — Useful for understanding what permissions a role has
- `lambda:GetFunction` — Useful for verifying function creation and configuration
- `lambda:GetPolicy` — Useful for viewing the function's resource-based policy after adding permissions
- `lambda:DeleteFunction` — Useful for cleaning up attack artifacts

## Prerequisites

**Admin:**
- A role must exist that trusts lambda.amazonaws.com to assume it
- The role must have administrative permissions (e.g., AdministratorAccess or an equivalent custom policy)

**Lateral:**
- A role must exist that trusts lambda.amazonaws.com to assume it

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | Target IAM role ARN to pass to the Lambda function |
| `PAYLOAD` | yes | — | Payload type (exfil/response, exfil/https, backdoor/attach-policy, backdoor/create-role, backdoor/create-user) |
| `REGION` | no | `us-east-1` | AWS region for Lambda function deployment |
| `FUNCTION_NAME` | no | — | Lambda function name (auto-generated if empty) |
| `RUNTIME` | no | `python3.11` | Lambda runtime |
| `TIMEOUT` | no | `30` | Function timeout in seconds |
| `MEMORY_SIZE` | no | `128` | Function memory size in MB |
| `CLEANUP` | no | `true` | Clean up created resources after execution |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess policy to an existing IAM user or role
- `backdoor/create-access-key` — Create new access keys for an existing IAM user (does not work on roles)
- `backdoor/create-role` — Create an IAM role with administrator privileges and a custom trust policy
- `backdoor/create-user` — Create an IAM user with administrator privileges and console access
- `backdoor/update-role-trust` — Update a role's trust policy to add a trusted principal
- `exfil/https` — Send extracted credentials to a remote HTTPS endpoint
- `exfil/response` — Extract credentials and return them in the Lambda function response
- `exfil/s3` — Exfiltrate Lambda execution role credentials to an attacker-controlled S3 bucket
- `revshell/tls` — Establish a TLS-encrypted reverse shell from inside a Lambda function. Only works with new-passrole modules where the function timeout can be set to 900s

## References

- [Pathfinding Cloud - lambda-006](https://pathfinding.cloud/paths/lambda-006)
- [AWS IAM Privilege Escalation Methods and Mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [HackTricks - AWS Lambda Privesc](https://cloud.hacktricks.wiki/pentesting-cloud/aws-security/aws-privilege-escalation/aws-lambda-privesc/)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1648 - Serverless Execution

