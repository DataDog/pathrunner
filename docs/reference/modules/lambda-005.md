# `lambda-005` — lambda:UpdateFunctionCode + lambda:AddPermission

|  |  |
|---|---|
| ID | `lambda-005` |
| Category | existing-passrole |
| Services | lambda |
| Author | Seth Art |
| Aliases | `lambda-updatecode-addpermission`, `exploit/lambda_updatecode_addpermission` |
| pathfinding.cloud | https://pathfinding.cloud/paths/lambda-005 |

Modify an existing Lambda function's code with malicious code and grant self-invocation permission via the resource-based policy to execute code under the function's privileged execution role

## Required permissions

- `lambda:UpdateFunctionCode` — Must have permission to update the target Lambda function's code
- `lambda:AddPermission` — Must have permission to modify the target Lambda function's resource-based policy

## Additional permissions

- `lambda:ListFunctions` — Helpful for discovering available Lambda functions to target
- `lambda:GetFunction` — Useful for viewing function details including execution role ARN and resource policy
- `lambda:GetFunctionConfiguration` — Useful for viewing function configuration details
- `lambda:GetPolicy` — Useful for viewing the function's resource-based policy
- `iam:GetRole` — Useful for viewing the execution role's trust policy and permissions
- `iam:ListAttachedRolePolicies` — Useful for understanding what permissions the execution role has

## Prerequisites

**Admin:**
- A Lambda function must exist with an administrative execution role (e.g., AdministratorAccess)

**Lateral:**
- A Lambda function must exist with a privileged execution role

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `FUNCTION_NAME` | yes | — | Target Lambda function name to update |
| `PAYLOAD` | yes | — | Payload type (exfil/response, exfil/https, backdoor/attach-policy, backdoor/create-role, backdoor/create-user) |
| `REGION` | no | `us-east-1` | AWS region |
| `CLEANUP` | no | `true` | Restore original function code and remove added permission after execution |
| `FUNCTION_RUNTIME` | no | — | Lambda runtime (auto-detected via 'discover FUNCTION_NAME') |

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

- [Pathfinding Cloud - lambda-005](https://pathfinding.cloud/paths/lambda-005)
- [AWS Privilege Escalation Methods and Mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [HackTricks - AWS Lambda Privesc](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-lambda-privesc)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1648 - Serverless Execution

