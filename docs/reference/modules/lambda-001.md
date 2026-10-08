# `lambda-001` — iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction

|  |  |
|---|---|
| ID | `lambda-001` |
| Category | new-passrole |
| Services | iam, lambda |
| Author | Seth Art |
| Aliases | `lambda-passrole`, `exploit/lambda_passrole` |
| pathfinding.cloud | https://pathfinding.cloud/paths/lambda-001 |

Create a Lambda function with a privileged role, invoke it to execute code with the role's permissions

## Required permissions

- `iam:PassRole` — Target role ARN
- `lambda:CreateFunction`
- `lambda:InvokeFunction`

## Prerequisites

**Admin:**
- IAM role with desired permissions and trust policy allowing Lambda

**Lateral:**
- Principal with iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | Target IAM role ARN to assume |
| `PAYLOAD` | yes | — | Payload type (exfil/response, exfil/https, backdoor/attach-policy, backdoor/create-role, backdoor/create-user) |
| `REGION` | no | `us-east-1` | AWS region for Lambda function deployment |
| `FUNCTION_NAME` | no | — | Lambda function name |
| `RUNTIME` | no | `python3.9` | Lambda runtime |
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

- [Pathfinding Cloud - lambda-001](https://pathfinding.cloud/paths/lambda-001)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts

