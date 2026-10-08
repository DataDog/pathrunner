# `lambda-002` — iam:PassRole + lambda:CreateFunction + lambda:CreateEventSourceMapping

|  |  |
|---|---|
| ID | `lambda-002` |
| Category | new-passrole |
| Services | iam, lambda |
| Author | Seth Art |
| Aliases | `lambda-passrole-esm`, `exploit/lambda_passrole_esm` |
| pathfinding.cloud | https://pathfinding.cloud/paths/lambda-002 |

Create a Lambda function with a privileged role and configure it to be triggered by a DynamoDB stream event source, executing code with elevated privileges without manual invocation

## Required permissions

- `iam:PassRole` — Target role ARN must be in the Resource section
- `lambda:CreateFunction` — Must have permission to create Lambda functions
- `lambda:CreateEventSourceMapping` — Must have permission to create event source mappings

## Additional permissions

- `iam:ListRoles` — Helpful for discovering available roles to pass
- `iam:GetRole` — Useful for viewing role trust policies and attached permissions
- `dynamodb:DescribeTable` — Get table details including stream ARN
- `dynamodb:PutItem` — Trigger Lambda execution by inserting record into DynamoDB table
- `lambda:ListFunctions` — Helpful for reconnaissance
- `lambda:ListEventSourceMappings` — Useful for seeing existing event source mappings

## Prerequisites

**Admin:**
- A role must exist that trusts lambda.amazonaws.com to assume it
- The role must have administrative permissions (e.g., AdministratorAccess)
- An event source must exist (DynamoDB stream, Kinesis stream, or SQS queue)

**Lateral:**
- A role must exist that trusts lambda.amazonaws.com to assume it
- An event source must exist (DynamoDB stream, Kinesis stream, or SQS queue)

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | Target IAM role ARN to pass to Lambda |
| `PAYLOAD` | yes | — | Payload type (backdoor/attach-policy, backdoor/create-role, backdoor/create-user, exfil/https) |
| `EVENT_SOURCE_ARN` | yes | — | DynamoDB stream ARN to use as event source |
| `TABLE_NAME` | yes | — | DynamoDB table name for inserting trigger records |
| `REGION` | no | `us-east-1` | AWS region |
| `FUNCTION_NAME` | no | — | Lambda function name |
| `RUNTIME` | no | `python3.11` | Lambda runtime |
| `TIMEOUT` | no | `30` | Function timeout in seconds |
| `MEMORY_SIZE` | no | `128` | Function memory size in MB |
| `CLEANUP` | no | `false` | Clean up Lambda function and ESM after execution (starting user may lack DeleteFunction permission) |
| `MAX_TRIGGER_ATTEMPTS` | no | `30` | Max trigger-and-verify attempts (each ~10s, default 30 = 5 min) |

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

- [Pathfinding Cloud - lambda-002](https://pathfinding.cloud/paths/lambda-002)
- [AWS Privilege Escalation Methods and Mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0003 - Persistence
- **Techniques:** T1098.001 - Account Manipulation: Additional Cloud Credentials, T1578 - Modify Cloud Compute Infrastructure

