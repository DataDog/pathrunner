# `bedrock-001` — iam:PassRole + bedrock-agentcore:CreateCodeInterpreter + bedrock-agentcore:StartCodeInterpreterSession + bedrock-agentcore:InvokeCodeInterpreter

|  |  |
|---|---|
| ID | `bedrock-001` |
| Category | new-passrole |
| Services | iam, bedrock-agentcore |
| Author | Seth Art |
| Aliases | `bedrock-passrole`, `exploit/bedrock_passrole_codeinterpreter` |
| pathfinding.cloud | https://pathfinding.cloud/paths/bedrock-001 |

A principal with iam:PassRole, bedrock-agentcore:CreateCodeInterpreter, bedrock-agentcore:StartCodeInterpreterSession, and bedrock-agentcore:InvokeCodeInterpreter can create a code interpreter with a privileged execution role and invoke arbitrary Python code inside the resulting Firecracker microVM. The microVM Metadata Service (MMDS) at 169.254.169.254 exposes the execution role's temporary credentials — the attacker reads them and gains the full permissions of the passed role.

## Required permissions

- `iam:PassRole` — Target role ARN must trust bedrock-agentcore.amazonaws.com
- `bedrock-agentcore:CreateCodeInterpreter`
- `bedrock-agentcore:StartCodeInterpreterSession`
- `bedrock-agentcore:InvokeCodeInterpreter`

## Additional permissions

- `iam:ListRoles` — Helpful for discovering available roles to pass
- `iam:GetRole` — Useful for viewing role trust policies and attached permissions
- `bedrock-agentcore:GetCodeInterpreter` — Can verify code interpreter creation and status

## Prerequisites

**Admin:**
- A role must exist that trusts bedrock-agentcore.amazonaws.com to assume it
- The role must have administrative permissions (e.g., AdministratorAccess)

**Lateral:**
- A role must exist that trusts bedrock-agentcore.amazonaws.com to assume it

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | ARN of the IAM role to pass to the code interpreter (must trust bedrock-agentcore.amazonaws.com) |
| `PAYLOAD` | yes | `exfil/mmds` | Payload to run inside the code interpreter (exfil/mmds, backdoor/attach-policy) |
| `INTERPRETER_NAME` | no | `pathrunner` | Name for the code interpreter resource |
| `REGION` | no | `us-east-1` | AWS region for code interpreter deployment |
| `INIT_WAIT_SECONDS` | no | `15` | Seconds to wait for the code interpreter to initialize before invoking code |
| `CLEANUP` | no | `false` | Delete the code interpreter after execution (requires bedrock-agentcore-control:DeleteCodeInterpreter — often not available on the starting identity) |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess (or custom policy) to an IAM user/role using the execution role's boto3 credentials
- `exfil/mmds` — Extract execution-role credentials from the MicroVM Metadata Service (MMDS) at 169.254.169.254

## References

- [Pathfinding Cloud - bedrock-001](https://pathfinding.cloud/paths/bedrock-001)
- [AWS AgentCore: The Overlooked Privilege Escalation Path in Bedrock AI Tooling](https://sonraisecurity.com/blog/aws-agentcore-privilege-escalation-bedrock-scp-fix/)
- [Understanding Credentials Management in Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-credentials-management.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0006 - Credential Access
- **Techniques:** T1098.001 - Account Manipulation: Additional Cloud Credentials, T1552.005 - Unsecured Credentials: Cloud Instance Metadata API

