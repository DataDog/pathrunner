# `bedrock-002` — bedrock-agentcore:StartCodeInterpreterSession + bedrock-agentcore:InvokeCodeInterpreter

|  |  |
|---|---|
| ID | `bedrock-002` |
| Category | existing-passrole |
| Services | iam, bedrock-agentcore |
| Author | Seth Art |
| Aliases | `bedrock-startsession-invoke`, `exploit/bedrock_startsession_invoke` |
| pathfinding.cloud | https://pathfinding.cloud/paths/bedrock-002 |

A principal with bedrock-agentcore:StartCodeInterpreterSession and bedrock-agentcore:InvokeCodeInterpreter can access an existing Bedrock AgentCore code interpreter that has a privileged IAM execution role attached. By starting a session and invoking arbitrary Python code within the interpreter, the attacker can access the MicroVM Metadata Service (MMDS) at 169.254.169.254 to retrieve temporary credentials for the interpreter's execution role. No iam:PassRole is required since the role is already attached to the existing interpreter. Similar to lambda:UpdateFunctionCode, this targets existing resources rather than creating new ones.

## Required permissions

- `bedrock-agentcore:StartCodeInterpreterSession` — Target code interpreter must be in the Resource section
- `bedrock-agentcore:InvokeCodeInterpreter` — Target code interpreter must be in the Resource section

## Additional permissions

- `bedrock-agentcore:ListCodeInterpreters` — Helpful for discovering existing code interpreters to target
- `bedrock-agentcore:GetCodeInterpreter` — Useful for viewing interpreter details including execution role ARN

## Prerequisites

**Admin:**
- A Bedrock AgentCore code interpreter must exist with an IAM execution role attached
- The interpreter's role must have administrative permissions (e.g., AdministratorAccess or equivalent)
- The interpreter must be in a running or ready state
- Python 3 with boto3 installed locally

**Lateral:**
- A Bedrock AgentCore code interpreter must exist with an IAM execution role attached
- The interpreter must be in a running or ready state
- Python 3 with boto3 installed locally

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `INTERPRETER_ID` | yes | — | ID of the existing Bedrock AgentCore code interpreter to target |
| `PAYLOAD` | no | `exfil/response` | Payload code to run inside the code interpreter microVM (exfil/response or backdoor/attach-policy) |
| `REGION` | no | `us-east-1` | AWS region where the code interpreter is deployed |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess (or custom policy) to an IAM user/role using the execution role's boto3 credentials
- `exfil/mmds` — Extract execution-role credentials from the MicroVM Metadata Service (MMDS) at 169.254.169.254

## References

- [Pathfinding Cloud - bedrock-002](https://pathfinding.cloud/paths/bedrock-002)
- [AWS AgentCore: The Overlooked Privilege Escalation Path in Bedrock AI Tooling](https://sonraisecurity.com/blog/aws-agentcore-privilege-escalation-bedrock-scp-fix/)
- [Sandboxed to Compromised: New Research Exposes Credential Exfiltration Paths in AWS Code Interpreters](https://sonraisecurity.com/blog/sandboxed-to-compromised-new-research-exposes-credential-exfiltration-paths-in-aws-code-interpreters/)
- [Understanding Credentials Management in Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-credentials-management.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0006 - Credential Access
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1552.005 - Unsecured Credentials: Cloud Instance Metadata API

