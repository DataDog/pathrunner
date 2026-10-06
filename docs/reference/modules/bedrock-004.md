# `bedrock-004` — bedrock-agentcore:InvokeAgentRuntimeCommand

|  |  |
|---|---|
| ID | `bedrock-004` |
| Category | existing-passrole |
| Services | iam, bedrock-agentcore |
| Author | Seth Art |
| Aliases | `bedrock-invokeagentruntime`, `exploit/bedrock_invokeagentruntime` |
| pathfinding.cloud | https://pathfinding.cloud/paths/bedrock-004 |

A principal with bedrock-agentcore:InvokeAgentRuntimeCommand can run a root shell command inside the Firecracker microVM of an existing AgentCore Runtime or Harness, parallel to the customer agent process and bypassing the agent, model and guardrails entirely. The command reads the execution role temporary credentials from the MicroVM Metadata Service (MMDS) at 169.254.169.254, granting the attacker the full permissions of the role already attached to that resource. No iam:PassRole is required because the role is already attached to the existing resource.

## Required permissions

- `bedrock-agentcore:InvokeAgentRuntimeCommand` — Target runtime or harness must use IAM as its Inbound Auth type

## Additional permissions

- `bedrock-agentcore:ListAgentRuntimes` — Helpful for discovering existing runtimes to target
- `bedrock-agentcore:ListHarnesses` — Helpful for discovering existing harnesses to target
- `bedrock-agentcore:GetAgentRuntime` — Useful for confirming execution role ARN and Inbound Auth type of target

## Prerequisites

**Admin:**
- An AgentCore Runtime or Harness must exist with an IAM execution role attached
- The resource must use IAM as its Inbound Auth type (JWT-auth resources reject the call)
- The execution role must have administrative permissions (e.g., AdministratorAccess)
- Python 3 with boto3 >= botocore 1.43.36 must be installed locally

**Lateral:**
- An AgentCore Runtime or Harness must exist with an IAM execution role attached
- The resource must use IAM as its Inbound Auth type (JWT-auth resources reject the call)
- Python 3 with boto3 >= botocore 1.43.36 must be installed locally

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `TARGET_RUNTIME_ARN` | yes | — | ARN of the existing AgentCore Runtime or Harness to target |
| `PAYLOAD` | no | `exfil/response` | Payload to run inside the runtime microVM via InvokeAgentRuntimeCommand (exfil/response or backdoor/attach-policy) |
| `REGION` | no | `us-east-1` | AWS region where the runtime is deployed |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess (or custom policy) to an IAM user/role using the execution role's boto3 credentials
- `exfil/mmds` — Extract execution-role credentials from the MicroVM Metadata Service (MMDS) at 169.254.169.254

## References

- [Pathfinding Cloud - bedrock-004](https://pathfinding.cloud/paths/bedrock-004)
- [Mapping Every Privilege Escalation Path in AWS AgentCore](https://www.beyondtrust.com/blog/entry/aws-agentcore-privilege-escalation)
- [Understanding Credentials Management in Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-credentials-management.html)
- [AgentCore Runtime command execution security best practices](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-security-best-practices.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0006 - Credential Access
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1552.005 - Unsecured Credentials: Cloud Instance Metadata API

