# `bedrock-005` — iam:PassRole + bedrock-agentcore:CreateHarness + bedrock-agentcore:CreateAgentRuntime + bedrock-agentcore:CreateAgentRuntimeEndpoint + bedrock-agentcore:CreateWorkloadIdentity + bedrock-agentcore:GetAgentRuntime + bedrock-agentcore:InvokeAgentRuntimeCommand

|  |  |
|---|---|
| ID | `bedrock-005` |
| Category | new-passrole |
| Services | iam, bedrock-agentcore |
| Author | Seth Art |
| Aliases | `bedrock-passrole-createharness`, `exploit/bedrock_passrole_createharness` |
| pathfinding.cloud | https://pathfinding.cloud/paths/bedrock-005 |

A principal with iam:PassRole, bedrock-agentcore:CreateHarness, and the supporting create and invoke permissions can deploy a new AgentCore Harness with a privileged IAM execution role and then run shell commands as root inside its Firecracker microVM. CreateHarness provisions a Runtime under the hood (hence the longer permission chain), and InvokeAgentRuntimeCommand runs as root parallel to the managed agent loop, bypassing the agent, model and guardrails. The command reads the execution role temporary credentials from the MicroVM Metadata Service (MMDS) at 169.254.169.254 — AgentCore's equivalent of EC2's IMDS.

## Required permissions

- `iam:PassRole` — Target role ARN must be in Resource; role must trust bedrock-agentcore.amazonaws.com
- `bedrock-agentcore:CreateHarness` — Must have permission to create Bedrock AgentCore harnesses
- `bedrock-agentcore:CreateAgentRuntime` — CreateHarness provisions a Runtime under the hood, which requires this permission
- `bedrock-agentcore:CreateAgentRuntimeEndpoint` — Required to create the runtime endpoint the harness uses
- `bedrock-agentcore:CreateWorkloadIdentity` — Required to create the workload identity the underlying runtime needs
- `bedrock-agentcore:GetAgentRuntime` — Required to resolve the runtime that CreateHarness provisions before invoking it
- `bedrock-agentcore:InvokeAgentRuntimeCommand` — Must have permission to invoke commands on the created harness

## Additional permissions

- `iam:ListRoles` — Helpful for discovering AgentCore execution roles available to pass
- `iam:GetRole` — Useful for viewing role trust policies and attached permissions

## Prerequisites

**Admin:**
- A role must exist that trusts bedrock-agentcore.amazonaws.com to assume it
- The role must have administrative permissions (e.g., AdministratorAccess or equivalent)
- At least one Bedrock foundation model must be enabled in the account (required by CreateHarness; the model is never invoked by the attack)

**Lateral:**
- A role must exist that trusts bedrock-agentcore.amazonaws.com to assume it
- At least one Bedrock foundation model must be enabled in the account

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | ARN of the IAM role to pass to the new harness as its execution role; must trust bedrock-agentcore.amazonaws.com |
| `REGION` | no | `us-east-1` | AWS region to create the harness in |
| `MODEL_ID` | no | `amazon.nova-micro-v1:0` | Bedrock foundation model ID to associate with the harness (required by CreateHarness; never invoked by the attack) |
| `HARNESS_NAME` | no | — | Name for the new AgentCore Harness (auto-generated if not set; must start with a letter and use only alphanumeric characters and underscores) |
| `PAYLOAD` | no | `exfil/response` | Payload to run inside the harness microVM via InvokeAgentRuntimeCommand (exfil/response or backdoor/attach-policy) |
| `CLEANUP` | no | `false` | Whether to delete the harness after credential extraction. Defaults to false because the starting identity typically lacks bedrock-agentcore:DeleteHarness; use 'workspace cleanup' with the extracted admin identity instead. |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess (or custom policy) to an IAM user/role using the execution role's boto3 credentials
- `exfil/mmds` — Extract execution-role credentials from the MicroVM Metadata Service (MMDS) at 169.254.169.254

## References

- [Pathfinding Cloud - bedrock-005](https://pathfinding.cloud/paths/bedrock-005)
- [Mapping Every Privilege Escalation Path in AWS AgentCore](https://www.beyondtrust.com/blog/entry/aws-agentcore-privilege-escalation)
- [Understanding Credentials Management in Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-credentials-management.html)
- [Amazon Bedrock AgentCore Harness](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0006 - Credential Access
- **Techniques:** T1098.001 - Account Manipulation: Additional Cloud Credentials, T1552.005 - Unsecured Credentials: Cloud Instance Metadata API

