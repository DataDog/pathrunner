# `bedrock-003` — iam:PassRole + bedrock-agentcore:CreateAgentRuntime + bedrock-agentcore:CreateAgentRuntimeEndpoint + bedrock-agentcore:CreateWorkloadIdentity + bedrock-agentcore:InvokeAgentRuntimeCommand

|  |  |
|---|---|
| ID | `bedrock-003` |
| Category | new-passrole |
| Services | iam, bedrock-agentcore |
| Author | Seth Art |
| Aliases | `bedrock-passrole-createagentruntime`, `exploit/bedrock_passrole_createagentruntime` |
| pathfinding.cloud | https://pathfinding.cloud/paths/bedrock-003 |

A principal with iam:PassRole, bedrock-agentcore:CreateAgentRuntime, bedrock-agentcore:CreateAgentRuntimeEndpoint, bedrock-agentcore:CreateWorkloadIdentity, and bedrock-agentcore:InvokeAgentRuntimeCommand can deploy a new AgentCore Runtime with a privileged IAM execution role and then run shell commands as root inside its Firecracker microVM. InvokeAgentRuntimeCommand executes a submitted command as root parallel to the customer agent process, bypassing the agent, model and guardrails entirely. The command reads the execution role temporary credentials from the MicroVM Metadata Service (MMDS) at 169.254.169.254, AgentCore's equivalent of EC2's IMDS, granting the attacker the full permissions of the chosen execution role.

## Required permissions

- `iam:PassRole` — Target role ARN must be in Resource; role must trust bedrock-agentcore.amazonaws.com
- `bedrock-agentcore:CreateAgentRuntime` — Must have permission to create Bedrock AgentCore runtimes
- `bedrock-agentcore:CreateAgentRuntimeEndpoint` — Must have permission to create the runtime endpoint used to invoke the runtime
- `bedrock-agentcore:CreateWorkloadIdentity` — Must have permission to create the workload identity the runtime requires at creation
- `bedrock-agentcore:InvokeAgentRuntimeCommand` — Must have permission to invoke commands on the created runtime

## Additional permissions

- `iam:ListRoles` — Helpful for discovering AgentCore execution roles available to pass
- `iam:GetRole` — Useful for viewing role trust policies and attached permissions
- `bedrock-agentcore:GetAgentRuntime` — Useful for confirming the new runtime reached a READY state before invoking it

## Prerequisites

**Admin:**
- A role must exist that trusts bedrock-agentcore.amazonaws.com to assume it
- The role must have administrative permissions (e.g., AdministratorAccess or equivalent)
- An attacker-controlled container image must be available in ECR (the runtime pulls it on startup)

**Lateral:**
- A role must exist that trusts bedrock-agentcore.amazonaws.com to assume it
- An attacker-controlled container image must be available in ECR

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `EXECUTION_ROLE_ARN` | yes | — | ARN of the IAM role to pass to the new runtime as its execution role; must trust bedrock-agentcore.amazonaws.com |
| `CONTAINER_URI` | no | — | ECR image URI for the runtime (e.g., <account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>); the image is always built and pushed by pathrunner — set this to control which ECR repo is used, or leave empty to auto-find/create the attacker ECR repo |
| `REGION` | no | `us-east-1` | AWS region to create the runtime in |
| `RUNTIME_NAME` | no | — | Name for the new AgentCore Runtime (auto-generated if not set) |
| `PAYLOAD` | no | `exfil/response` | Payload to run inside the runtime microVM via InvokeAgentRuntimeCommand (exfil/response or backdoor/attach-policy) |
| `CLEANUP` | no | `false` | Whether to delete the runtime after credential extraction. Defaults to false because the starting identity typically lacks bedrock-agentcore:DeleteAgentRuntime; use 'workspace cleanup' with the extracted admin identity instead. |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess (or custom policy) to an IAM user/role using the execution role's boto3 credentials
- `exfil/mmds` — Extract execution-role credentials from the MicroVM Metadata Service (MMDS) at 169.254.169.254

## References

- [Pathfinding Cloud - bedrock-003](https://pathfinding.cloud/paths/bedrock-003)
- [Mapping Every Privilege Escalation Path in AWS AgentCore](https://www.beyondtrust.com/blog/entry/aws-agentcore-privilege-escalation)
- [Understanding Credentials Management in Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-credentials-management.html)
- [AgentCore Runtime execution role permissions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-permissions.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0006 - Credential Access
- **Techniques:** T1098.001 - Account Manipulation: Additional Cloud Credentials, T1552.005 - Unsecured Credentials: Cloud Instance Metadata API

