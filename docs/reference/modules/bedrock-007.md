# `bedrock-007` — bedrock-agentcore:StartBrowserSession + bedrock-agentcore:ConnectBrowserAutomationStream

|  |  |
|---|---|
| ID | `bedrock-007` |
| Category | existing-passrole |
| Services | bedrock-agentcore |
| Author | Seth Art |
| Aliases | `bedrock-startbrowsersession-cdp`, `exploit/bedrock_startbrowsersession_cdp` |
| pathfinding.cloud | https://pathfinding.cloud/paths/bedrock-007 |

A principal with bedrock-agentcore:StartBrowserSession and bedrock-agentcore:ConnectBrowserAutomationStream can connect to an existing AgentCore Custom Browser over CDP and drive it to read the execution role credentials from MMDS at 169.254.169.254. No iam:PassRole required — the role is already attached to the browser.

## Required permissions

- `bedrock-agentcore:StartBrowserSession` — Target Custom Browser ARN or ID
- `bedrock-agentcore:ConnectBrowserAutomationStream` — Checked by AWS when the CDP WebSocket upgrade is authenticated

## Additional permissions

- `bedrock-agentcore:ListBrowsers` — Discover existing Custom Browsers
- `bedrock-agentcore:GetBrowser` — Confirm execution role attached to target browser

## Prerequisites

**Admin:**
- An AgentCore Custom Browser must exist with an IAM execution role attached
- The browser execution role must have administrative permissions (e.g., AdministratorAccess)

**Lateral:**
- An AgentCore Custom Browser must exist with an IAM execution role attached

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `BROWSER_ID` | yes | — | Target AgentCore Custom Browser ID (use 'discover' to enumerate existing browsers) |
| `REGION` | no | `us-east-1` | AWS region where the Custom Browser is deployed |
| `IDENTITY_NAME` | no | — | Name for the stolen execution role identity (auto-generated if empty) |
| `AUTO_SWITCH` | no | `true` | Automatically switch to the stolen identity after extraction |

## References

- [Pathfinding Cloud - bedrock-007](https://pathfinding.cloud/paths/bedrock-007)
- [Mapping Every Privilege Escalation Path in AWS AgentCore](https://www.beyondtrust.com/blog/entry/aws-agentcore-privilege-escalation)
- [Understanding Credentials Management in Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-credentials-management.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0006 - Credential Access
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1552.005 - Unsecured Credentials: Cloud Instance Metadata API

