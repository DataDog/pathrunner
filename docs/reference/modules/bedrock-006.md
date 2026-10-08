# `bedrock-006` — iam:PassRole + bedrock-agentcore:CreateBrowser + bedrock-agentcore:StartBrowserSession + bedrock-agentcore:ConnectBrowserAutomationStream

|  |  |
|---|---|
| ID | `bedrock-006` |
| Category | new-passrole |
| Services | iam, bedrock-agentcore |
| Author | Seth Art |
| Aliases | `bedrock-createbrowser-cdp`, `exploit/bedrock_createbrowser_cdp` |
| pathfinding.cloud | https://pathfinding.cloud/paths/bedrock-006 |

A principal with iam:PassRole, bedrock-agentcore:CreateBrowser, bedrock-agentcore:StartBrowserSession and bedrock-agentcore:ConnectBrowserAutomationStream can create a Custom Browser with a privileged IAM execution role and drive the browser over Chrome DevTools Protocol (CDP) to read the execution role credentials from the MicroVM Metadata Service (MMDS) at 169.254.169.254. The attacker presigns the automation WebSocket, connects with Playwright and installs a context.route hook that rewrites the MMDS token request from GET to PUT and injects the token header, then navigates to the role-credentials endpoint and reads the response. Creating the browser rather than targeting an existing one lets the attacker pick exactly which role to escalate to.

## Required permissions

- `iam:PassRole` — Target role ARN must trust bedrock-agentcore.amazonaws.com
- `bedrock-agentcore:CreateBrowser` — Must have permission to create Bedrock AgentCore Custom Browsers
- `bedrock-agentcore:StartBrowserSession` — Must have permission to start sessions on the created browser
- `bedrock-agentcore:ConnectBrowserAutomationStream` — Must have permission to connect a remote automation driver to the browser session

## Additional permissions

- `iam:ListRoles` — Helpful for discovering AgentCore execution roles available to pass
- `iam:GetRole` — Useful for viewing role trust policies and attached permissions
- `bedrock-agentcore:GetBrowser` — Useful for confirming the browser reached READY state before starting a session

## Prerequisites

**Admin:**
- A role must exist that trusts bedrock-agentcore.amazonaws.com to assume it
- The role must have administrative permissions (e.g., AdministratorAccess or equivalent)
- Python 3 with boto3, botocore, and playwright must be installed locally
- Playwright Chromium browser must be installed: playwright install chromium

**Lateral:**
- A role must exist that trusts bedrock-agentcore.amazonaws.com to assume it
- Python 3 with boto3, botocore, and playwright must be installed locally
- Playwright Chromium browser must be installed: playwright install chromium

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | ARN of the IAM role to pass to the new browser as its execution role (must trust bedrock-agentcore.amazonaws.com) |
| `REGION` | no | `us-east-1` | AWS region to create the Custom Browser in |
| `BROWSER_NAME` | no | — | Name for the new Custom Browser resource (auto-generated if empty) |
| `WAIT_TIMEOUT` | no | `300` | Maximum seconds to wait for the browser to reach READY state. Provisioning typically takes 2-5 minutes. |
| `CLEANUP` | no | `false` | Delete the Custom Browser after credential extraction. The starting user typically lacks bedrock-agentcore:DeleteBrowser; use the escalated identity or workspace cleanup with admin credentials instead. |

## References

- [Pathfinding Cloud - bedrock-006](https://pathfinding.cloud/paths/bedrock-006)
- [Mapping Every Privilege Escalation Path in AWS AgentCore](https://www.beyondtrust.com/blog/entry/aws-agentcore-privilege-escalation)
- [Understanding Credentials Management in Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-credentials-management.html)
- [Amazon Bedrock AgentCore Browser tool](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-tool.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0006 - Credential Access
- **Techniques:** T1098.001 - Account Manipulation: Additional Cloud Credentials, T1552.005 - Unsecured Credentials: Cloud Instance Metadata API

