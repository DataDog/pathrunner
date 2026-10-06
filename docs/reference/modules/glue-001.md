# `glue-001` — iam:PassRole + glue:CreateDevEndpoint

|  |  |
|---|---|
| ID | `glue-001` |
| Category | new-passrole |
| Services | iam, glue |
| Author | Seth Art |
| Aliases | `glue-passrole-devendpoint`, `exploit/glue_passrole_devendpoint` |
| pathfinding.cloud | https://pathfinding.cloud/paths/glue-001 |

Create a Glue development endpoint with a privileged IAM role and gain SSH access to execute code with that role's permissions

## Required permissions

- `iam:PassRole` — Target role ARN must be in the Resource section
- `glue:CreateDevEndpoint`

## Additional permissions

- `glue:GetDevEndpoint` — Poll endpoint status and retrieve the public SSH address
- `iam:ListRoles` — Discover available roles to pass to Glue
- `glue:DeleteDevEndpoint` — Clean up the created endpoint

## Prerequisites

**Admin:**
- A role must exist that trusts glue.amazonaws.com to assume it
- The role must have administrative permissions (e.g., AdministratorAccess)

**Lateral:**
- A role must exist that trusts glue.amazonaws.com to assume it

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | IAM role ARN to pass to the Glue dev endpoint (must trust glue.amazonaws.com) |
| `SSH_PUBLIC_KEY` | no | — | SSH public key to authorize on the endpoint (OpenSSH authorized_keys format). Auto-detected from ~/.ssh/id_ed25519.pub or ~/.ssh/id_rsa.pub if not set. |
| `ENDPOINT_NAME` | no | — | Name for the Glue dev endpoint |
| `GLUE_VERSION` | no | `1.0` | Glue version for the dev endpoint |
| `NUMBER_OF_NODES` | no | `2` | Number of Glue Data Processing Units (DPUs) to allocate |
| `REGION` | no | `us-east-1` | AWS region for the dev endpoint |
| `CLEANUP` | no | `false` | Delete the dev endpoint after printing connection details. Defaults to false because dev endpoints bill by the hour (~$2.20/hr) and operators typically want SSH access after this module runs. |

## References

- [Pathfinding Cloud - glue-001](https://pathfinding.cloud/paths/glue-001)
- [Well, That Escalated Quickly: How Abusing AWS API Can Lead to Admin Access](https://know.bishopfox.com/research/privilege-escalation-in-aws)
- [HackingTheCloud - PassRole + Glue CreateDevEndpoint Privilege Escalation](https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/#iampassrole-gluecreatedevendpoint)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation
- **Techniques:** T1098.001 - Account Manipulation: Additional Cloud Credentials, T1578 - Modify Cloud Compute Infrastructure

