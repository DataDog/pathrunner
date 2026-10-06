# `cloudformation-005` — cloudformation:CreateChangeSet + cloudformation:ExecuteChangeSet

|  |  |
|---|---|
| ID | `cloudformation-005` |
| Category | new-passrole |
| Services | cloudformation, iam |
| Author | Seth Art |
| Aliases | `cloudformation-createchangeset-executechangeset`, `cfn-005`, `exploit/cloudformation_createchangeset_executechangeset` |
| pathfinding.cloud | https://pathfinding.cloud/paths/cloudformation-005 |

A principal with cloudformation:CreateChangeSet and cloudformation:ExecuteChangeSet can inherit administrative privileges from an existing CloudFormation stack's service role. Unlike direct stack updates, change set execution bypasses traditional IAM permission checks by delegating all operations to the stack's attached service role. If that service role has administrative privileges, an attacker can inject malicious infrastructure changes (such as creating a new admin IAM role with a trust policy allowing the attacker to assume it) through the change set mechanism without needing those elevated IAM permissions directly.

## Required permissions

- `cloudformation:CreateChangeSet` — Create a change set on the target stack
- `cloudformation:ExecuteChangeSet` — Execute the change set to apply the template changes

## Additional permissions

- `cloudformation:DescribeChangeSet` — View change set details and confirm creation
- `cloudformation:DescribeStacks` — Discover existing stacks and poll for completion
- `cloudformation:GetTemplate` — Retrieve the current stack template for safe injection

## Prerequisites

**Admin:**
- An existing CloudFormation stack must exist with a service role attached
- The stack's service role must have administrative permissions (e.g., AdministratorAccess)

**Lateral:**
- An existing CloudFormation stack must exist with a service role attached
- The stack's service role must have elevated permissions

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `STACK_NAME` | yes | — | Name of the existing CloudFormation stack with an admin service role |
| `CHANGESET_NAME` | no | — | Name for the change set to create |
| `REGION` | no | `us-east-1` | AWS region for CloudFormation and IAM operations |
| `ASSUME_ROLE` | no | `true` | Attempt to assume the escalated role after the change set completes |
| `PAYLOAD` | no | `backdoor/attach-policy` | Payload type for the CloudFormation template injection (backdoor/attach-policy) |
| `ESCALATED_ROLE_NAME` | no | — | Name for the escalated IAM role to create (auto-generated if empty) |
| `TRUST_PRINCIPAL` | no | — | ARN to trust in the escalated role's trust policy (defaults to caller ARN) |
| `CLEANUP` | no | `false` | Revert the stack change set after execution. Requires CloudFormation write permissions on the stack |

## Compatible payloads

- `backdoor/attach-policy` — Create an IAM role with AdministratorAccess trusted by the attacker's principal via CloudFormation template

## References

- [Pathfinding Cloud - cloudformation-005](https://pathfinding.cloud/paths/cloudformation-005)
- [CloudFormation Change Set Privilege Escalation - Lucian Patian](https://dev.to/aws-builders/cloudformation-change-set-privilege-escalation-18i6)
- [PMapper CloudFormation Edge Detection](https://github.com/nccgroup/PMapper/blob/master/principalmapper/graphing/cloudformation_edges.py)
- [AWS CloudFormation Privilege Escalation - HackTricks](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-cloudformation-privesc)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation
- **Techniques:** T1098.003 - Account Manipulation: Additional Cloud Roles

