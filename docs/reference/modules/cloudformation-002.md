# `cloudformation-002` — cloudformation:UpdateStack

|  |  |
|---|---|
| ID | `cloudformation-002` |
| Category | existing-passrole |
| Services | cloudformation, iam |
| Author | Seth Art |
| Aliases | `cloudformation-updatestack`, `cfn-002`, `exploit/cloudformation_updatestack` |
| pathfinding.cloud | https://pathfinding.cloud/paths/cloudformation-002 |

A principal with cloudformation:UpdateStack can modify an existing CloudFormation stack that has an administrative service role attached. CloudFormation stacks execute with the permissions of their service role, which often requires elevated privileges to manage infrastructure. By updating the stack template to include new IAM resources (such as an admin role with a trust policy allowing the attacker to assume it), the attacker can leverage the stack's elevated permissions to create resources they couldn't create directly. This is particularly insidious because it appears as legitimate infrastructure management activity.

## Required permissions

- `cloudformation:UpdateStack` — Must have permission to update the target CloudFormation stack

## Additional permissions

- `cloudformation:DescribeStacks` — Discover existing stacks and poll for update completion
- `cloudformation:GetTemplate` — Retrieve current stack template for safe injection
- `iam:GetRole` — Verify the escalated role was created by the stack update
- `sts:AssumeRole` — Assume the newly created admin role

## Prerequisites

**Admin:**
- A CloudFormation stack must exist with an administrative service role (e.g., AdministratorAccess or an equivalent custom policy)
- The principal must have permission to update that specific stack

**Lateral:**
- A CloudFormation stack must exist with a service role that has elevated permissions
- The principal must have permission to update that specific stack

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `STACK_NAME` | yes | — | Name of the existing CloudFormation stack with an admin service role |
| `PAYLOAD` | no | `backdoor/attach-policy` | Payload type for the injected CloudFormation resources (backdoor/attach-policy) |
| `REGION` | no | `us-east-1` | AWS region for CloudFormation and IAM operations |
| `ASSUME_ROLE` | no | `true` | Attempt to assume the escalated role after the stack update completes |
| `ROLE_ARN` | no | — | ARN of the CloudFormation stack's service role. When provided, used to derive the stack name during discovery if cloudformation:ListStacks is unavailable |
| `ESCALATED_ROLE_NAME` | no | — | Name for the escalated IAM role to create (auto-generated if empty) |
| `TRUST_PRINCIPAL` | no | — | ARN to trust in the escalated role's trust policy (defaults to caller ARN) |
| `CLEANUP` | no | `false` | Revert the stack update after execution by restoring the original template. Requires cloudformation:UpdateStack |

## Compatible payloads

- `backdoor/attach-policy` — Create an IAM role with AdministratorAccess trusted by the attacker's principal via CloudFormation template

## References

- [Pathfinding Cloud - cloudformation-002](https://pathfinding.cloud/paths/cloudformation-002)
- [PMapper CloudFormation Edge Detection (Original Implementation)](https://github.com/nccgroup/PMapper/blob/master/principalmapper/graphing/cloudformation_edges.py)
- [AWS IAM Privilege Escalation - Methods and Mitigation (Rhino Security Labs)](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [CloudFormation Change Set Privilege Escalation](https://dev.to/aws-builders/cloudformation-change-set-privilege-escalation-18i6)
- [AWS CloudFormation Service Role Documentation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0003 - Persistence
- **Techniques:** T1098 - Account Manipulation, T1098.001 - Account Manipulation: Additional Cloud Credentials

