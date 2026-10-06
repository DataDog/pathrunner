# `cloudformation-003` — iam:PassRole + cloudformation:CreateStackSet + cloudformation:CreateStackInstances

|  |  |
|---|---|
| ID | `cloudformation-003` |
| Category | new-passrole |
| Services | iam, cloudformation |
| Author | Seth Art |
| Aliases | `cloudformation-createstackset`, `cfn-003`, `exploit/cloudformation_passrole_createstackset_createstackinstances` |
| pathfinding.cloud | https://pathfinding.cloud/paths/cloudformation-003 |

A principal with iam:PassRole, cloudformation:CreateStackSet, and cloudformation:CreateStackInstances can escalate privileges by creating a new CloudFormation StackSet with a privileged execution role and then deploying stack instances to trigger resource provisioning. The two-step process is critical: CreateStackSet defines the template and execution role but deploys nothing, while CreateStackInstances actually provisions the resources defined in the template using the execution role's credentials. Both permissions are required. The attacker's template defines an IAM role with AdministratorAccess trusted by the attacker's principal; once the stack instance deployment succeeds, the attacker assumes that role to gain administrative access.

## Required permissions

- `iam:PassRole` — Must have permission to pass the execution role to CloudFormation StackSets
- `cloudformation:CreateStackSet` — Create a new CloudFormation StackSet with the malicious template
- `cloudformation:CreateStackInstances` — Deploy stack instances to trigger resource provisioning

## Additional permissions

- `cloudformation:DescribeStackSet` — Monitor StackSet creation progress
- `cloudformation:DescribeStackSetOperation` — Poll for stack instance deployment status
- `cloudformation:ListStackInstances` — List deployed stack instances
- `cloudformation:DeleteStackInstances` — Remove stack instances during cleanup
- `cloudformation:DeleteStackSet` — Delete the StackSet during cleanup
- `iam:ListRoles` — Discover available privileged roles to use as the execution role

## Prerequisites

**Admin:**
- A privileged IAM role must exist that can be passed as the StackSet execution role
- The execution role must have administrative permissions (e.g., AdministratorAccess or equivalent)
- An administration role must exist that trusts cloudformation.amazonaws.com and has permission to assume the execution role

**Lateral:**
- A privileged IAM role must exist that can be passed as the StackSet execution role
- The execution role must have elevated permissions to create the desired resources
- An administration role must exist for StackSet operations

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `EXECUTION_ROLE_NAME` | yes | — | Name of the IAM execution role to pass to CloudFormation StackSets (must have elevated permissions; CloudFormation assumes this role in each target account to create resources) |
| `PAYLOAD` | no | `backdoor/attach-policy` | Payload type for the CloudFormation StackSet template (backdoor/attach-policy) |
| `ROLE_ARN` | no | — | ARN of the IAM administration role to pass via iam:PassRole (must trust cloudformation.amazonaws.com and be able to assume the execution role). Leave blank to auto-construct from account ID using the lab's default naming convention |
| `STACKSET_NAME` | no | — | Name for the new CloudFormation StackSet to create. Defaults to a timestamped pathrunner name |
| `REGION` | no | `us-east-1` | AWS region for CloudFormation and IAM operations |
| `ASSUME_ROLE` | no | `true` | Attempt to assume the escalated role after the StackSet deployment completes |
| `ESCALATED_ROLE_NAME` | no | — | Name for the escalated IAM role to create (auto-generated if empty) |
| `TRUST_PRINCIPAL` | no | — | ARN to trust in the escalated role's trust policy (defaults to caller ARN) |
| `CLEANUP` | no | `false` | Delete the StackSet and its stack instances after execution. Requires cloudformation:DeleteStackInstances and cloudformation:DeleteStackSet |

## Compatible payloads

- `backdoor/attach-policy` — Create an IAM role with AdministratorAccess trusted by the attacker's principal via CloudFormation template

## References

- [Pathfinding Cloud - cloudformation-003](https://pathfinding.cloud/paths/cloudformation-003)
- [AWS IAM Privilege Escalation – Methods and Mitigation (Rhino Security Labs)](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [How to implement the principle of least privilege with CloudFormation StackSets (AWS Security Blog)](https://aws.amazon.com/blogs/security/how-to-implement-the-principle-of-least-privilege-with-cloudformation-stacksets/)
- [Grant self-managed permissions (AWS CloudFormation Documentation)](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs-self-managed.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0003 - Persistence
- **Techniques:** T1098.001 - Account Manipulation: Additional Cloud Credentials

