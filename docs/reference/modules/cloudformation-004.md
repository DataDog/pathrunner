# `cloudformation-004` — iam:PassRole + cloudformation:UpdateStackSet

|  |  |
|---|---|
| ID | `cloudformation-004` |
| Category | new-passrole |
| Services | iam, cloudformation |
| Author | Seth Art |
| Aliases | `cloudformation-updatestackset`, `cfn-004`, `exploit/cloudformation_updatestackset` |
| pathfinding.cloud | https://pathfinding.cloud/paths/cloudformation-004 |

A principal with iam:PassRole and cloudformation:UpdateStackSet can escalate privileges by modifying an existing CloudFormation StackSet that has a privileged execution role. Both permissions are required—cloudformation:UpdateStackSet alone is insufficient because the UpdateStackSet API call requires passing the administration role ARN, which necessitates iam:PassRole. The attacker injects a malicious IAM role into the StackSet template and passes the administration role ARN. CloudFormation's execution role provisions the new admin IAM role across all stack instances. The attacker then assumes that role for full admin access.

## Required permissions

- `iam:PassRole` — Must have permission to pass the administration role to CloudFormation StackSets
- `cloudformation:UpdateStackSet` — Must have permission to update the target CloudFormation StackSet

## Additional permissions

- `cloudformation:DescribeStackSet` — View StackSet details and retrieve current template
- `cloudformation:DescribeStackSetOperation` — Monitor StackSet update operation progress
- `cloudformation:ListStackInstances` — List stack instances to confirm deployment targets
- `iam:GetRole` — Verify the escalated role was created by the StackSet update

## Prerequisites

**Admin:**
- A CloudFormation StackSet must exist that the principal can update
- The StackSet must have an execution role with administrative permissions (e.g., AdministratorAccess)
- The StackSet must have at least one stack instance deployed

**Lateral:**
- A CloudFormation StackSet must exist that the principal can update
- The StackSet must have an execution role with elevated permissions to create the desired resources
- The StackSet must have deployed stack instances

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `STACKSET_NAME` | yes | — | Name of the existing CloudFormation StackSet with an admin execution role |
| `ADMIN_ROLE_ARN` | no | — | ARN of the administration role to pass to CloudFormation StackSets (requires iam:PassRole). Leave blank to auto-construct from account ID using the lab's default role name |
| `EXECUTION_ROLE_NAME` | no | — | Name of the execution role used by the StackSet in target accounts |
| `REGION` | no | `us-east-1` | AWS region for CloudFormation and IAM operations |
| `ASSUME_ROLE` | no | `true` | Attempt to assume the escalated role after the StackSet update completes |
| `PAYLOAD` | no | `backdoor/attach-policy` | Payload type for the CloudFormation StackSet template injection (backdoor/attach-policy) |
| `ESCALATED_ROLE_NAME` | no | — | Name for the escalated IAM role to create (auto-generated if empty) |
| `TRUST_PRINCIPAL` | no | — | ARN to trust in the escalated role's trust policy (defaults to caller ARN) |
| `CLEANUP` | no | `false` | Revert the StackSet to its original template after execution. Requires cloudformation:UpdateStackSet with the admin role |

## Compatible payloads

- `backdoor/attach-policy` — Create an IAM role with AdministratorAccess trusted by the attacker's principal via CloudFormation template

## References

- [Pathfinding Cloud - cloudformation-004](https://pathfinding.cloud/paths/cloudformation-004)
- [AWS IAM Privilege Escalation - Methods and Mitigation (Rhino Security Labs)](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [AWS CloudFormation Privilege Escalation (HackTricks)](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-cloudformation-privesc/index.html)
- [AWS CloudFormation Service Role Documentation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0003 - Persistence
- **Techniques:** T1098 - Account Manipulation, T1098.001 - Account Manipulation: Additional Cloud Credentials

