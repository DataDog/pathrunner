# `cloudformation-001` — iam:PassRole + cloudformation:CreateStack

|  |  |
|---|---|
| ID | `cloudformation-001` |
| Category | new-passrole |
| Services | iam, cloudformation |
| Author | Seth Art |
| Aliases | `cloudformation-passrole`, `cfn-001`, `exploit/cloudformation_passrole` |
| pathfinding.cloud | https://pathfinding.cloud/paths/cloudformation-001 |

A principal with iam:PassRole and cloudformation:CreateStack can create a new CloudFormation stack that provisions AWS resources using the permissions of a passed IAM role. When the passed role has administrative permissions, the template can create resources that grant the attacker escalated access — such as a new IAM role with AdministratorAccess that trusts the attacker's principal for sts:AssumeRole.

## Required permissions

- `iam:PassRole` — Target CloudFormation service role ARN must be in Resource
- `cloudformation:CreateStack` — Create a new CloudFormation stack

## Additional permissions

- `cloudformation:DescribeStacks` — Poll for stack creation completion
- `cloudformation:DeleteStack` — Clean up the attack stack after exploitation
- `iam:ListRoles` — Discover available CloudFormation-trusted roles to pass

## Prerequisites

**Admin:**
- A role must exist that trusts cloudformation.amazonaws.com as a service principal
- The role must have administrative permissions (e.g., AdministratorAccess)

**Lateral:**
- A role must exist that trusts cloudformation.amazonaws.com as a service principal

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | ARN of the IAM role to pass to CloudFormation (must trust cloudformation.amazonaws.com) |
| `PAYLOAD` | no | `backdoor/attach-policy` | Payload type for the CloudFormation template (backdoor/attach-policy) |
| `STACK_NAME` | no | — | Name for the CloudFormation stack to create. Auto-generated if not set |
| `REGION` | no | `us-east-1` | AWS region for CloudFormation and IAM operations |
| `ASSUME_ROLE` | no | `true` | Assume the escalated role after the stack completes |
| `ESCALATED_ROLE_NAME` | no | — | Name for the escalated IAM role to create (auto-generated if empty) |
| `TRUST_PRINCIPAL` | no | — | ARN to trust in the escalated role's trust policy (defaults to caller ARN) |
| `CLEANUP` | no | `false` | Delete the CloudFormation stack after execution. Requires cloudformation:DeleteStack |

## Compatible payloads

- `backdoor/attach-policy` — Create an IAM role with AdministratorAccess trusted by the attacker's principal via CloudFormation template

## References

- [Pathfinding Cloud - cloudformation-001](https://pathfinding.cloud/paths/cloudformation-001)
- [AWS Privilege Escalation Methods and Mitigation - Rhino Security Labs](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [HackingTheCloud - PassRole + CloudFormation CreateStack](https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/#iampassrole-cloudformationcreatestack)
- [IAM Vulnerable - PassExistingRoleToCloudFormation](https://github.com/BishopFox/iam-vulnerable/blob/main/modules/free-resources/privesc-paths/privesc20-PassExistingRoleToCloudFormation.tf)
- [HackTricks - AWS CloudFormation Privesc](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-cloudformation-privesc/index.html#iampassrole-cloudformationcreatestack)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0003 - Persistence
- **Techniques:** T1098.001 - Account Manipulation: Additional Cloud Credentials

