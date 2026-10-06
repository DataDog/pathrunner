# `imagebuilder-001` — iam:PassRole + imagebuilder:CreateComponent + imagebuilder:CreateImageRecipe + imagebuilder:CreateInfrastructureConfiguration + imagebuilder:CreateImage

|  |  |
|---|---|
| ID | `imagebuilder-001` |
| Category | new-passrole |
| Services | iam, imagebuilder, ec2 |
| Author | Zander Mackie (Datadog) |
| Aliases | `imagebuilder-passrole`, `exploit/imagebuilder_passrole` |
| pathfinding.cloud | https://pathfinding.cloud/paths/imagebuilder-001 |

A principal with iam:PassRole and EC2 Image Builder creation permissions can escalate privileges by building a pipeline: create a component containing malicious shell commands, add it to an image recipe, create an infrastructure configuration that passes an admin IAM instance profile, then trigger an image build. The Image Builder agent runs the component shell commands on an EC2 build instance with admin credentials available via IMDS.

## Required permissions

- `iam:PassRole` — Must be able to pass the target admin IAM instance profile role to the EC2 Image Builder service
- `imagebuilder:CreateComponent`
- `imagebuilder:CreateImageRecipe`
- `imagebuilder:CreateInfrastructureConfiguration`
- `imagebuilder:CreateImage`

## Additional permissions

- `imagebuilder:GetComponent` — Verify component creation
- `imagebuilder:GetImage` — Poll image build status
- `imagebuilder:GetImageRecipe` — Verify recipe configuration
- `imagebuilder:GetInfrastructureConfiguration` — Verify infrastructure configuration
- `imagebuilder:TagResource` — Required in some regions or configurations
- `ec2:DescribeImages` — Find the base AMI for the image recipe
- `imagebuilder:ListImages` — Discover existing images and build status
- `iam:ListAttachedUserPolicies` — Verify privilege escalation success

## Prerequisites

**Admin:**
- A role must exist that can be used as an EC2 instance profile (trusts ec2.amazonaws.com)
- The role must have administrative permissions (e.g., AdministratorAccess or equivalent)
- The AWS Image Builder service-linked role (AWSServiceRoleForImageBuilder) must exist in the account

**Lateral:**
- A role must exist that can be used as an EC2 instance profile and has elevated permissions
- The AWSServiceRoleForImageBuilder SLR must exist in the account

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `INSTANCE_PROFILE` | yes | — | Admin IAM instance profile NAME to pass to the Image Builder build EC2 instance (not ARN — the API requires the profile name) |
| `PAYLOAD` | yes | — | Payload type (backdoor/attach-policy) |
| `TARGET_ARN` | no | — | IAM user or role name/ARN to attach AdministratorAccess to (auto-resolved from caller identity if not set) |
| `REGION` | no | `us-east-1` | AWS region for Image Builder resources |
| `SUBNET_ID` | no | — | Subnet ID for the Image Builder build EC2 instance (uses default VPC subnet if omitted) |
| `SECURITY_GROUP_ID` | no | — | Security group ID for the build EC2 instance (optional; Image Builder uses the default SG if omitted) |
| `POLICY_ARN` | no | `arn:aws:iam::aws:policy/AdministratorAccess` | Policy ARN to attach to TARGET_ARN via the build component |
| `COMPONENT_NAME` | no | — | Name prefix for the Image Builder component (auto-generated if omitted) |
| `CLEANUP` | no | `false` | Delete Image Builder resources after execution (note: the starting user typically lacks imagebuilder:Delete* — use workspace cleanup with admin credentials) |

## Compatible payloads

- `backdoor/attach-policy` — Attach AdministratorAccess to an IAM user or role via EC2 Image Builder component using IMDS credentials

## References

- [Pathfinding Cloud - imagebuilder-001](https://pathfinding.cloud/paths/imagebuilder-001)
- [Actions defined by EC2 Image Builder](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2imagebuilder.html)
- [Security best practices in EC2 Image Builder](https://docs.aws.amazon.com/imagebuilder/latest/userguide/security-best-practices.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1578 - Modify Cloud Compute Infrastructure

