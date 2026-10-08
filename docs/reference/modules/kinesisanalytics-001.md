# `kinesisanalytics-001` — iam:PassRole + kinesisanalytics:CreateApplication + kinesisanalytics:StartApplication

|  |  |
|---|---|
| ID | `kinesisanalytics-001` |
| Category | new-passrole |
| Services | iam, kinesisanalytics |
| Author | Seth Art |
| Aliases | `kinesisanalytics-passrole`, `exploit/kinesisanalytics_passrole` |
| pathfinding.cloud | https://pathfinding.cloud/paths/kinesisanalytics-001 |

Create a Managed Apache Flink application with a privileged service execution role, start it to execute a malicious JAR from S3 with the role's credentials.

## Required permissions

- `iam:PassRole` — Must be able to pass the target admin IAM role to kinesisanalytics.amazonaws.com
- `kinesisanalytics:CreateApplication`
- `kinesisanalytics:StartApplication`

## Additional permissions

- `kinesisanalytics:DescribeApplication` — Poll application status to confirm execution
- `iam:ListAttachedUserPolicies` — Verify backdoor/attach-policy payload succeeded

## Prerequisites

**Admin:**
- IAM role trusting kinesisanalytics.amazonaws.com with administrative permissions
- S3 bucket accessible to the Flink application's execution role containing the payload JAR

**Lateral:**
- IAM role trusting kinesisanalytics.amazonaws.com with elevated permissions
- S3 bucket accessible to the Flink application's execution role containing the payload JAR

## Options

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ROLE_ARN` | yes | — | IAM role ARN to pass as the Flink application service execution role (must trust kinesisanalytics.amazonaws.com) |
| `PAYLOAD` | yes | — | Payload type to execute (backdoor/attach-policy, exfil/https, exfil/s3) |
| `CODE_BUCKET` | no | — | S3 bucket containing the payload JAR. Auto-resolved from the attacker code bucket if unset. |
| `CODE_KEY` | no | — | S3 key of the payload JAR within CODE_BUCKET. Auto-resolved from the payload's JAR key if unset. |
| `LOCAL_JAR` | no | — | Local path to the payload JAR to upload to the attacker code bucket. Required when using the attacker code bucket and the JAR has not been uploaded yet. Example: ../pathfinding-labs/.../exploit-jar/exploit.jar |
| `APP_NAME` | no | — | Managed Apache Flink application name (auto-generated if unset) |
| `REGION` | no | `us-east-1` | AWS region for the Flink application |
| `CLEANUP` | no | `false` | Stop and delete the Flink application after execution (requires kinesisanalytics:StopApplication and kinesisanalytics:DeleteApplication) |

## Compatible payloads

- `backdoor/attach-policy` — Attach an IAM policy to a user or role via a Managed Apache Flink application running with an admin execution role
- `exfil/https` — Exfiltrate execution role credentials to an attacker HTTPS endpoint via a Managed Apache Flink application
- `exfil/s3` — Exfiltrate execution role credentials to an attacker-controlled S3 bucket via a Managed Apache Flink application

## References

- [Pathfinding Cloud - kinesisanalytics-001](https://pathfinding.cloud/paths/kinesisanalytics-001)
- [Actions defined by Amazon Kinesis Data Analytics](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonkinesisdataanalytics.html)

## MITRE ATT&CK

- **Tactics:** TA0004 - Privilege Escalation, TA0002 - Execution
- **Techniques:** T1078.004 - Valid Accounts: Cloud Accounts, T1578 - Modify Cloud Compute Infrastructure

