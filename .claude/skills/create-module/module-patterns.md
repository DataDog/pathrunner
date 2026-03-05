# Module Code Patterns by Category

This document contains Go code templates extracted from existing pathrunner modules, organized by exploit category. Use these as the basis for new modules.

## Category: new-passrole — Direct Invoke (lambda-001, ec2-001)

Pattern: Create a new AWS resource with a privileged role attached, then directly invoke/execute code and capture the response.

### Template Structure

```go
package {service}_{technique}

import (
    "context"
    "fmt"
    "pathrunner/pkg/discovery"
    "pathrunner/pkg/modules"
    "pathrunner/pkg/payloads"
    "time"

    "github.com/aws/aws-sdk-go-v2/aws"
    // Import service-specific SDK packages
)

type Module struct {
    modules.BaseModule
}

func NewModule() *Module {
    return &Module{
        BaseModule: modules.BaseModule{
            Info: modules.PathInfo{
                ID:       "{service}-{number}",
                Name:     "{permission-based name from YAML}",
                Category: "new-passrole",
                Services: []string{"{service1}", "{service2}"},
                Description: "{description from YAML}",
                Permissions: modules.PermissionSet{
                    Required: []modules.Permission{
                        {Permission: "iam:PassRole", Description: "Target role ARN"},
                        // ... other required permissions
                    },
                    Additional: []modules.Permission{
                        // ... optional permissions
                    },
                },
                Prerequisites: modules.Prerequisites{
                    Admin: []string{
                        // What the admin needs to have set up
                    },
                    Lateral: []string{
                        // What the attacker needs
                    },
                },
                References: []modules.Reference{
                    {Title: "Pathfinding Cloud - {service}-{number}", URL: "https://pathfinding.cloud/paths/{service}-{number}"},
                },
                MITRE: &modules.MITREMapping{
                    Tactics:    []string{"TA0004 - Privilege Escalation"},
                    Techniques: []string{"T1078.004 - Valid Accounts: Cloud Accounts"},
                },
                Author:  "Seth Art",
                Aliases: []string{"{service}-{technique}", "exploit/{service}_{technique}"},
            },
        },
    }
}

func init() {
    modules.Register("{service}-{number}", func() modules.Module {
        return NewModule()
    })
}

func (m *Module) Options() []modules.Option {
    return []modules.Option{
        {Name: "ROLE_ARN", Description: "Target IAM role ARN", Required: true},
        {Name: "PAYLOAD", Description: "Payload type", Required: true},
        {Name: "REGION", Description: "AWS region", Required: false, Default: "us-east-1"},
        // ... service-specific options
    }
}

// Implement PayloadCompatible for payload-based modules
func (m *Module) GetCompatibleTags() []string {
    return []string{payloads.TagService{Service}, payloads.TagLanguage{Language}}
}

func (m *Module) GetPayloadContext() string {
    return payloads.TagService{Service}
}

// Implement Discoverable for auto-discovery of option values
// Only include options where the "additional" permissions in PathInfo enable enumeration
func (m *Module) DiscoverableOptions() []string {
    return []string{"ROLE_ARN"} // adjust based on module's discoverable options
}

func (m *Module) Discover(optionName string, identity *modules.Identity, currentOptions map[string]string) ([]modules.DiscoveryChoice, error) {
    config := identity.GetConfig()
    if region := currentOptions["REGION"]; region != "" {
        config.Region = region
    }
    switch optionName {
    case "ROLE_ARN":
        return discovery.DiscoverRolesForService(context.Background(), config, "{service}.amazonaws.com")
    default:
        return nil, fmt.Errorf("option '%s' does not support auto-discovery", optionName)
    }
}

func (m *Module) PayloadOptions(payloadName string) []modules.Option {
    payload, err := payloads.GetPayloadForService(payloadName, payloads.TagService{Service})
    if err != nil {
        return []modules.Option{}
    }
    return payload.GetOptions()
}

func (m *Module) ListPayloads() []modules.PayloadInfo {
    servicePayloads := payloads.GetPayloadsByTags([]string{payloads.TagService{Service}})
    var infos []modules.PayloadInfo
    for _, p := range servicePayloads {
        infos = append(infos, modules.PayloadInfo{Name: p.GetName(), Description: p.GetDescription()})
    }
    return infos
}

func (m *Module) Execute(identity *modules.Identity, options map[string]string, tracker modules.ResourceTracker) (string, error) {
    // 1. Parse and validate options
    roleArn := options["ROLE_ARN"]
    payloadType := options["PAYLOAD"]

    // 2. Get and validate payload
    payload, err := payloads.GetPayloadForService(payloadType, payloads.TagService{Service})
    if err != nil {
        return "", fmt.Errorf("unknown payload type: %s", payloadType)
    }
    if err := payload.Validate(options); err != nil {
        return "", fmt.Errorf("payload validation failed: %v", err)
    }

    // 3. Generate payload code
    code, err := payload.GenerateCode(options)
    if err != nil {
        return "", fmt.Errorf("failed to generate payload code: %v", err)
    }

    // 4. Configure AWS client
    config := identity.GetConfig()
    if region := options["REGION"]; region != "" {
        config.Region = region
    }

    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()

    // 5. Create resource with privileged role
    // ... AWS SDK calls to create the resource ...

    // 6. Track resource for cleanup
    if tracker != nil {
        tracker.TrackResource(modules.CreatedResource{
            Type:          "{service}:{resource-type}",
            Name:          resourceName,
            ARN:           resourceARN,
            Region:        config.Region,
            CleanupMethod: "{service}:{DeleteAction}",
            ModuleID:      "{service}-{number}",
            Metadata:      map[string]string{...},
        })
    }

    // 7. Execute/invoke the resource
    // ... invoke the function/instance/task ...

    // 8. Track payload side effects for cleanup
    if tracker != nil {
        if reporter, ok := payload.(payloads.SideEffectReporter); ok {
            for _, sideEffect := range reporter.ReportSideEffects(options) {
                sideEffect.ModuleID = "{service}-{number}"
                sideEffect.Region = config.Region
                tracker.TrackResource(sideEffect)
            }
        }
    }

    // 9. Process and return result
    result, err := payload.ProcessResult(rawResult)
    if err != nil {
        return rawResult, fmt.Errorf("failed to process result: %v", err)
    }
    return result, nil
}
```

## Category: new-passrole — Event-Triggered (lambda-002)

Pattern: Create a new AWS resource with a privileged role attached, configure an event trigger (DynamoDB stream, CloudWatch Events, SQS queue, etc.), then trigger execution indirectly and verify the effect.

### Key Differences from Direct Invoke
- **No function response is captured** — the function runs asynchronously via the event source
- **Only action-based payloads work** — `exfil/response` does NOT work; use `backdoor/attach-policy`, `backdoor/create-role`, `exfil/https`, etc.
- **Trigger-and-verify retry loop** — must repeatedly trigger the event and check if the payload's effect has been observed (e.g., policy attached, user created)
- **Payloads should implement `Verifiable`** — so the module can confirm the payload executed
- **Longer context timeouts** — the full attack with retries can take 5-10 minutes
- **Lambda environment variables** — pass payload parameters via env vars, not hardcoded in source
- **Starting user often lacks cleanup permissions** — default CLEANUP to "false"

### Template Structure

```go
func (m *Module) Execute(identity *modules.Identity, options map[string]string, tracker modules.ResourceTracker) (string, error) {
    // 1. Parse and validate options
    // 2. Get, validate, and generate payload code
    // 3. Configure AWS client with LONG timeout
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
    defer cancel()

    // 4. Build Lambda environment variables for payload parameters
    envVars := map[string]string{}
    if targetUser := options["TARGET_USER"]; targetUser != "" {
        envVars["TARGET_USER"] = targetUser
    }
    if policyArn := options["POLICY_ARN"]; policyArn != "" {
        envVars["POLICY_ARN"] = policyArn
    }

    // 5. Create resource (Lambda function) with privileged role + env vars
    createInput := &lambda.CreateFunctionInput{
        // ... standard fields ...
    }
    if len(envVars) > 0 {
        createInput.Environment = &types.Environment{Variables: envVars}
    }
    // ... create function, track resource ...

    // 6. Wait for function to become active
    // ... poll GetFunction until State=Active ...

    // 7. Create event source mapping (ESM)
    // ... CreateEventSourceMapping, track resource ...

    // 8. Wait for ESM to become Enabled (time-based, ~60s)
    // NOTE: ESM showing "Enabled" does NOT mean it's processing events yet!

    // 9. Trigger-and-verify retry loop
    //    This is the critical pattern for event-triggered modules.
    //    Extract retry params from demo_attack.sh (e.g., 30 attempts x 10s = 5 min)
    verifiable, isVerifiable := payload.(payloads.Verifiable)
    maxAttempts := 30  // from demo_attack.sh

    for attempt := 1; attempt <= maxAttempts; attempt++ {
        // Insert trigger record (DynamoDB PutItem, SQS SendMessage, etc.)
        // Wait ~5 seconds for Lambda to execute
        time.Sleep(5 * time.Second)

        // Verify payload effect
        if isVerifiable {
            success, _ := verifiable.VerifySuccess(ctx, config, options)
            if success {
                verified = true
                break
            }
        }

        // Wait before next attempt
        time.Sleep(5 * time.Second)
    }

    // 10. If verified, wait for IAM propagation (~15 seconds)
    if verified {
        time.Sleep(15 * time.Second)
    }

    // 11. Track payload side effects for cleanup
    if tracker != nil {
        if reporter, ok := payload.(payloads.SideEffectReporter); ok {
            for _, sideEffect := range reporter.ReportSideEffects(options) {
                sideEffect.ModuleID = "{service}-{number}"
                sideEffect.Region = config.Region
                tracker.TrackResource(sideEffect)
            }
        }
    }

    // 12. Build and return result
    return result.String(), nil
}
```

### Cleanup Permission Considerations

Starting users often have permissions to CREATE resources but NOT DELETE them (e.g., lambda:CreateFunction but not lambda:DeleteFunction). For event-triggered modules:

- Default the `CLEANUP` option to `"false"` — the starting user likely can't delete what they created
- Print a message telling the user to run `workspace cleanup` with admin credentials later
- The tracked resources + side effects will be cleaned up when the user switches to an admin identity

## Category: principal-access (sts-001)

Pattern: Use current credentials to assume a different role or access another principal's resources. No payload needed — the module produces credentials directly.

### Key Differences from new-passrole
- No payload system — module directly outputs credentials
- Uses `PATHFINDER_IDENTITY_DATA` format for auto-import
- Typically no resources to track/cleanup
- Simpler Execute() — just an API call + credential formatting

```go
func (m *Module) Execute(identity *modules.Identity, options map[string]string, tracker modules.ResourceTracker) (string, error) {
    // 1. Parse options (role ARN, session name, etc.)
    // 2. Make STS/IAM API call
    // 3. Format credentials in PATHFINDER_IDENTITY_DATA format

    var outputBuilder strings.Builder
    outputBuilder.WriteString("=== Results ===\n\n")
    // ... human-readable output ...

    // Structured credential output for auto-import
    outputBuilder.WriteString("\n--- PATHFINDER_IDENTITY_DATA ---\n")
    outputBuilder.WriteString(fmt.Sprintf("NAME=%s\n", identityName))
    outputBuilder.WriteString(fmt.Sprintf("TYPE=assumed_role\n"))
    outputBuilder.WriteString(fmt.Sprintf("ACCESS_KEY_ID=%s\n", accessKeyID))
    outputBuilder.WriteString(fmt.Sprintf("SECRET_ACCESS_KEY=%s\n", secretKey))
    outputBuilder.WriteString(fmt.Sprintf("SESSION_TOKEN=%s\n", sessionToken))
    outputBuilder.WriteString(fmt.Sprintf("REGION=%s\n", region))
    outputBuilder.WriteString(fmt.Sprintf("EXPIRES_AT=%s\n", expiresAt.Format(time.RFC3339)))
    outputBuilder.WriteString(fmt.Sprintf("AUTO_SWITCH=%s\n", options["AUTO_SWITCH"]))
    outputBuilder.WriteString("--- END_PATHFINDER_IDENTITY_DATA ---\n")

    return outputBuilder.String(), nil
}
```

## Category: self-escalation (iam-001 through iam-013)

Pattern: Modify the caller's own IAM policy/permissions to grant additional access. No payloads needed — the module makes IAM API calls directly. Resources are typically policy modifications that need to be reverted.

### Key Differences
- No payload system
- The "resource" tracked is a policy modification (attached policy, inline policy, policy version)
- Cleanup means reverting the policy change
- Must track enough metadata to undo the change

```go
func (m *Module) Execute(identity *modules.Identity, options map[string]string, tracker modules.ResourceTracker) (string, error) {
    // 1. Get current caller identity to determine who we're escalating
    // 2. Make the IAM modification (attach policy, put inline policy, create policy version, etc.)
    // 3. Track the modification as a resource for cleanup

    if tracker != nil {
        tracker.TrackResource(modules.CreatedResource{
            Type:          "iam:attached-policy",
            Name:          policyArn,
            Region:        "global",
            CleanupMethod: "iam:DetachRolePolicy",
            ModuleID:      "{service}-{number}",
            Metadata: map[string]string{
                "principal_type": "role",  // or "user"
                "principal_name": roleName,
                "policy_arn":     policyArn,
            },
        })
    }

    // 4. Verify escalation worked
    // 5. Output success message
    return "Privilege escalation successful. ..." , nil
}
```

## Category: two-step / existing-passrole (iam-014 through iam-021)

Pattern: Modify some resource (policy, role trust, etc.), then assume a role to gain the escalated permissions. Combines self-escalation + principal-access in two steps.

### Key Differences
- Two-phase execution: modify, then assume
- Tracks modifications AND produces credentials
- Needs cleanup for the modification step
- Outputs PATHFINDER_IDENTITY_DATA for the assumed role

```go
func (m *Module) Execute(identity *modules.Identity, options map[string]string, tracker modules.ResourceTracker) (string, error) {
    // Phase 1: Modify (e.g., update role trust policy, attach policy)
    // ... IAM modification ...
    // Track the modification

    // Phase 2: Assume the now-accessible role
    // ... sts:AssumeRole ...
    // Output PATHFINDER_IDENTITY_DATA

    return outputBuilder.String(), nil
}
```

## Category: credential-access

Pattern: Extract credentials from AWS services (Secrets Manager, SSM Parameter Store, EC2 metadata, etc.). No payloads needed. May not need resource tracking.

```go
func (m *Module) Execute(identity *modules.Identity, options map[string]string, tracker modules.ResourceTracker) (string, error) {
    // 1. Call AWS API to retrieve secret/parameter/credential
    // 2. Format and return the extracted data
    // 3. If credentials found, output in PATHFINDER_IDENTITY_DATA format
    return result, nil
}
```
