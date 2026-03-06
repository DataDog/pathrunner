---
name: create-module
description: Create a new pathrunner exploit module from pathfinding.cloud path definition
argument-hint: "<pathfinding-cloud-id> (e.g., ecs-001, iam-014, lambda-002)"
---

# Create Pathrunner Module

You are creating a new pathrunner exploit module. The user has provided a pathfinding-cloud ID (e.g., `ecs-001`). Your job is to:

1. Read all source data for this path
2. Analyze the demo_attack.sh for operational details (timing, retries, payload behavior)
3. Generate the Go exploit module + payloads (reusing existing where possible)
4. Wire up registration, cleanup handlers, and imports
5. Verify the build compiles and tests pass

## Source Data

Read these files to understand the attack path. Extract the service from the ID (e.g., `lambda` from `lambda-002`).

You MUST read all four files before proceeding to Step 1:

1. **Path definition (source of truth):** Use Glob to find the YAML at `/Users/seth.art/Documents/projects/pathfinding.cloud/data/paths/{service}/{id}.yaml` and Read it
2. **Lab scenario:** Use Grep to find the matching `scenario.yaml` by searching for the ID in `/Users/seth.art/Documents/projects/pathfinding-labs/modules/scenarios/`, then Read it
3. **Demo attack script:** Read `demo_attack.sh` from the same scenario directory found in step 2
4. **Cleanup script:** Read `cleanup_attack.sh` from the same scenario directory found in step 2

## Steps

### Step 1: Parse and Validate

- Extract the service from the ID (e.g., `ecs` from `ecs-001`)
- Read all source data above
- Determine the category from the YAML (new-passrole, self-escalation, principal-access, existing-passrole, credential-access)
- Check if a module already exists: `grep -r '"$ARGUMENTS"' pkg/exploits/`
- If module exists, inform the user and stop

### Step 2: Analyze demo_attack.sh for Operational Details

**CRITICAL**: The demo_attack.sh script is the most important source of operational knowledge. It contains battle-tested timing, retry logic, and payload behavior that MUST be reflected in the module. Extract and document ALL of the following before writing any code:

#### 2a. Timing and Delays
- What `sleep` commands exist and what are they waiting for? (e.g., function initialization, policy propagation, event source mapping activation)
- What are the specific delay durations? Use these exact values — they were calibrated through testing.
- Are there polling loops? What are their intervals and max attempt counts?

#### 2b. Retry Logic
- Does the script retry operations? How many times and with what interval?
- What conditions trigger a retry vs a failure?
- What is the total max wait time? (e.g., `MAX_ATTEMPTS=30` * `sleep 10` = 5 minutes)
- These retry parameters must be translated directly into the module's Execute() method.

#### 2c. Payload Behavior (What the attack actually DOES)
- What specific AWS API calls does the injected code make? (e.g., `iam.attach_user_policy`, `iam.create_role`, `sts.get_caller_identity`)
- Does the payload need to return data to the caller, or does it take action independently?
- **For event-triggered modules** (ESM, CloudWatch Events, etc.): the function output is NOT returned to the attacker. Only payloads that take direct action (IAM modifications, webhook exfil) are useful. Payloads like `exfil/output` that rely on capturing the function response will NOT work.
- **For directly-invoked modules** (lambda:InvokeFunction, etc.): the function response IS captured, so `exfil/output` payloads work fine.

#### 2d. Resource Discovery
- Does the script discover resources dynamically? (e.g., `aws dynamodb describe-table` to get stream ARN)
- What environment variables or parameters does it extract from terraform/context?
- Which of these should become module Options vs discovered at runtime?

#### 2e. Verification Steps
- How does the script verify the exploit succeeded? (e.g., polling for policy attachment, listing users)
- For event-triggered modules: the payload SHOULD implement the `Verifiable` interface so the module can confirm the payload executed. The verification method should test the payload's effect using the starting user's credentials (e.g., call `iam:ListUsers` to check if admin policy was attached).
- For direct-invoke modules: verification usually comes from inspecting the function response.

#### 2f. Cleanup Permissions
- Does the starting user have permission to delete what they create? (Check the IAM policy in the Terraform module)
- If NOT: default `CLEANUP` to "false" and advise using `workspace cleanup` with admin credentials
- This is common — e.g., lambda-002 starting user has CreateFunction but NOT DeleteFunction

### Step 3: Check Existing Payloads and Determine What's Needed

- Check if `pkg/payloads/{service}/` directory exists
- If YES: list existing payloads and evaluate which are compatible
- **Match the payload to what demo_attack.sh does**: If the demo script attaches a policy to a user, don't use a payload that creates a new user. Create a new payload that matches the demo behavior if none exists.
- For event-triggered modules: exclude `exfil/output` from the recommended payloads since there's no caller to receive the response
- Only create new payloads when the exploitation pattern requires something not already available
- Not all modules need payloads — self-escalation and principal-access modules typically don't

### Step 4: Create the Module

Read the patterns from the skill supporting files:
- `.claude/skills/create-module/module-patterns.md` — Go templates by category
- `.claude/skills/create-module/payload-patterns.md` — Payload templates and reuse guide

Create the module at `pkg/exploits/{service}_{technique}/module.go`:
- Embed `BaseModule` with full `PathInfo` populated from the YAML
- Implement `Options()` with appropriate options derived from the demo_attack.sh
- Implement `Execute()` by translating demo_attack.sh to Go AWS SDK v2 calls
- If payload-based: implement `PayloadCompatible` interface
- Track ALL created resources via `tracker.TrackResource()` with:
  - `ModuleID` set to the path ID
  - `Metadata` including everything needed for cleanup
- After execution, check if payload implements `SideEffectReporter` and track any side effects
- For Lambda payloads: pass payload options via Lambda environment variables (build `envVars` map and set on `CreateFunctionInput.Environment`)
- Output credentials using `PATHFINDER_IDENTITY_DATA` structured format when applicable

**Timing and retry logic in Execute()**: Translate the demo script's timing directly:
- Use the same sleep durations (e.g., if demo sleeps 10s after function creation, do the same)
- Implement polling loops with the same max attempts and intervals from the demo script
- If the demo script retries an operation N times with M-second intervals, use those exact values
- Add progress output during waits so the user knows what's happening

### Step 5: Create New Payloads (if needed)

Only if Step 3 determined new payloads are needed:
- Create at `pkg/payloads/{service}/{technique}_{method}.go`
- Follow the patterns in `payload-patterns.md`
- Register via `init()` function
- Add new tag constants to `pkg/payloads/tags.go` if new service
- **The payload's Python/bash code should mirror what demo_attack.sh injects** — use the same API calls, error handling, and logic
- **For event-triggered modules**: Implement the `Verifiable` interface so the module can verify the payload executed
- **For payloads that modify existing resources**: Implement the `SideEffectReporter` interface so modifications are tracked for cleanup
- **For Lambda payloads**: Use `os.environ.get()` to read parameters from Lambda environment variables instead of hardcoding them in the Python source

### Step 6: Add Cleanup Handlers

Check `pkg/core/repl/session.go` `cleanupResource()` switch statement.
If the module creates resource types not already handled:
- Add new cases to the switch
- Implement cleanup functions following the existing pattern
- Import any new AWS SDK service packages needed

**Check demo_attack.sh AND cleanup_attack.sh** to identify ALL resource types created:
- Lambda functions, event source mappings, IAM roles/users/policies, EC2 instances, ECS services, etc.
- The cleanup script shows exactly what needs to be reversed — each cleanup step maps to a resource type

### Step 7: Wire Up Registration

- Add blank import in `cmd/pathrunner/main.go` for the new module package
- If new payload service directory, add blank import for that too
- Verify `init()` function calls `modules.Register()` correctly

### Step 8: Build and Verify

Run:
```bash
go build ./...
```

Fix any compilation errors.

### Step 9: Create Tests

Add unit tests in `tests/unit/`:
- Verify module loads by primary ID and aliases
- Verify PathInfo fields are correct

Add integration tests in `tests/integration/`:
- Verify `use {service}-{number}` works
- Verify `show info` displays correct metadata
- Verify `search {service}` finds the module

### Step 10: Run Tests

```bash
go test ./tests/...
```

Fix any test failures.

### Step 11: Final Verification

Run through the checklist in `.claude/skills/create-module/checklist.md` and confirm every item passes.

Report to the user:
- Module created: `{service}-{number}` at `pkg/exploits/{service}_{technique}/module.go`
- Payloads: list which were reused vs newly created, and WHY (reference demo_attack.sh behavior)
- Timing: list key delays and retry parameters extracted from demo_attack.sh
- Cleanup handlers: list any new ones added
- Test results: all passing
- Next step: deploy the lab scenario and run `/test-module` to verify against real AWS
