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

1. **Path definition (source of truth):** Use Glob to find the YAML at `../pathfinding.cloud/data/paths/{service}/{id}.yaml` (relative to the pathrunner repo root) and Read it
2. **Lab scenario:** Use Grep to find the matching `scenario.yaml` by searching for the ID in `../pathfinding-labs/modules/scenarios/`, then Read it
3. **Demo attack script:** Read `demo_attack.sh` from the same scenario directory found in step 2
4. **Cleanup script:** Read `cleanup_attack.sh` from the same scenario directory found in step 2

## Steps

### Step 0: SSO Preflight

Before any AWS-touching work, verify the SSO profiles you'll need are still alive. Both plabs and pathrunner's attacker identity commonly use short-term SSO profiles that expire silently.

```bash
./scripts/check-sso.sh plabs
```

If any profile shows FAIL/EXPIRED, tell the user which and stop — they need to run `aws sso login --profile <name>` interactively before you can proceed. Do NOT try to work around expired SSO by using `SKIP_SSO_CHECK=1` unless the user explicitly asks.

If the module will use attacker infra (any `revshell/*`, `exfil/https`, `exfil/s3`, or a Glue-style module uploading to the attacker code bucket), also verify the attacker profile: `./scripts/check-sso.sh check <attacker-profile-name>`. Discover the profile name via `./pathrunner attacker show`.

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

The payload registry is **modular and service-scoped**: payloads live under `pkg/payloads/{service}/` (`ec2/`, `lambda/`, `glue/`), self-register in `init()`, and are queried by tag (`payloads.GetPayloadsByTags`, `payloads.GetPayloadForService`). Same logical name (e.g., `backdoor/attach-policy`) can exist under multiple services — the composite `(service, name)` key disambiguates. Your module doesn't enumerate specific payloads; it declares service tags via `GetCompatibleTags()` and every registered payload for that service becomes selectable.

- Check if `pkg/payloads/{service}/` directory exists
- If YES: list existing payloads and evaluate which are compatible
- **Match the payload to what demo_attack.sh does**: If the demo script attaches a policy to a user, don't use a payload that creates a new user. Create a new payload that matches the demo behavior if none exists.
- For event-triggered modules: exclude `exfil/response` from the recommended payloads since there's no caller to receive the response
- Only create new payloads when the exploitation pattern requires something not already available
- Not all modules need payloads — self-escalation and principal-access modules typically don't
- **If the payload depends on attacker infra** (listener callback, exfil bucket): note it now. The module itself does NOT need to know — the payload declares its own options (`LISTENER_IP`, `HTTPS_URL`, `EXFIL_BUCKET`, etc.) and pathrunner auto-populates them from the running listener / deployed bucket. See `payload-patterns.md` for the auto-inject contract.

### Step 4: Create the Module — Start From a Canonical Example

Rather than assembling the module from a list of rules, **copy the canonical module for your category and adapt it**. The canonicals below are known-good, tested, and idiomatic — they demonstrate the current signatures (`modules.ExecutionContext`), the `shared.PayloadHelper` for tag-based payload wiring, resource tracking, side-effect tracking, and (where applicable) attacker-infra integration. Read the canonical end-to-end before writing anything.

| Your module's shape | Canonical to copy | Read it because it demonstrates |
|---|---|---|
| **new-passrole** — provision a fresh compute resource with a privileged role and run a payload on it | `pkg/exploits/ec2_passrole/module.go` (ec2-001) | `shared.NewPayloadHelper(serviceTag, langTag)` for one-line payload wiring, `Discoverable` for AWS-side option enumeration, auto-detection of infra defaults (AMI, VPC, subnet), tracking the created compute resource, tracking payload `SideEffectReporter` output, `ExecutionContext` signature |
| **existing-passrole** — modify an existing resource's code/config to inherit its role's permissions | `pkg/exploits/lambda_updatecode_addpermission/module.go` (lambda-005) | Backing up original state before mutating so cleanup can restore it, injecting payload params directly into the generated code when the AWS API can't set env vars, tracking a policy/permission grant separately from the code change, handler-name adaptation, waiting for propagation only when the payload takes IAM action (SideEffectReporter check), CLEANUP defaulting to true because the caller can reverse everything |
| **new-passrole with attacker code artifacts** — payload must be hosted somewhere the victim service can fetch it from (Glue script, CodeBuild source, etc.) | `pkg/exploits/glue_passrole_job/module.go` (glue-003) | Using `ectx.AttackerIdentity` (separate from victim identity) to upload payload script to `attacker.GetCodeBucketInfo()` bucket, namespacing uploads under a per-run S3 prefix and cleaning them up (but leaving the bucket itself since it's persistent attacker infra), auto-populating `EXFIL_BUCKET` from `attacker.GetExfilBucket()`, auto-resolving `TARGET_USER` from the caller identity, passing payload options via job arguments (Glue `DefaultArguments`), verifying via the payload's `Verifiable` interface |

**For categories not covered by those three canonicals** — `self-escalation`, `principal-access`, `credential-access`, event-triggered `new-passrole` — grep `pkg/exploits/*/module.go` for the closest existing module in the same category and use it as your starting point. `iam_*` directories are all self-escalation or two-step; `sts_assume_role/` is principal-access; `lambda_passrole_esm/` is event-triggered new-passrole. If nothing quite matches, start from the closest canonical above and diverge only where the path genuinely demands it.

Once you've read the canonical, create `pkg/exploits/{service}_{technique}/module.go` by copying its shape and editing:
- `PathInfo` — populate from the YAML (ID, Name, Category, Services, Description, Permissions, Prerequisites, References, MITRE, Aliases)
- `Options()` — derive from demo_attack.sh's parameters, mirroring the canonical's naming style
- `Execute()` — translate demo_attack.sh's API calls, sleeps, retries, and verification into the canonical's flow. Use the demo's exact sleep durations and retry counts (they were calibrated through real testing).

The supporting files (`module-patterns.md`, `payload-patterns.md`, `checklist.md`) are reference material for cross-cutting concerns (registration mechanics, attacker-infra auto-injection contract, payload interface semantics, post-creation checklist) — consult them when a specific concern comes up, but don't try to follow them linearly.

### Step 5: Create New Payloads (if needed)

Only if Step 3 determined new payloads are needed. Rather than assembling from a rule list, **copy the closest existing payload in the same service and adapt it**:

- Match by shape, not just service: for a new IAM-modifying backdoor, copy `pkg/payloads/{service}/backdoor_attach_policy.go` and adjust the AWS API call and `SideEffectReporter` output; for a new out-of-band exfil, copy `exfil_https.go` or `exfil_s3.go`; for a new reverse shell, copy `revshell_tls.go`.
- Payload lives at `pkg/payloads/{service}/{technique}_{method}.go`; `init()` calls `payloads.Register(&MyPayload{})`. No wiring changes needed if the service directory already exists.
- If your payload is the first under a new service directory (e.g., first `pkg/payloads/ecs/…`), add a blank import to `cmd/pathrunner/main.go` and add the service tag to `pkg/payloads/tags.go`.
- The payload's Python/bash code should mirror what demo_attack.sh injects — same API calls, same error handling.
- If the payload takes IAM action (attaches policy, creates user, etc.): implement `SideEffectReporter` so the module can track modifications for cleanup (`pkg/payloads/lambda/backdoor_attach_policy.go` is the reference implementation).
- If the module is event-triggered (payload runs but its return value isn't captured): implement `Verifiable` so the module can confirm the effect via a follow-up API call (`pkg/payloads/lambda/backdoor_attach_policy.go` also demonstrates this).
- Lambda/Glue payloads read runtime params from `os.environ` (Python) or job args; EC2 payloads read shell env. Never string-substitute values into the source at code-gen time.
- If the payload depends on attacker infra (listener callback, exfil bucket), use the standard option names so the auto-inject/auto-populate wiring picks them up — see `payload-patterns.md` for the full contract.

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

- Verify the module's `init()` function calls `modules.Register("{id}", constructor)` — the primary key must be the pathfinding.cloud ID.
- **Exploit modules are picked up automatically**: `pkg/exploits/register.go` is generated by `scripts/gen_register.go` (invoked via `//go:generate` in `pkg/exploits/gen.go`). Running `make build` — or `go generate ./pkg/exploits/` — regenerates it and adds a blank import for your new directory. Do NOT edit `cmd/pathrunner/main.go` for a new exploit module.
- **Payloads are still wired manually**: If you introduced a new payload service directory (e.g., first payload under `pkg/payloads/ecs/`), add a blank import for it in `cmd/pathrunner/main.go` alongside the existing `pkg/payloads/{ec2,lambda,glue}` imports. Payloads within an existing service directory need no wiring changes — `init()` handles it.

### Step 8: Build and Verify

Run:
```bash
make build
```

`make build` runs `go generate ./pkg/exploits/` before compiling, so it regenerates `register.go` and then builds. If you prefer raw Go commands, run `go generate ./pkg/exploits/ && go build ./...`.

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

Run through the sibling `checklist.md` in this skill directory and confirm every item passes.

Report to the user:
- Module created: `{service}-{number}` at `pkg/exploits/{service}_{technique}/module.go`
- Payloads: list which were reused vs newly created, and WHY (reference demo_attack.sh behavior)
- Timing: list key delays and retry parameters extracted from demo_attack.sh
- Cleanup handlers: list any new ones added
- Test results: all passing
- Next step: deploy the lab scenario and run `/test-module <id> --iterate 5` to verify against real AWS. `test-module` will iterate up to 5 attempts on pathrunner-side failures (compile errors, wrong ARN parses, missing env vars, timing bugs) with hard-stops on lab-side or environmental failures.
