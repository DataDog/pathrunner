---
name: create-module
description: Create a new pathrunner exploit module from pathfinding.cloud path definition
disable-model-invocation: true
argument-hint: "<pathfinding-cloud-id> (e.g., ecs-001, iam-014, lambda-002)"
---

# Create Pathrunner Module

You are creating a new pathrunner exploit module. The user has provided a pathfinding-cloud ID (e.g., `ecs-001`). Your job is to:

1. Read all source data for this path
2. Generate the Go exploit module + payloads (reusing existing where possible)
3. Wire up registration, cleanup handlers, and imports
4. Verify the build compiles and tests pass

## Source Data

Read these files to understand the attack path. Replace `$ARGUMENTS` with the provided ID.

**Path definition (source of truth):**
!`SERVICE=$(echo "$ARGUMENTS" | sed 's/-.*//' ); find /Users/seth.art/Documents/projects/pathfinding.cloud/data/paths/$SERVICE -name "$ARGUMENTS.yaml" 2>/dev/null | head -1 | xargs cat 2>/dev/null || echo "YAML not found for $ARGUMENTS"`

**Lab scenario (find matching scenario):**
!`grep -rl "pathfinding-cloud-id.*$ARGUMENTS" /Users/seth.art/Documents/projects/pathfinding-labs/modules/scenarios/*/scenario.yaml 2>/dev/null | head -1 | xargs cat 2>/dev/null || echo "No scenario.yaml found for $ARGUMENTS"`

**Demo attack script (the shell commands we're translating to Go):**
!`grep -rl "pathfinding-cloud-id.*$ARGUMENTS" /Users/seth.art/Documents/projects/pathfinding-labs/modules/scenarios/*/scenario.yaml 2>/dev/null | head -1 | sed 's/scenario.yaml/demo_attack.sh/' | xargs cat 2>/dev/null || echo "No demo_attack.sh found for $ARGUMENTS"`

**Cleanup script (resources the module must track):**
!`grep -rl "pathfinding-cloud-id.*$ARGUMENTS" /Users/seth.art/Documents/projects/pathfinding-labs/modules/scenarios/*/scenario.yaml 2>/dev/null | head -1 | sed 's/scenario.yaml/cleanup_attack.sh/' | xargs cat 2>/dev/null || echo "No cleanup_attack.sh found for $ARGUMENTS"`

## Steps

### Step 1: Parse and Validate

- Extract the service from the ID (e.g., `ecs` from `ecs-001`)
- Read all source data above
- Determine the category from the YAML (new-passrole, self-escalation, principal-access, existing-passrole, credential-access)
- Check if a module already exists: `grep -r '"$ARGUMENTS"' pkg/exploits/`
- If module exists, inform the user and stop

### Step 2: Check Existing Payloads

- Check if `pkg/payloads/{service}/` directory exists
- If YES: list existing payloads and evaluate which are compatible
- Only create new payloads when the exploitation pattern requires something new
- For services without any payloads yet, create at minimum `exfil/output`
- Not all modules need payloads — self-escalation and principal-access modules typically don't

### Step 3: Create the Module

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
- Output credentials using `PATHFINDER_IDENTITY_DATA` structured format when applicable

### Step 4: Create New Payloads (if needed)

Only if Step 2 determined new payloads are needed:
- Create at `pkg/payloads/{service}/{technique}_{method}.go`
- Follow the patterns in `payload-patterns.md`
- Register via `init()` function
- Add new tag constants to `pkg/payloads/tags.go` if new service

### Step 5: Add Cleanup Handlers

Check `pkg/core/repl/session.go` `cleanupResource()` switch statement.
If the module creates resource types not already handled:
- Add new cases to the switch
- Implement cleanup functions following the existing pattern
- Import any new AWS SDK service packages needed

### Step 6: Wire Up Registration

- Add blank import in `cmd/pathrunner/main.go` for the new module package
- If new payload service directory, add blank import for that too
- Verify `init()` function calls `modules.Register()` correctly

### Step 7: Build and Verify

Run:
```bash
go build ./...
```

Fix any compilation errors.

### Step 8: Create Tests

Add unit tests in `tests/unit/`:
- Verify module loads by primary ID and aliases
- Verify PathInfo fields are correct

Add integration tests in `tests/integration/`:
- Verify `use {service}-{number}` works
- Verify `show info` displays correct metadata
- Verify `search {service}` finds the module

### Step 9: Run Tests

```bash
go test ./tests/...
```

Fix any test failures.

### Step 10: Final Verification

Run through the checklist in `.claude/skills/create-module/checklist.md` and confirm every item passes.

Report to the user:
- Module created: `{service}-{number}` at `pkg/exploits/{service}_{technique}/module.go`
- Payloads: list which were reused vs newly created
- Cleanup handlers: list any new ones added
- Test results: all passing
- Next step: deploy the lab scenario and run `/test-module` to verify against real AWS
