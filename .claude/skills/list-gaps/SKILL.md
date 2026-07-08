---
name: list-gaps
description: List pathfinding-labs scenarios that don't have pathrunner modules yet
context: fork
argument-hint: "[service] (optional filter, e.g., lambda, ecs, iam)"
allowed-tools: Bash, Read, Glob, Grep
---

# List Coverage Gaps

Cross-reference pathfinding-labs scenarios against pathrunner's module registry to find gaps.

## Steps

### Step 1: Get All Pathfinding-Labs Scenarios

List all scenario.yaml files and extract their pathfinding-cloud-id:

Paths are relative to the pathrunner repo root (siblings `../pathfinding.cloud/` and `../pathfinding-labs/` under a shared `pathfinding/` parent).

```bash
# Note: scenarios/ has multi-level nesting (single-account/, cross-account/, ctf/, etc.)
# — must use `find` recursively, NOT a single-level glob.
# The plabs scenario ID is "{pathfinding-cloud-id}-{goal}" where goal is the parent
# directory name (to-admin, to-bucket, etc.), NOT the scenario directory name.
find ../pathfinding-labs/modules/scenarios/ -name "scenario.yaml" | while read -r f; do
    ID=$(grep 'pathfinding-cloud-id' "$f" 2>/dev/null | head -1 | sed 's/.*: *//' | tr -d '"' | tr -d "'")
    GOAL=$(basename "$(dirname "$(dirname "$f")")")
    if [ -n "$ID" ]; then
        echo "$ID|${ID}-${GOAL}"
    fi
done | sort
```

### Step 2: Get All Pathrunner Modules

List registered module IDs:

```bash
grep -r 'modules.Register(' pkg/exploits/*/module.go | sed 's/.*Register("\([^"]*\)".*/\1/' | sort
```

Or read `pkg/exploits/register.go` directly — it's the auto-generated fan-out of every registered module directory.

### Step 3: Cross-Reference

For each scenario ID, check if a pathrunner module exists.

### Step 4: Check Deployment Status

For scenarios without modules, check if they're deployed (useful for prioritizing):

```bash
(cd ../pathfinding-labs && ./plabs scenarios list) 2>&1
```

### Step 5: Apply Service Filter

If the user provided a service filter argument (`$ARGUMENTS`), only show gaps for that service.

### Step 6: Output Table

Format as a markdown table:

| Path ID | Scenario | Module Exists | Category | Services |
|---------|----------|--------------|----------|----------|
| ecs-001 | ecs-001-to-admin | No | new-passrole | iam, ecs |
| ecs-002 | ecs-002-to-admin | No | new-passrole | iam, ecs |
| ... | ... | ... | ... | ... |

Also show summary stats:
- Total paths with scenarios: X
- Paths with pathrunner modules: Y
- Gaps: Z
- Coverage: Y/X (percentage)

If filtered by service, show service-specific stats.
