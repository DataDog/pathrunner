---
name: batch-modules
description: Batch-create pathrunner exploit modules from a list of pathfinding-labs coverage gaps, using a rolling pool of concurrent sub-agents that enable → build → test → disable each lab. Verify stage iteratively fixes pathrunner-side failures (default budget 5 per module). Uses multi-agent orchestration.
argument-hint: "[count] [--iterate N] (e.g., 5 --iterate 5) — count of gaps to process; iteration budget defaults to 5"
---

# Batch Module Creation

Automates the create → deploy-lab → build-module → test → tear-down-lab cycle across many gaps in parallel. Under the hood it invokes the `batch-modules` **workflow** (`.claude/workflows/batch-modules.js`), which pipelines items through four stages using a rolling pool of sub-agents. The `plabs-lifecycle` lock serializes terraform applies across concurrent items — no coordination code needed here beyond that.

**This skill spawns multiple sub-agents concurrently.** Only invoke when the user explicitly asks for batch/multi-agent module creation (e.g., "/batch-modules 5", "batch up 10", "work through the gap list"). Do not infer batching from a request to make a single module.

## Prerequisites — check before invoking

The workflow's Preflight phase does the first check for you (SSO profile freshness). The others are still worth confirming up front so you don't fail 5 minutes in.

1. **All plabs SSO profiles are alive**: `./scripts/check-sso.sh plabs`. Any expired profile will cause the workflow's Preflight phase to abort immediately. If it fails, run `aws sso login --profile <name>` for each expired one before invoking this skill. **This is now a hard failure at workflow start — do not proceed and hope the sub-agents will handle it.**
2. **Attacker AWS identity is set** and validated: `./pathrunner attacker validate`. Some scenarios need the attacker exfil bucket or code artifacts bucket. If the attacker identity is a profile, also check that its SSO is fresh: `./scripts/check-sso.sh check <attacker-profile-name>`.
3. **plabs is initialized and pointing at a real AWS account**: `(cd ../pathfinding-labs && ./plabs status)` runs without error. If not, tell the user to run `./plabs init` in the labs repo first.
4. **The lock is unlocked** (or held only by a live process you know about): `./scripts/plabs-lifecycle.sh lock-info`. If a stale/dead lock is shown, tell the user; don't `force-unlock` without asking.

Scenario starting credentials **do not** need to be pre-imported — the Enable stage auto-imports them via `plabs-lifecycle.sh enable`, so sub-agents in the Verify stage can just `./pathrunner identity switch <scenario-id>`.

If any of these fail, stop and surface the problem — don't proceed and leak half-deployed labs.

## Argument parsing

The user's `$ARGUMENTS` may contain:
- A count (integer, e.g. `5` or `10`), or empty (default `5`), or the word `all` (process every gap the list-gaps skill finds).
- `--iterate N` — Verify-stage fix-and-retry budget per module. Default `5`. Set `1` to disable iteration and fail on first error; higher values give sub-agents more slack to chase down harder bugs.

Examples:
- `/batch-modules 5` → 5 gaps, iteration budget 5
- `/batch-modules 10 --iterate 3` → 10 gaps, iteration budget 3 per module
- `/batch-modules all --iterate 1` → every gap, no iteration (fail fast)

## Steps

### Step 1: Discover gaps

Invoke the `list-gaps` skill to produce the coverage-gap table. The output is a markdown table with columns: `Path ID | Scenario | Module Exists | Category | Services`.

Parse the table into a JSON array of `{ pathId, scenarioId, category, services }` records. Filter to rows where `Module Exists = No`. If a `service` filter argument was provided, restrict further.

**IMPORTANT**: The `scenarioId` must be the plabs-registered ID (e.g., `ecs-001-to-admin`), NOT the directory name (e.g., `ecs-001-iam-passrole+ecs-createcluster+...`). The Scenario column from list-gaps already uses the correct format: `{pathfinding-cloud-id}-{goal}` where goal is typically `to-admin`.

If the resulting list is empty, tell the user "no gaps remaining" and stop.

### Step 2: Trim to the requested count

Take the first N entries from the gap list, where N is the parsed count (default 5, or all).

**Show the user the exact list you're about to work on**, one line per gap: `pathId — scenarioId — category — services`. Ask for confirmation before proceeding unless the user's original message clearly authorized the specific batch (e.g., "batch these five: X, Y, Z, ..."). This is a heavyweight operation — the deploy phase alone can take minutes and costs money.

### Step 3: Bootstrap payload service directories

Multiple sub-agents will work on modules concurrently. If two agents both try to create `pkg/payloads/{service}/` and add its blank import to `main.go` at the same time, they'll collide. Pre-create any missing service directories before the workflow starts.

Extract the unique services from the gap list (the primary service from each `pathId`, e.g., `ecs` from `ecs-001`). Run:

```bash
./scripts/ensure-payload-services.sh <service1> <service2> ...
```

This is idempotent — it skips services that already have a `pkg/payloads/{service}/` directory and import. It also runs `make build` if anything changed, so the binary is ready for the sub-agents.

### Step 4: Invoke the workflow

Call the Workflow tool with `name: "batch-modules"` and `args` set to the structured gap list plus the iteration budget:

```
Workflow({
  name: "batch-modules",
  args: {
    gaps: [
      { pathId: "ecs-001", scenarioId: "ecs-001-to-admin", category: "new-passrole", services: "iam,ecs" },
      { pathId: "sqs-001", scenarioId: "sqs-001-to-admin", category: "new-passrole", services: "iam,sqs" },
      ...
    ],
    iterationBudget: 5   // omit or pass 5 for default; 1 = single-shot, no fix loop
  }
})
```

The workflow runs a single up-front **Preflight** phase (SSO profile freshness), then pipelines each gap through Enable → Build → Verify → Disable. Sub-agents run concurrently, capped by the workflow runtime (min(16, cpu-cores-2)). The `plabs-lifecycle` script's file lock ensures at most one `plabs apply` is in flight at any moment; other items block on lock acquisition and continue as it releases. The Enable stage auto-imports each scenario's starting credentials into pathrunner's identity store, so Verify sub-agents just switch to `<scenario-id>` and start testing.

The **Verify** stage runs up to `iterationBudget` attempts per module. Each attempt: run go tests + `test-module.sh full <id>`, and if either fails, classify the failure. Pathrunner-side bugs (compile errors, wrong SDK calls, wrong ARN parsing, missing env vars in payloads, timing constants, etc.) get a minimal Edit-based fix; lab-side or environmental failures (missing scenario, SSO expired, drift) trigger a **hard-stop** with no code changes. Sub-agents never touch `../pathfinding-labs/**` or `../pathfinding.cloud/**`, never git-commit, never call `plabs enable/disable`. If the budget is exhausted without passing, the sub-agent returns `success: false` with the full fix history — Disable still runs, so labs aren't leaked.

Watch `/workflows` while it's running to see live progress.

### Step 5: Report results

The workflow returns:
```
{
  summary: {
    attempted, enabled, built, tested, disabled, fullySuccessful,
    leakedLabs: [...],
    iterationBudget,
    iterations: { total, passedFirstTry, passedAfterFix, averageIterations },
    hardStopped: [{ pathId, reason }, ...]
  },
  results: [{ gap, enabled, built, tested, disabled, iterationsUsed, fixesApplied, verifyInfo, errors }, ...]
}
```

Summarize for the user:
- **Fully successful** (`tested && disabled`): list `pathId`s. Annotate each with `(passed first try)` or `(passed after N fixes)` from `iterationsUsed`. These are ready to commit.
- **Passed after fixes**: for any module where `fixesApplied` is non-empty, list the fix summaries so the user knows what changed before reviewing the diff. Especially important if the fixes touched shared code (`pkg/discovery/`, `pkg/modules/`).
- **Built but failed verification** (budget exhausted, no hard-stop): list `pathId`s, the final error, and the full `fixesApplied` history. These need human investigation — the sub-agent tried N times and couldn't crack it.
- **Hard-stopped** (`summary.hardStopped`): failures the sub-agent classified as lab/environmental. No code changes attempted. List `pathId (reason)` so the user knows which need lab-side or SSO fixes before re-running.
- **Failed to build**: list `pathId`s and their errors. Likely path YAML issues, unusual patterns, or compilation errors the sub-agent couldn't resolve.
- **Leaked labs**: `summary.leakedLabs` — labs that were enabled but disable failed. Tell the user to run `./scripts/plabs-lifecycle.sh disable <id>` manually for each.
- **Iteration cost signal**: if `iterations.total` is high relative to modules passed, or `averageIterations` is >3, note it — that's a signal the sub-agents are grinding and either the budget can be tightened or the modules genuinely needed a lot of fixup.

Do NOT auto-commit the created modules. The user reviews the diff, then commits or asks for cleanup.

## When to stop and ask

- **Preflight SSO fails**: the workflow's Preflight phase returned `alive: false` with an `expiredProfiles` list. Do NOT retry the workflow — tell the user which profiles need `aws sso login`, wait for them to confirm, then re-invoke.
- **Stale lock** at start (`lock-info` shows a lock older than the lease with a dead PID and reclamation didn't fire): don't force-unlock; ask the user.
- **`plabs status` shows unexpected pre-deployed scenarios** that overlap with the target list: ask whether to keep them or disable-and-redeploy. The workflow's enable stage handles `alreadyDeployed=true` gracefully, but the user should know.
- **The gap list is >20 items and the user said "all"**: confirm the scope — that's a lot of AWS resources deploying serially through the lock.

## Failure modes

- **Workflow aborts at Preflight with `aborted: 'sso-preflight'`**: `preflight.expiredProfiles` lists which SSO profiles need refresh. Nothing was deployed; no cleanup needed. Refresh and re-invoke.
- **Sub-agent Enable stage returns `success: false` with an SSO-expired error**: rare — happens if a token expires mid-batch after Preflight passed. Prompt the user to refresh, then re-invoke for the remaining gaps.
- **Workflow returns with `leakedLabs` non-empty**: the enable succeeded but disable failed for those IDs. Their AWS resources are still deployed and billing. Run `./scripts/plabs-lifecycle.sh disable <id>` manually, or `./scripts/plabs-lifecycle.sh force-unlock` first if the lock is stuck.
- **Workflow itself throws / is killed**: any lab that was mid-enable when the workflow died is likely still deployed. Check `plabs status` and disable manually.
- **A sub-agent silently returns unsuccessful with no error text**: check `/workflows` for the sub-agent transcript. Common causes: sub-agent context ran out, tool call was denied by permission, source YAML file missing.
- **Terraform state lock error inside a sub-agent's apply**: the plabs-lifecycle lock should prevent this, but if it happens (e.g., the labs repo was applied directly outside this workflow), the sub-agent will report it via its structured output.
- **Auto-import of scenario creds fails but apply succeeded**: rare — usually means `jq` isn't installed or the pathrunner binary path is wrong. The lifecycle script logs a warning and continues; downstream sub-agents will fail their `identity switch` step. Run `./scripts/import-lab-creds.sh <scenario-id>` manually to diagnose.

## Related skills / scripts

- `/list-gaps` — produces the gap table this skill consumes
- `/plabs-lifecycle` — the lock-protected enable/disable/swap primitives sub-agents call
- `/create-module` — the module-creation flow each sub-agent follows in its Build stage
- `/test-module` — the live-lab test harness each sub-agent invokes in its Verify stage
- `/cleanup-scenario` — for manual cleanup if the workflow leaks labs
