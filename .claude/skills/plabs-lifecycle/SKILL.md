---
name: plabs-lifecycle
description: Enable, disable, and swap pathfinding-labs scenarios via plabs, serializing terraform applies through a shared lock so concurrent agents don't collide
argument-hint: "<enable|disable|swap|status|lock-info> [args]"
---

# plabs Lifecycle

Wrap `plabs enable` / `plabs disable` / `plabs apply` behind a shared file lock so multiple concurrent agents (batch module creation, workflows) can safely serialize their terraform applies. The lock prevents lost work — terraform's own state lock would just fail loudly on contention.

The implementation lives in `scripts/plabs-lifecycle.sh`. This skill teaches when and how to invoke it.

## Why this exists

`pathfinding-labs` uses a **single shared Terraform state** at `../pathfinding-labs/terraform.tfstate`. Only one `plabs apply` can run at a time. `plabs enable X` and `plabs disable X` just toggle scenario inclusion in the next apply — they're cheap on their own; the expensive step is the apply itself.

The natural batching unit is therefore **the current set of enabled scenarios**, not "5 modules." Adding one scenario to an already-deployed set is a small terraform delta. That's what makes the rolling-pool coordination model efficient.

## Commands

Run from the pathrunner repo root:

```bash
./scripts/plabs-lifecycle.sh enable  <scenario-id>...           # enable + apply + import creds, holds lock
./scripts/plabs-lifecycle.sh disable <scenario-id>...           # disable + apply + clear identity, holds lock
./scripts/plabs-lifecycle.sh swap [--add <id>]... [--remove <id>]...  # combined, one apply, +import/-clear
./scripts/plabs-lifecycle.sh status                             # read-only, no lock
./scripts/plabs-lifecycle.sh lock-info                          # who holds the lock, how long
./scripts/plabs-lifecycle.sh force-unlock                       # emergency only
```

Companion scripts (invoked automatically by the lifecycle script, but usable standalone):
- `./scripts/check-sso.sh` — verify SSO profile freshness (plabs profiles + optional pathrunner attacker profile)
- `./scripts/import-lab-creds.sh <scenario-id>` — pull scenario starting creds via `plabs credentials` and add to pathrunner identity store

Scenario IDs are the plabs form (e.g., `lambda-005-to-admin`, `iam-013-to-admin`) — the pathfinding-cloud path ID plus the `-to-{target}` suffix. Confirm the exact ID via `./scripts/plabs-lifecycle.sh status` or `(cd ../pathfinding-labs && ./plabs scenarios list)`.

Prefer `swap` when both adding and removing in the same coordinator turn — it does one terraform apply instead of two.

## Automatic side effects

Every `enable`, `disable`, and `swap` invocation does more than toggle terraform state:

1. **Preflight SSO check** — before acquiring the lock, `check-sso.sh plabs` probes every AWS profile plabs is configured to use. If any is expired, the script exits code 4 with the failing profile name and instructions (`aws sso login --profile <name>`). This avoids the failure mode where `plabs apply` runs for two minutes, then dies mid-terraform because a token silently expired. Bypass with `SKIP_SSO_CHECK=1` if you need to (e.g., testing offline).
2. **Auto-import scenario credentials** — after a successful `enable` or `swap --add`, `import-lab-creds.sh` fetches each newly-enabled scenario's starting IAM user credentials via `plabs credentials <id> --format=json` and registers them in pathrunner's identity store under the name `<scenario-id>`. Idempotent: if the identity already exists (e.g., previous run), it's replaced with the current keys. Bypass with `SKIP_CREDS_IMPORT=1`.
3. **Identity cleanup on disable** — after a successful `disable` or `swap --remove`, each removed scenario's pathrunner identity (`identity clear <scenario-id>`) is removed. Prevents stale identities pointing at IAM users terraform just destroyed.

The SSO check is fast (~1s per profile), so it's fine to run on every invocation. The auto-import is only invoked on paths that succeed — if `plabs apply` fails, no creds get imported.

Downstream sub-agents doing module build/test work don't need to run `plabs credentials` themselves; they can just `./pathrunner identity switch <scenario-id>` after enable finishes.

## The lock

- Location: `/tmp/pathrunner-plabs.lock.d` (override with `PLABS_LOCK_DIR`).
- Implementation: atomic `mkdir` — portable across macOS/Linux, no `flock` dependency.
- Owner file: records PID, acquisition timestamp, hostname, purpose.
- Wait timeout: default 3600s (`PLABS_LOCK_TIMEOUT`). Exit code 2 on timeout.
- Stale reclamation: if the lock is older than `PLABS_LOCK_LEASE_MAX` (default 1800s) AND the recorded PID is no longer alive on this host, the next acquire reclaims it automatically. This handles agents that were SIGKILLed mid-apply.
- Read-only commands (`status`, `lock-info`) do NOT acquire the lock.

If `lock-info` shows a stale lock and reclamation didn't fire (rare — e.g., PID reused, or a run <30 min but the shell is gone), use `force-unlock` after verifying no `plabs apply` is actually running elsewhere: `pgrep -af 'plabs apply'`.

## When to invoke each command

- **enable** — one-off, when you're starting work on a single module. Use `swap` instead if you're also removing something.
- **disable** — one-off, when you're done with a scenario and no new one is starting in its place.
- **swap** — the coordinator's workhorse. When one module finishes and another starts, `swap --remove <finished> --add <next>` in a single call does both toggles + one apply.
- **status** — before starting work, to see what's already deployed and skip redundant enables.
- **lock-info** — when a command is waiting longer than expected, to see who's holding things up.

## Integration with module creation

The recommended coordination model (chosen ADR-style with the user) is a **rolling pool of 5 deployed scenarios**:

1. Coordinator picks the first 5 gaps from `/list-gaps` output and calls `plabs-lifecycle.sh enable id1 id2 id3 id4 id5` once. One apply deploys all five.
2. Five sub-agents work in parallel — each on one module. They can `plabs scenarios credentials <id>` to get the starting user, and run tests against the deployed lab. **The build/test phase itself does NOT touch this skill or the lock** — the lab is already deployed and their work is read-only against AWS.
3. When any sub-agent finishes (module + tests passing), the coordinator picks the next unstarted gap and calls `plabs-lifecycle.sh swap --remove <finished-id> --add <next-id>` — one apply retires the old, deploys the new.
4. Repeat until the gap list is drained; final `plabs-lifecycle.sh disable <last-N>` tears down the remaining pool.

The lock keeps steps 1, 3, and 4 safe under concurrency without requiring the sub-agents to coordinate directly. A future `batch-modules` skill or workflow will implement this loop; this skill provides the primitives.

## Failure modes and recovery

- **`plabs apply` fails mid-run**: terraform state on disk is authoritative. Re-run the same `enable`/`disable`/`swap` command — it's idempotent because terraform will replay the intended state.
- **Lock timeout (exit 2)**: check `lock-info`. If a real apply is in progress, wait; if it looks stuck, investigate before force-unlocking.
- **Scenario ID not found**: verify the exact ID with `(cd ../pathfinding-labs && ./plabs scenarios list) | grep <partial>`.
- **`plabs status` shows a scenario as "enabled but not deployed"**: a previous apply failed. Just re-run `enable` for that ID (or `swap --add` for it) to trigger a fresh apply.
- **Attacker infra collision**: if a pathrunner workflow also deploys `attacker infra ec2 create` at the same time as a lab apply, they're independent terraform states (attacker infra is in pathrunner's tracker, lab infra is in pathfinding-labs). No lock coordination between them is needed.

## What NOT to do

- Don't run `plabs apply` directly in the labs repo while any agent might be using this script — bypasses the lock.
- Don't set `PLABS_LOCK_TIMEOUT=0` to fail-fast unless you're intentionally probing lock state — a real apply takes minutes.
- Don't `force-unlock` without checking `pgrep -af 'plabs apply'` and `lock-info` first — you can corrupt a running apply.
- Don't hold the lock across the module build/test phase — enable, release (implicit on script exit), work, then re-acquire to disable. The script already does this correctly per invocation.
