---
name: test-module
description: Test a pathrunner exploit module against a deployed pathfinding-labs scenario. Supports iterative fix-and-retry — the skill can loop up to N times, diagnosing pathrunner-side failures and applying fixes between runs.
disable-model-invocation: true
argument-hint: "<module-id> [scenario-suffix] [payloads] [--iterate N] (e.g., lambda-001 --iterate 5)"
---

# Test Pathrunner Module

You are testing a pathrunner exploit module against a deployed pathfinding-labs scenario using the `test-module.sh` script. If the module fails on the first run, you can (optionally) iterate: diagnose the pathrunner-side failure, apply a minimal fix, re-run.

## Argument Parsing

The user's `$ARGUMENTS` should be parsed as: `<module-id> [scenario-suffix] [payload1,payload2,...] [--iterate N]`

- **module-id** (required): The pathrunner module ID (e.g., `lambda-001`, `iam-001`)
- **scenario-suffix** (optional): Appended to module-id to form the plabs scenario ID (default: `to-admin`). Must NOT contain `/`.
- **payloads** (optional): Comma-separated payload filter. Contains `/` (e.g., `exfil/response`, `backdoor/attach-policy`).
- **`--iterate N`** (optional): Enable iterative fix-and-retry mode with a budget of N attempts. Default: `1` (single-shot, current behavior). Recommended: `5` for interactive dev work. Max meaningful value: `10`.

Examples:
- `lambda-001` → module=lambda-001, scenario=lambda-001-to-admin, iterate=1
- `iam-001 to-bucket` → module=iam-001, scenario=iam-001-to-bucket, iterate=1
- `lambda-001 exfil/response` → module=lambda-001, scenario=lambda-001-to-admin, payload=exfil/response, iterate=1
- `lambda-005 --iterate 5` → module=lambda-005, iterate=5
- `glue-003 --iterate 3 exfil/s3` → module=glue-003, payload=exfil/s3, iterate=3

## Prerequisites for Attacker-Infra-Dependent Payloads

If the requested payload depends on attacker infra, the operator must have it running BEFORE the test:

| Payload | Prerequisite |
|---|---|
| `revshell/tls` | `./pathrunner attacker listener start` (auto-injects `LISTENER_IP`, `LISTENER_PORT`) |
| `exfil/https` | `./pathrunner attacker listener start` (auto-injects `HTTPS_URL`) |
| `exfil/s3` | `./pathrunner attacker infra bucket create` (auto-populates `EXFIL_BUCKET`) |

For remote/AWS-reachable testing (payload running in Lambda/EC2/Glue must dial back), the listener needs a public IP the AWS-side payload can reach — either run the listener on the deployed attacker EC2 box (`./pathrunner attacker infra ec2 create` then start the listener there) or expose the local listener via a reachable public IP. Payloads that only take action against AWS APIs (e.g., `backdoor/attach-policy`) don't need the listener.

## Steps

### Step 0: SSO Preflight (once per session, cheap)

`plabs credentials` (which `test-module.sh` calls internally) reads terraform state, but `./pathrunner attacker validate` and any auto-populated attacker-infra deploys hit AWS directly. Confirm the profiles you'll rely on are alive:

```bash
./scripts/check-sso.sh plabs
./scripts/check-sso.sh check <pathrunner-attacker-profile>   # if attacker infra is in play
```

If any profile shows FAIL/EXPIRED, tell the user and stop — they need `aws sso login --profile <name>` interactively.

### Step 1: Verify scenario is deployed

Check that the plabs scenario exists and is deployed:

```bash
(cd ../pathfinding-labs && ./plabs scenarios show <scenario-id>) 2>&1
```

If NOT deployed, inform the user and stop. They need to deploy first.

### Step 2: Run the test script

The `test-module.sh` script handles building, credential import, module configuration, exploit execution, verification, and cleanup.

**For a full test run (default):**
```bash
./scripts/test-module.sh full $ARGUMENTS
```

**For interactive mode** (pauses before cleanup so you can inspect state):
```bash
./scripts/test-module.sh full -i $ARGUMENTS
```

**For setup only** (stops before exploit — useful for manual testing):
```bash
./scripts/test-module.sh setup $ARGUMENTS
```

**For cleanup only** (run after a previous setup/manual test):
```bash
./scripts/test-module.sh cleanup $ARGUMENTS
```

### Step 3: Review results

The script outputs a summary table showing per-payload results:
- **Execution**: Did the exploit succeed?
- **Creds Obtained**: Were credentials extracted?
- **Cleanup**: Did cleanup complete without issues?

If everything passed, report success and stop. If any payload failed:

- **`--iterate 1` (default)**: report the failure to the user with a suggested fix; do NOT modify code.
- **`--iterate N` with N > 1**: enter the fix-and-retry loop in Step 4.

**IMPORTANT**: Do NOT run pathfinding-labs cleanup scripts (`cleanup_attack.sh`). Those belong to a separate project. Pathrunner's own cleanup is what's being tested.

### Step 4: Fix-and-Retry Loop (only if `--iterate N > 1`)

Enter an iteration loop with a hard budget of N total attempts (the initial run in Step 2 counts as attempt 1). For each subsequent attempt:

**4a. Classify the failure.** Read `test-module.sh`'s output carefully and determine the failure mode:

| Failure mode | Iterate? | Reason |
|---|---|---|
| Go compile error, panic, wrong ARN parsed, wrong option name, missing import, wrong AWS SDK call shape, incorrect payload code-gen, missing `os.environ.get` in payload | **YES** | Fixable in pathrunner-side code |
| Test assertion mismatch caused by module logic | **YES** | Fixable in pathrunner-side code |
| Wrong credential markers / missing PATHFINDER_IDENTITY_DATA emission | **YES** | Fixable in module |
| `plabs credentials` returned empty (scenario not really deployed) | **NO — hard stop** | Lab issue; abort iteration |
| Terraform state drift, wrong resource in lab, missing pl-* resource | **NO — hard stop** | Lab issue; abort iteration |
| SSO expired mid-run | **NO — hard stop** | Operator must re-auth |
| `plabs status` shows scenario disabled | **NO — hard stop** | Bad scenario ID or teardown mid-test |
| Payload takes >90s and times out for a legitimate reason (IAM propagation, ESM warm-up) | **MAYBE** | Only iterate if the fix is bumping a timeout constant in the pathrunner module — never edit lab code |

If the failure is anything in the "NO" column, stop immediately. Report the classification and the reason to the user; do NOT edit any code. Iterating on lab-side issues is out of scope for this skill.

**4b. Apply the minimal fix in pathrunner code.** Read the specific file(s) implicated by the error, propose the smallest fix that plausibly addresses the failure, and apply it via Edit. Guardrails:

- **Only edit files under `pkg/exploits/**`, `pkg/payloads/**`, and (rarely) `pkg/discovery/**` or `pkg/modules/**`.** Never touch anything under `../pathfinding-labs/` or `../pathfinding.cloud/`. If a fix seems to require lab changes, that's a hard stop from Step 4a.
- **No new dependencies** unless the compile error is a genuine missing import that already exists as an indirect dep.
- **Prefer localized fixes** to sweeping refactors — the goal is to unblock this test, not to restructure the module.
- **If the fix requires changing the deployed lab's expected behavior**, that's out of scope; stop.

**4c. Rebuild.** Run `make build` (regenerates `pkg/exploits/register.go` and compiles). If build fails, that's a Go-level bug from the fix — either fix again within the budget or bail.

**4d. Re-run the test.** `./scripts/test-module.sh full <args>`. Note that `test-module.sh` handles its own credential import and cleanup between runs, so it's safe to invoke repeatedly.

**4e. Loop.** If the test passes, report success with a summary of every fix applied (file + one-line diff description per attempt). If it still fails and iteration budget remains, go back to 4a. If budget is exhausted, report failure with the final classification, every fix attempted, and a "next steps for human review" note.

### Iteration guardrails summary

Regardless of budget:

- **Read-only for lab side**: no edits under `../pathfinding-labs/**` or `../pathfinding.cloud/**` (also true for the YAML source of truth). Use them as reference only.
- **No `plabs` calls that mutate state** during iteration — no re-enable, no re-disable, no re-apply. The lab stays exactly as it was when you started.
- **No git commits** during iteration. The user reviews the final diff.
- **Bail on ambiguity**: if you can't confidently classify the failure or identify the fix location, stop and report to the user rather than guessing.
- **Track your attempts**: keep a list of `{attempt, failure_class, files_edited, fix_summary}` for the final report.
