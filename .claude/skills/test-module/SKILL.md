---
name: test-module
description: Test a pathrunner exploit module against a deployed pathfinding-labs scenario
disable-model-invocation: true
argument-hint: "<module-id> [scenario-suffix] [payloads] (e.g., lambda-001, iam-001 to-bucket)"
---

# Test Pathrunner Module

You are testing a pathrunner exploit module against a deployed pathfinding-labs scenario using the `test-module.sh` script.

## Argument Parsing

The user's `$ARGUMENTS` should be parsed as: `<module-id> [scenario-suffix] [payload1,payload2,...]`

- **module-id** (required): The pathrunner module ID (e.g., `lambda-001`, `iam-001`)
- **scenario-suffix** (optional): Appended to module-id to form the plabs scenario ID (default: `to-admin`). Must NOT contain `/`.
- **payloads** (optional): Comma-separated payload filter. Contains `/` (e.g., `exfil/output`, `backdoor/attach-policy`).

Examples:
- `lambda-001` → module=lambda-001, scenario=lambda-001-to-admin
- `iam-001 to-bucket` → module=iam-001, scenario=iam-001-to-bucket
- `lambda-001 exfil/output` → module=lambda-001, scenario=lambda-001-to-admin, payload=exfil/output
- `lambda-001 to-bucket backdoor/attach-policy` → module=lambda-001, scenario=lambda-001-to-bucket, payload=backdoor/attach-policy

## Steps

### Step 1: Verify scenario is deployed

Check that the plabs scenario exists and is deployed:

```bash
cd /Users/seth.art/Documents/projects/pathfinding-labs && ./plabs scenarios show <scenario-id> 2>&1
```

If NOT deployed, inform the user and stop. They need to deploy first.

### Step 2: Run the test script

The `test-module.sh` script handles building, credential import, module configuration, exploit execution, verification, and cleanup.

**For a full test run (default):**
```bash
/Users/seth.art/Documents/projects/pathrunner/scripts/test-module.sh full $ARGUMENTS
```

**For interactive mode** (pauses before cleanup so you can inspect state):
```bash
/Users/seth.art/Documents/projects/pathrunner/scripts/test-module.sh full -i $ARGUMENTS
```

**For setup only** (stops before exploit — useful for manual testing):
```bash
/Users/seth.art/Documents/projects/pathrunner/scripts/test-module.sh setup $ARGUMENTS
```

**For cleanup only** (run after a previous setup/manual test):
```bash
/Users/seth.art/Documents/projects/pathrunner/scripts/test-module.sh cleanup $ARGUMENTS
```

### Step 3: Review results

The script outputs a summary table showing per-payload results:
- **Execution**: Did the exploit succeed?
- **Creds Obtained**: Were credentials extracted?
- **Cleanup**: Did cleanup complete without issues?

Report the results to the user. If any payload failed or cleanup had issues, investigate and suggest fixes.

**IMPORTANT**: Do NOT run pathfinding-labs cleanup scripts (`cleanup_attack.sh`). Those belong to a separate project. Pathrunner's own cleanup is what's being tested.
