---
name: test-module
description: Test a pathrunner exploit module against a deployed pathfinding-labs scenario
disable-model-invocation: true
argument-hint: "<scenario-id> (e.g., lambda-001-to-admin, ecs-001-to-admin)"
---

# Test Pathrunner Module

You are testing a pathrunner exploit module against a deployed pathfinding-labs scenario. The scenario must already be deployed via `plabs`.

## Scenario Information

!`cd /Users/seth.art/Documents/projects/pathfinding-labs && ./plabs scenarios show $ARGUMENTS 2>&1`

## Steps

### Step 1: Parse Scenario Data

From the scenario show output above, extract:
- **pathfinding-cloud-id**: The path ID (e.g., `lambda-001`)
- **Starting credentials**: How to get initial credentials (profile name, role ARN, etc.)
- **Target ARNs**: Role ARNs, instance profile ARNs, etc. needed as module options
- **Deployment status**: Is the scenario currently deployed?

If the scenario is NOT deployed, inform the user and stop. They need to run `plabs scenarios deploy $ARGUMENTS` first.

### Step 2: Build Pathrunner

```bash
cd /Users/seth.art/Documents/projects/pathrunner && go build -o pathrunner cmd/pathrunner/main.go
```

### Step 3: Determine Test Matrix

Based on the module type:
- **Payload-based modules**: Test each available payload, starting with `exfil/output` (easiest to verify)
- **Non-payload modules**: Single test run

### Step 4: Run Each Test

For each payload (or single run for non-payload modules):

1. **Add starting identity:**
   ```bash
   ./pathrunner identity add --profile <profile> 2>&1
   ```
   Or use the credentials from the scenario output.

2. **Load module and set options:**
   ```bash
   ./pathrunner use <pathfinding-cloud-id>
   ./pathrunner set ROLE_ARN <target-role-arn>
   ./pathrunner set PAYLOAD <payload-name>
   ./pathrunner set REGION <region>
   # ... any other required options
   ```

3. **Run the exploit:**
   ```bash
   ./pathrunner exploit 2>&1
   ```

4. **Check output for success indicators:**
   - Credentials in output (AccessKeyId, SecretAccessKey)
   - `PATHFINDER_IDENTITY_DATA` markers
   - Expected role/user ARN in result
   - No error messages

5. **Pause and ask user to inspect the results before continuing to next payload.**

### Step 5: Test Cleanup

After all payloads are tested:

1. **Run pathrunner cleanup:**
   ```bash
   ./pathrunner workspace cleanup --all 2>&1
   ```

2. **Verify resources were cleaned up** by checking AWS state:
   ```bash
   ./pathrunner aws lambda list-functions --query 'Functions[?starts_with(FunctionName, `pathrunner`)]' 2>&1
   ./pathrunner aws ec2 describe-instances --filters "Name=tag:ManagedBy,Values=Pathrunner" "Name=instance-state-name,Values=running" 2>&1
   ```
   (Adjust commands based on what resource types the module creates)

### Step 6: Report Summary

Create a summary table:

| Payload | Execution | Credentials Obtained | Cleanup |
|---------|-----------|---------------------|---------|
| exfil/output | PASS/FAIL | YES/NO | PASS/FAIL |
| exfil/https | PASS/FAIL | YES/NO | PASS/FAIL |
| ... | ... | ... | ... |

If pathrunner cleanup missed anything, flag it as a bug that needs fixing in the cleanup handlers.

### Step 7: Final Cleanup Safety Net

As a safety net, also run the pathfinding-labs cleanup script:
```bash
cd /Users/seth.art/Documents/projects/pathfinding-labs
SCENARIO_DIR=$(grep -rl "pathfinding-cloud-id.*<path-id>" modules/scenarios/*/scenario.yaml | head -1 | xargs dirname)
bash "$SCENARIO_DIR/cleanup_attack.sh" 2>&1
```

Report what pathrunner cleaned vs what the fallback script had to clean. Any resources that only the fallback cleaned indicate gaps in pathrunner's cleanup handlers.
