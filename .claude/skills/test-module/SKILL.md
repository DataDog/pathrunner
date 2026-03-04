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

### Step 7: Verify Cleanup Completeness

After pathrunner cleanup, verify that all resources are actually cleaned up by checking AWS state directly:

1. **Check for leftover policy attachments** (for backdoor payloads):
   ```bash
   ./pathrunner aws iam list-attached-user-policies --user-name <starting-user> --output json 2>&1
   ```

2. **Check function code was restored** (for lambda-003 and similar):
   ```bash
   ./pathrunner aws lambda invoke --function-name <target-function> --payload '{}' /tmp/verify.json --output json 2>&1
   ```

3. **Check for leftover pathrunner functions** (for lambda-001/002):
   ```bash
   ./pathrunner aws lambda list-functions --query 'Functions[?starts_with(FunctionName, `pathrunner`)]' 2>&1
   ```

If anything was missed, flag it as a bug in pathrunner's cleanup handlers.

**IMPORTANT**: Do NOT run pathfinding-labs cleanup scripts (`cleanup_attack.sh`). Those belong to a separate project and should only be used as reference for understanding what needs to be cleaned up, never executed from this skill.
