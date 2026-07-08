---
name: cleanup-scenario
description: Clean up AWS resources after testing a pathrunner module against a pathfinding-labs scenario
disable-model-invocation: true
argument-hint: "<scenario-id> (e.g., lambda-001-to-admin)"
---

# Cleanup Scenario

Clean up AWS resources after testing a pathrunner module. This exercises pathrunner's cleanup functionality first, then uses the pathfinding-labs cleanup script as a safety net.

## Scenario Information

!`(cd ../pathfinding-labs && ./plabs scenarios show $ARGUMENTS) 2>&1`

## Steps

### Step 1: Run Pathrunner Cleanup First

This tests our cleanup code:

```bash
./pathrunner workspace cleanup --all 2>&1
```

If the module deployed attacker infra (EC2 attacker box, exfil S3 bucket), also tear that down with `./pathrunner attacker infra ec2 destroy` and/or `./pathrunner attacker infra bucket destroy` — `workspace cleanup` handles victim-side resources tracked by the module, not attacker-owned deploys, which live in their own per-workspace state.

Record what pathrunner reports as cleaned vs failed.

### Step 2: Verify Resources Were Cleaned

Check AWS state for any remaining pathrunner-created resources:

```bash
# Check for Lambda functions
./pathrunner aws lambda list-functions --query 'Functions[?starts_with(FunctionName, `pathrunner`)]' 2>&1

# Check for EC2 instances
./pathrunner aws ec2 describe-instances --filters "Name=tag:ManagedBy,Values=Pathrunner" "Name=instance-state-name,Values=running,pending" 2>&1

# Check for ECS resources
./pathrunner aws ecs list-clusters --query 'clusterArns[?contains(@, `pathrunner`)]' 2>&1
```

### Step 3: Run Pathfinding-Labs Cleanup as Safety Net

```bash
SCENARIO_DIR=$(grep -rl "pathfinding-cloud-id" ../pathfinding-labs/modules/scenarios/*/scenario.yaml 2>/dev/null | xargs grep -l "$ARGUMENTS\|$(echo $ARGUMENTS | sed 's/-to-.*//')" | head -1 | xargs dirname 2>/dev/null)
if [ -n "$SCENARIO_DIR" ] && [ -f "$SCENARIO_DIR/cleanup_attack.sh" ]; then
    bash "$SCENARIO_DIR/cleanup_attack.sh" 2>&1
else
    echo "No cleanup_attack.sh found for scenario"
fi
```

### Step 4: Remove Test Identity

```bash
./pathrunner identity clear --expired 2>&1
```

### Step 5: Report

Summarize:
- **Pathrunner cleaned**: List resources pathrunner successfully cleaned
- **Pathrunner failed**: List resources pathrunner failed to clean (these are bugs)
- **Safety net cleaned**: List anything the fallback script had to clean that pathrunner missed
- **Cleanup gaps identified**: If the safety net found resources pathrunner didn't handle, note which cleanup handlers need to be added to `pkg/core/repl/session.go`
