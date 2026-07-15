export const meta = {
  name: 'batch-modules',
  description: 'Rolling-pool pipeline that creates pathrunner exploit modules from a list of pathfinding-labs gaps. Runs up to N sub-agents concurrently; each one enables its lab, creates the module, runs tests, and disables the lab. The plabs-lifecycle lock serializes terraform applies across concurrent items, and its enable/swap steps also import each lab\'s starting credentials into pathrunner\'s identity store automatically.',
  phases: [
    { title: 'Preflight', detail: 'verify SSO profiles are alive (single up-front check)' },
    { title: 'Enable', detail: 'deploy lab scenario via plabs-lifecycle + auto-import creds (lock-protected)' },
    { title: 'Build', detail: 'create the exploit module + unit/integration tests' },
    { title: 'Verify', detail: 'run tests against the deployed lab; iteratively fix pathrunner-side failures (budget: args.iterationBudget, default 5)' },
    { title: 'Disable', detail: 'tear down lab scenario via plabs-lifecycle (lock-protected)' },
  ],
}

// Expected args shape:
//   {
//     gaps: [
//       { pathId: "ecs-001", scenarioId: "ecs-001-to-admin", category: "new-passrole", services: "iam,ecs" },
//       ...
//     ],
//     concurrency: 5,          // optional; workflow-level cap is already min(16, cores-2)
//     dryRun: false,           // optional; skip enable/disable/build, just simulate
//     verifyOnly: false,       // optional; skip Build stage — modules already exist, just test them
//     iterationBudget: 5,      // optional; Verify stage's fix-and-retry budget per module. Default 5.
//                              // Set to 1 to disable iteration (single-shot test, fail on first error).
//   }
//
// Returns:
//   { summary: {...}, results: [{ gap, enabled, built, tested, disabled, iterationsUsed, fixesApplied, verifyInfo, errors }, ...] }

const gaps = args?.gaps || []
if (gaps.length === 0) {
  log('No gaps provided in args.gaps — nothing to do.')
  return { summary: { attempted: 0 }, results: [] }
}

const dryRun = Boolean(args?.dryRun)
if (dryRun) log('DRY RUN — no plabs applies, no module creation, no tests')

const verifyOnly = Boolean(args?.verifyOnly)
if (verifyOnly) log('VERIFY ONLY — skipping Build stage, modules must already exist')

log(`Batching ${gaps.length} modules${verifyOnly ? ' (verify only)' : ''}. Rolling pool concurrency is capped by the workflow runtime (min(16, cores-2)).`)

// -----------------------------------------------------------------------------
// Phase 0: SSO preflight — one up-front check, then trust the plabs-lifecycle
// script to re-verify per-invocation. Fails the entire batch if any plabs
// profile is expired, so we don't get halfway through and stall on a re-auth
// prompt inside a sub-agent's non-interactive bash call.
// -----------------------------------------------------------------------------

if (!dryRun) {
  phase('Preflight')
  const preflight = await agent(
    [
      'Run `./scripts/check-sso.sh preflight` from the pathrunner repo root and report whether all plabs profiles are alive.',
      '',
      'If the script exits 0, return { alive: true }.',
      'If it exits non-zero, capture the failing profile names from its stderr/stdout and return { alive: false, expiredProfiles: [...], details: "raw output" }.',
      '',
      'Do NOT attempt to fix expired sessions — the operator has to run `aws sso login --profile <name>` interactively.',
    ].join('\n'),
    {
      label: 'preflight:sso',
      phase: 'Preflight',
      schema: {
        type: 'object',
        additionalProperties: false,
        required: ['alive'],
        properties: {
          alive: { type: 'boolean' },
          expiredProfiles: { type: 'array', items: { type: 'string' } },
          details: { type: 'string' },
        },
      },
    },
  )
  if (!preflight || !preflight.alive) {
    log(`Preflight FAILED — ${preflight?.expiredProfiles?.join(', ') || 'unknown profiles'} expired. Refresh with 'aws sso login --profile <name>' and re-run.`)
    return {
      summary: { attempted: 0, aborted: 'sso-preflight' },
      preflight: preflight || { alive: false },
      results: [],
    }
  }
  log('Preflight passed — all plabs profiles alive')
}

// -----------------------------------------------------------------------------
// Structured-output schemas for each stage. Sub-agents are forced to call
// StructuredOutput matching these — no free-form parsing.
// -----------------------------------------------------------------------------

const ENABLE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['success'],
  properties: {
    success: { type: 'boolean' },
    scenarioId: { type: 'string' },
    error: { type: 'string', description: 'Failure detail if success=false' },
    alreadyDeployed: { type: 'boolean', description: 'True if the lab was already deployed' },
  },
}

const BUILD_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['success'],
  properties: {
    success: { type: 'boolean' },
    modulePath: { type: 'string', description: 'e.g. pkg/exploits/ecs_passrole/module.go' },
    payloadsCreated: { type: 'array', items: { type: 'string' } },
    payloadsReused: { type: 'array', items: { type: 'string' } },
    cleanupHandlersAdded: { type: 'array', items: { type: 'string' } },
    error: { type: 'string' },
  },
}

// Schema for a single verify attempt — the orchestrator loops, not the agent.
const VERIFY_ATTEMPT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['outcome'],
  properties: {
    outcome: {
      type: 'string',
      enum: ['pass', 'fail-fixed', 'fail-hard-stop', 'fail-no-fix'],
      description: 'pass = all tests green; fail-fixed = tests failed, minimal fix applied, orchestrator should retry; fail-hard-stop = lab/env issue, abort immediately; fail-no-fix = pathrunner-side bug but could not localize the fix',
    },
    unitTests: { type: 'string', description: 'pass | fail | skipped' },
    integrationTests: { type: 'string', description: 'pass | fail | skipped' },
    liveTest: { type: 'string', description: 'pass | fail | skipped — via scripts/test-module.sh' },
    fix: {
      type: 'object',
      description: 'Populated when outcome=fail-fixed. Describes the fix applied this attempt.',
      additionalProperties: false,
      required: ['failureClass', 'summary'],
      properties: {
        failureClass: { type: 'string', description: 'Short slug: compile-error | wrong-sdk-call | wrong-arn | missing-env-var | test-assertion | timeout-constant | other' },
        filesEdited: { type: 'array', items: { type: 'string' } },
        summary: { type: 'string', description: 'One-line description of the fix' },
      },
    },
    error: { type: 'string', description: 'Concise failure detail for non-pass outcomes' },
    hardStopReason: { type: 'string', description: 'Populated for fail-hard-stop: what lab/env signal triggered the abort' },
    statusMessage: { type: 'string', description: 'One-line summary of what this attempt found/did, shown in the progress log' },
  },
}

const VERIFY_ITERATION_BUDGET = args?.iterationBudget ?? 5

const DISABLE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['success'],
  properties: {
    success: { type: 'boolean' },
    error: { type: 'string' },
  },
}

// -----------------------------------------------------------------------------
// Stages
// -----------------------------------------------------------------------------

const stageEnable = async (gap, _origItem, idx) => {
  const state = { gap, index: idx, enabled: false, built: false, tested: false, disabled: false, errors: [] }

  if (dryRun) {
    state.enabled = true
    return state
  }

  const result = await agent(
    [
      `You are enabling a pathfinding-labs scenario as part of the batch-modules pipeline.`,
      ``,
      `Scenario ID: ${gap.scenarioId}`,
      `Path ID: ${gap.pathId}`,
      ``,
      `Steps:`,
      `1. Run \`./scripts/plabs-lifecycle.sh status\` and check if ${gap.scenarioId} is already deployed. If yes, run \`./scripts/import-lab-creds.sh ${gap.scenarioId}\` to make sure pathrunner has the identity, set alreadyDeployed=true and success=true, return.`,
      `2. Otherwise run \`./scripts/plabs-lifecycle.sh enable ${gap.scenarioId}\`. This acquires the shared lock, enables the scenario, runs \`plabs apply\`, AND automatically imports the scenario's starting IAM user credentials into pathrunner as identity "${gap.scenarioId}". You do NOT need a separate import step.`,
      `3. If the enable succeeds, return success=true. If it fails (lock timeout, terraform error, scenario ID not found, SSO expired), return success=false with a concise error string.`,
      ``,
      `Note: if the SSO preflight fails inside the lifecycle script (exit code 4), that's fatal for the batch — surface the profile name in the error string so the operator knows what to re-auth.`,
      ``,
      `Return the structured output — no other text.`,
    ].join('\n'),
    { label: `enable:${gap.pathId}`, phase: 'Enable', schema: ENABLE_SCHEMA },
  )

  if (!result || !result.success) {
    state.errors.push(`enable: ${result?.error || 'agent returned null or unsuccessful'}`)
    return state
  }
  state.enabled = true
  state.alreadyDeployed = Boolean(result.alreadyDeployed)
  return state
}

const stageBuild = async (state) => {
  if (!state.enabled) return state
  if (dryRun || verifyOnly) {
    state.built = true
    return state
  }

  const gap = state.gap
  const result = await agent(
    [
      `You are creating a pathrunner exploit module for pathfinding-cloud ID ${gap.pathId}.`,
      ``,
      `Follow the create-module skill flow end-to-end:`,
      `- Read the pathfinding.cloud YAML at ../pathfinding.cloud/data/paths/${gap.pathId.split('-')[0]}/${gap.pathId}.yaml`,
      `- Read the pathfinding-labs scenario.yaml and demo_attack.sh for ${gap.scenarioId}`,
      `- Category: ${gap.category || 'infer from YAML'}`,
      `- Services: ${gap.services || 'infer from YAML'}`,
      ``,
      `Pick the canonical example that matches this module's shape (ec2_passrole for new-passrole compute, lambda_updatecode_addpermission for existing-passrole, glue_passrole_job for new-passrole with attacker code artifacts). Copy its structure and adapt.`,
      ``,
      `Create the module directory, module.go, any needed payloads, and unit + integration tests. Run \`make build\` to regenerate register.go and verify compilation.`,
      ``,
      `Do NOT run tests here — that's a later stage. Do NOT touch the lab (it's already deployed). Do NOT modify main.go for the exploit module itself (register.go is generated).`,
      ``,
      `Return structured output describing what you created. If you couldn't complete the module (e.g., source YAML missing, unresolvable compilation error), return success=false with a concise error.`,
    ].join('\n'),
    { label: `build:${gap.pathId}`, phase: 'Build', schema: BUILD_SCHEMA },
  )

  if (!result || !result.success) {
    state.errors.push(`build: ${result?.error || 'agent returned null or unsuccessful'}`)
    return state
  }
  state.built = true
  state.buildInfo = result
  return state
}

// stageVerify runs the iteration loop in the orchestrator so each attempt is its
// own agent() call. This gives the /workflows view per-attempt turn counts and
// a rolling status label instead of one opaque black-box agent.
const stageVerify = async (state) => {
  if (!state.built) return state
  if (dryRun) {
    state.tested = true
    return state
  }

  const gap = state.gap
  const fixesApplied = []

  for (let attempt = 1; attempt <= VERIFY_ITERATION_BUDGET; attempt++) {
    const attemptLabel = `verify:${gap.pathId} [${attempt}/${VERIFY_ITERATION_BUDGET}]`

    // Build a concise "prior fixes" section so the agent knows what was already tried.
    const priorFixesSection = fixesApplied.length === 0
      ? ''
      : [
          '',
          `## Prior fixes applied (do not repeat these — try a different approach if they didn't work)`,
          ...fixesApplied.map((f) => `- Attempt ${f.attempt} (${f.failureClass}): ${f.summary}${f.filesEdited?.length ? ` [${f.filesEdited.join(', ')}]` : ''}`),
        ].join('\n')

    const result = await agent(
      [
        `You are running ONE verify attempt (#${attempt} of max ${VERIFY_ITERATION_BUDGET}) for pathrunner module ${gap.pathId} against deployed lab ${gap.scenarioId}.`,
        ``,
        `The scenario's starting credentials are already in pathrunner's identity store as "${gap.scenarioId}".`,
        priorFixesSection,
        ``,
        `## Steps for this single attempt`,
        ``,
        `1. Run \`go test -run ${gap.pathId.replace('-', '_')} ./tests/unit/ ./tests/integration/\`. Capture pass/fail and output.`,
        `2. Run the live test and save its full output to disk with: \`./scripts/test-module.sh full ${gap.pathId} 2>&1 | tee /tmp/pathrunner-verify-${gap.pathId}-attempt-${attempt}.log; echo "test-module-exit:\${PIPESTATUS[0]}"\`. The tee makes output visible to you AND persists it so the operator can review it after the run. Read the embedded \`test-module-exit:N\` line at the end to determine pass (0) or fail (non-zero).`,
        `3. If both pass → return outcome="pass". You are done.`,
        `4. If either fails → classify:`,
        `   - PATHRUNNER-SIDE: Go compile error, panic, wrong ARN parse, wrong option name, missing import, wrong AWS SDK call, bad payload code-gen, missing os.environ.get, wrong PATHFINDER_IDENTITY_DATA output, test-assertion mismatch from module logic, timeout constant.`,
        `   - HARD STOP: plabs credentials empty (scenario not deployed), terraform drift, missing pl-* resource, SSO expired mid-run, plabs status shows disabled.`,
        `5. HARD STOP → return outcome="fail-hard-stop" with hardStopReason. Do not edit anything.`,
        `6. PATHRUNNER-SIDE → read implicated file(s), apply the minimal fix via Edit. ONLY edit under \`pkg/exploits/**\`, \`pkg/payloads/**\`, and rarely \`pkg/discovery/**\` or \`pkg/modules/**\`. NEVER touch \`../pathfinding-labs/**\` or \`../pathfinding.cloud/**\`. Run \`make build\`. If build fails, that counts as the fix failing — set outcome="fail-no-fix" and describe what you tried. If build succeeds, return outcome="fail-fixed" with the fix populated (the orchestrator will retry).`,
        `7. Can't localize the fix with confidence → return outcome="fail-no-fix" immediately. Better to bail than guess.`,
        ``,
        `## Guardrails`,
        `- Never call plabs enable/disable/apply/swap. The lab is already deployed; disable happens after this stage.`,
        `- Never git commit.`,
        `- statusMessage: always populate with a one-liner like "all tests passed", "compile error in module.go line 42 — fixed missing import", "hard-stop: plabs credentials empty".`,
        ``,
        `Return structured output.`,
      ].join('\n'),
      { label: attemptLabel, phase: 'Verify', schema: VERIFY_ATTEMPT_SCHEMA },
    )

    const status = result?.statusMessage || result?.outcome || 'no response'
    log(`${gap.pathId} attempt ${attempt}/${VERIFY_ITERATION_BUDGET}: ${status}`)

    if (!result) {
      state.errors.push(`verify attempt ${attempt}: agent returned null`)
      break
    }

    if (result.outcome === 'pass') {
      state.tested = true
      state.iterationsUsed = attempt
      state.fixesApplied = fixesApplied
      state.verifyInfo = {
        success: true,
        unitTests: result.unitTests,
        integrationTests: result.integrationTests,
        liveTest: result.liveTest,
        iterationsUsed: attempt,
        fixesApplied,
      }
      return state
    }

    if (result.outcome === 'fail-hard-stop') {
      state.errors.push(`verify: hard-stop — ${result.hardStopReason || result.error || 'unspecified lab/env failure'}`)
      state.verifyInfo = { success: false, hardStopReason: result.hardStopReason, iterationsUsed: attempt, fixesApplied }
      state.iterationsUsed = attempt
      state.fixesApplied = fixesApplied
      return state
    }

    if (result.outcome === 'fail-no-fix') {
      state.errors.push(`verify: could not localize fix after attempt ${attempt} — ${result.error || 'unspecified'}`)
      state.verifyInfo = { success: false, error: result.error, iterationsUsed: attempt, fixesApplied }
      state.iterationsUsed = attempt
      state.fixesApplied = fixesApplied
      return state
    }

    // outcome === 'fail-fixed': record the fix and continue the loop
    if (result.fix) {
      fixesApplied.push({ attempt, ...result.fix })
    }
  }

  // Budget exhausted without passing
  if (!state.tested) {
    state.errors.push(`verify: budget exhausted after ${VERIFY_ITERATION_BUDGET} attempts`)
    state.verifyInfo = { success: false, error: 'budget exhausted', iterationsUsed: VERIFY_ITERATION_BUDGET, fixesApplied }
    state.iterationsUsed = VERIFY_ITERATION_BUDGET
    state.fixesApplied = fixesApplied
  }

  return state
}

const stageDisable = async (state) => {
  // ALWAYS run — we must tear down whatever was enabled, even on upstream failure.
  if (!state.enabled) return state
  if (dryRun) {
    state.disabled = true
    return state
  }

  const gap = state.gap
  const result = await agent(
    [
      `Disable the pathfinding-labs scenario ${gap.scenarioId} to release the lab pool slot.`,
      ``,
      `Run \`./scripts/plabs-lifecycle.sh disable ${gap.scenarioId}\`. This acquires the shared lock, disables the scenario, and runs \`plabs apply\` to destroy its resources.`,
      ``,
      `Return success=true if the command exited 0. Return success=false with the error string otherwise.`,
    ].join('\n'),
    { label: `disable:${gap.pathId}`, phase: 'Disable', schema: DISABLE_SCHEMA },
  )

  if (!result || !result.success) {
    state.errors.push(`disable: ${result?.error || 'agent returned null or unsuccessful'} — LAB MAY BE LEAKED`)
    return state
  }
  state.disabled = true
  return state
}

// -----------------------------------------------------------------------------
// Pipeline
// -----------------------------------------------------------------------------
//
// Pipeline gives us dynamic dispatch: as soon as one item finishes all four
// stages, the next queued item can start. The workflow runtime's concurrency
// cap enforces the pool size (min(16, cores-2) by default). The plabs lock
// serializes the actual terraform applies inside the enable/disable stages,
// so multiple items in-flight in the pipeline is safe — the applies queue up.

const results = await pipeline(
  gaps,
  stageEnable,
  stageBuild,
  stageVerify,
  stageDisable,
)

// pipeline returns null for items that threw. Coerce to a structured record
// so the summary is clean.
const cleanResults = results.map((r, i) =>
  r ?? { gap: gaps[i], index: i, enabled: false, built: false, tested: false, disabled: false, errors: ['pipeline: item dropped (agent threw or was skipped)'] },
)

// -----------------------------------------------------------------------------
// Summary
// -----------------------------------------------------------------------------

// Iteration statistics — how much fix-loop work was done to get results.
const verifiedResults = cleanResults.filter((r) => r.tested)
const iterationsTotal = cleanResults.reduce((sum, r) => sum + (r.iterationsUsed || 0), 0)
const passedFirstTry = verifiedResults.filter((r) => (r.iterationsUsed || 1) === 1).length
const passedAfterFix = verifiedResults.filter((r) => (r.iterationsUsed || 1) > 1).length
const hardStopped = cleanResults.filter((r) => r.verifyInfo?.hardStopReason).map((r) => ({
  pathId: r.gap.pathId,
  reason: r.verifyInfo.hardStopReason,
}))

const summary = {
  attempted: cleanResults.length,
  enabled: cleanResults.filter((r) => r.enabled).length,
  built: cleanResults.filter((r) => r.built).length,
  tested: cleanResults.filter((r) => r.tested).length,
  disabled: cleanResults.filter((r) => r.disabled).length,
  fullySuccessful: cleanResults.filter((r) => r.tested && r.disabled).length,
  leakedLabs: cleanResults.filter((r) => r.enabled && !r.disabled).map((r) => r.gap.scenarioId),
  iterationBudget: VERIFY_ITERATION_BUDGET,
  iterations: {
    total: iterationsTotal,
    passedFirstTry,
    passedAfterFix,
    averageIterations: verifiedResults.length > 0 ? Number((iterationsTotal / verifiedResults.length).toFixed(2)) : 0,
  },
  hardStopped,
}

log(`Done. Fully successful: ${summary.fullySuccessful}/${summary.attempted}`)
log(`Test logs written to /tmp/pathrunner-verify-<module>-attempt-<N>.log for each attempt`)
if (passedAfterFix > 0) {
  log(`${passedAfterFix} passed after iterative fixes; ${passedFirstTry} first-try passes`)
}
if (hardStopped.length > 0) {
  log(`Hard-stopped (lab/env issues, no code fix attempted): ${hardStopped.map((h) => `${h.pathId} (${h.reason})`).join(', ')}`)
}
if (summary.leakedLabs.length > 0) {
  log(`⚠ Leaked labs still deployed (disable failed): ${summary.leakedLabs.join(', ')}. Run \`./scripts/plabs-lifecycle.sh disable <id>\` manually.`)
}

return { summary, results: cleanResults }
