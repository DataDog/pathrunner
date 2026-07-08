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

log(`Batching ${gaps.length} modules. Rolling pool concurrency is capped by the workflow runtime (min(16, cores-2)).`)

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

const VERIFY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['success'],
  properties: {
    success: { type: 'boolean' },
    unitTests: { type: 'string', description: 'pass | fail | skipped' },
    integrationTests: { type: 'string', description: 'pass | fail | skipped' },
    liveTest: { type: 'string', description: 'pass | fail | skipped — via scripts/test-module.sh' },
    iterationsUsed: { type: 'integer', description: 'How many fix-and-retry attempts were consumed (1 = passed first try)' },
    fixesApplied: {
      type: 'array',
      description: 'Ordered list of fixes applied across iterations',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['attempt', 'failureClass', 'summary'],
        properties: {
          attempt: { type: 'integer' },
          failureClass: { type: 'string' },
          filesEdited: { type: 'array', items: { type: 'string' } },
          summary: { type: 'string' },
        },
      },
    },
    error: { type: 'string' },
    hardStopReason: { type: 'string', description: 'Non-empty if a lab-side or environmental failure caused early abort (SSO expired, scenario not deployed, etc.)' },
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
  if (dryRun) {
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

const stageVerify = async (state) => {
  if (!state.built) return state
  if (dryRun) {
    state.tested = true
    return state
  }

  const gap = state.gap
  const result = await agent(
    [
      `You are testing the pathrunner module ${gap.pathId} against the live pathfinding-labs scenario ${gap.scenarioId}, which is already deployed. You have an iteration budget of ${VERIFY_ITERATION_BUDGET} attempts to get everything passing.`,
      ``,
      `The scenario's starting IAM user credentials have already been imported into pathrunner's identity store as name "${gap.scenarioId}" — you can \`./pathrunner identity switch ${gap.scenarioId}\` to use them.`,
      ``,
      `## Attempt loop (up to ${VERIFY_ITERATION_BUDGET} attempts)`,
      ``,
      `For each attempt:`,
      `1. Run \`go test -run ${gap.pathId.replace('-', '')} ./tests/unit/ ./tests/integration/\`. Capture pass/fail.`,
      `2. Run \`./scripts/test-module.sh full ${gap.pathId}\`. This exercises the module against the deployed lab (test-module.sh handles its own credential import + cleanup between runs). Capture pass/fail.`,
      `3. If both pass, return success=true with iterationsUsed = current attempt count and the running list of fixesApplied (may be empty on a first-try pass).`,
      `4. If either fails, classify the failure:`,
      `   - PATHRUNNER-SIDE (fix and retry): Go compile error, panic, wrong ARN parse, wrong option name, missing import, wrong AWS SDK call, incorrect payload code-gen, missing os.environ.get in payload, wrong PATHFINDER_IDENTITY_DATA emission, test-assertion mismatch caused by module logic, timeout that a pathrunner-side constant would fix.`,
      `   - HARD STOP (do not iterate — return immediately with hardStopReason set): \`plabs credentials\` returned empty (scenario not deployed), terraform state drift, missing pl-* resource in the lab, SSO expired mid-run, plabs status shows disabled, or any signal the failure is on the lab side or environmental.`,
      `5. On PATHRUNNER-SIDE classification: read the implicated file(s), apply the minimal fix via Edit. ONLY edit under \`pkg/exploits/**\`, \`pkg/payloads/**\`, and rarely \`pkg/discovery/**\` or \`pkg/modules/**\`. NEVER touch \`../pathfinding-labs/**\` or \`../pathfinding.cloud/**\`. NEVER call \`plabs enable/disable/apply\` — the lab stays exactly as it was. NEVER commit.`,
      `6. Run \`make build\` (regenerates register.go and compiles). If build fails, that's a bug in the fix — either fix again within the remaining budget or bail with success=false and error describing what you tried.`,
      `7. Record the fix as \`{ attempt: <n>, failureClass: <short>, filesEdited: [...], summary: <one-line> }\` and loop.`,
      ``,
      `## Termination conditions`,
      `- Pass on any attempt → return success=true with iterationsUsed and fixesApplied.`,
      `- Hard-stop classification at any point → return success=false with hardStopReason set. Do NOT iterate through a lab-side failure.`,
      `- Budget exhausted without passing → return success=false with a concise error describing the final failure state and the fixesApplied history.`,
      `- Can't confidently identify the fix location → return success=false with error "could not localize fix", short of exhausting the budget. Better to bail than guess.`,
      ``,
      `## Guardrails (repeat)`,
      `- Read-only for lab side: \`../pathfinding-labs/**\` and \`../pathfinding.cloud/**\` are reference only.`,
      `- Never call plabs enable/disable/apply/swap during this stage. Disable happens in the next pipeline stage.`,
      `- Never git commit.`,
      `- If you can't understand the failure output, bail rather than making shot-in-the-dark edits.`,
      ``,
      `Return structured output following VERIFY_SCHEMA.`,
    ].join('\n'),
    { label: `verify:${gap.pathId}`, phase: 'Verify', schema: VERIFY_SCHEMA },
  )

  // Capture iteration info regardless of pass/fail so the final summary reflects
  // what the fix loop actually did.
  state.verifyInfo = result || {}
  state.iterationsUsed = result?.iterationsUsed ?? 0
  state.fixesApplied = result?.fixesApplied ?? []

  if (!result || !result.success) {
    const hardStop = result?.hardStopReason ? ` (hard-stop: ${result.hardStopReason})` : ''
    state.errors.push(`verify: ${result?.error || 'agent returned null or unsuccessful'}${hardStop}`)
    return state
  }
  state.tested = true
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
