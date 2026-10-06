# Documentation GIF tapes

These are [VHS](https://github.com/charmbracelet/vhs) `.tape` scripts that render the
command GIFs shown in the documentation reference. Because each tape is committed
text, every GIF is reproducible — re-render instead of re-recording by hand.

Rendered GIFs go to `docs/reference/gifs/` and are referenced from the generated
reference on pathfinding.cloud/pathrunner.

## Two categories

**1. CI-safe tapes (in this directory).** Either AWS-free metadata commands
(`help`, `modules-list`, `payloads`, `search`, `version`) or local-state commands
run through `scripts/docs-sandbox.sh` against synthetic fixtures
(`identity-list`, `attacker-identity-show`). None need credentials, make AWS calls,
or touch the operator's real `~/.pathrunner`. Render them all with:

```bash
make build                      # produce ./pathrunner
./scripts/render-docs-tapes.sh  # render every tape here -> docs/reference/gifs/
```

**2. Exploit / AWS-calling command GIFs (NOT rendered here).** Commands that
actually call AWS (module execution, `identity check`, `whoami`, the listener)
cannot run in a credential-less sandbox and there is no AWS mock seam in the repo.
They are captured against a **deployed pathfinding-lab**, then redacted — reusing
tooling that already exists:

- `scripts/test-module.sh` — deploys a lab, runs the pathrunner exploit, records
  the output, verifies, and tears the lab down.
- `pathfinding-labs/scripts/redact_transcripts.py` — strips access keys, secrets,
  session tokens, and account IDs from the captured output so it is safe to publish
  (the same redaction that powers the labs' "Run Simulated Demo" transcripts).
- `pathfinding-labs/scripts/capture_demos.py` is the publish-pipeline template
  (run -> redact -> copy into the site -> regenerate JSON).

The remaining work for this category is a thin "docs capture" wrapper that drives
`test-module.sh` and pipes its output through `redact_transcripts.py` into
`docs/reference/gifs/` + transcript files. It is intentionally out of the CI path
because it requires a live lab.

## Adding a tape

1. Copy an existing tape and change the `Output` path + the `Type` line.
2. If the command reads local state (identities, options, attacker identity, created
   resources), invoke it through `./scripts/docs-sandbox.sh <command>` so it runs
   against the synthetic fixtures rather than real state.
3. Keep the terminal size/theme consistent with the other tapes.
4. Re-render with `./scripts/render-docs-tapes.sh <name>.tape`.
