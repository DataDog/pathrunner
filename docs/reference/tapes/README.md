# Documentation GIF tapes

These are [VHS](https://github.com/charmbracelet/vhs) `.tape` scripts that render the
command GIFs shown in the documentation reference. Because each tape is committed
text, every GIF is reproducible — re-render instead of re-recording by hand.

Rendered GIFs go to `docs/reference/gifs/` and are referenced from the generated
reference on pathfinding.cloud/pathrunner.

## Two categories

**1. CI-safe tapes (in this directory).** Either AWS-free metadata commands
(`help`, `modules-list`, `modules-info`, `modules-summary`, `modules-status`,
`payloads`, `search`, `version`) or local-state commands run through
`scripts/docs-sandbox.sh` against synthetic fixtures (`identity-list`,
`identity-show`, `identity-switch`, `identity-current`, `attacker-identity-show`,
`attacker-listener-status`, `attacker-infra-status`, `workspace-list`,
`workspace-create`, `use-show-options`, `show-payloads`). None need credentials,
make AWS calls, or touch the operator's real `~/.pathrunner`. Render them all with:

```bash
make build                      # produce ./pathrunner
./scripts/render-docs-tapes.sh  # render every tape here -> docs/reference/gifs/
```

**2. Exploit / AWS-calling command GIFs (NOT rendered here).** Commands that
actually call AWS (module execution with `exploit`, `identity check`, `whoami`,
`attacker listener start`, `pmapper analyze`, `discover`, `identity add`)
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

1. Copy an existing tape and change the `Output` path and command.
2. **Single command:** pass arguments to `./scripts/docs-sandbox.sh <command>` so it
   runs against the synthetic fixtures rather than real state. AWS-free commands can
   call `./pathrunner <command>` directly without the sandbox wrapper.
3. **Multi-step REPL workflow:** call `./scripts/docs-sandbox.sh` with no arguments
   to open the REPL, then `Type` each command followed by `Enter` and `Sleep`. See
   `use-show-options.tape` for the pattern.
4. Keep terminal size and theme consistent with the other tapes (Dracula, FontSize 16,
   Width 1100–1200, Padding 20). Adjust Height to fit the expected output.
5. Re-render with `./scripts/render-docs-tapes.sh <name>.tape`.
