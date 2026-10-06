# Documentation fixtures (synthetic state)

These files are **entirely synthetic** sample state used to render the documentation
demos for local-state commands (`identity list`, `workspace list`, `show options`,
`attacker identity show`, etc.) without using any real credentials, accounts, or the
operator's own `~/.pathrunner` state.

Everything here uses obviously-fake values:

- Account IDs `111111111111` (victim) and `222222222222` (attacker)
- `AKIAEXAMPLE…` / `ASIAEXAMPLE…` access key IDs and placeholder secrets/tokens
- `pl-demo-*` resource names and example ARNs

## How they are used

`scripts/docs-sandbox.sh` copies these into a throwaway `HOME` and sets
`PATHRUNNER_WORKSPACE=demo`, so pathrunner reads this fixture state instead of the
operator's real `~/.pathrunner`. The VHS tapes under `docs/reference/tapes/` run
through that sandbox, so the generated GIFs only ever show synthetic data.

Layout mirrors `~/.pathrunner/`:

```
docs/fixtures/
  sessions/demo.json        -> ~/.pathrunner/sessions/demo.json   (the "demo" workspace)
  attacker_identity.json    -> ~/.pathrunner/attacker_identity.json
```

## What they are NOT

These are not test fixtures for Go unit tests and are not loaded by the pathrunner
binary in normal operation. They exist purely to make documentation output
reproducible and free of real data.
