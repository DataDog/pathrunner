# Contributing

First off, thanks for taking the time to contribute!

## How to Contribute

### Reporting Bugs

Open a [GitHub Issue](https://github.com/DataDog/pathrunner/issues) with:
- A clear description of the bug
- Steps to reproduce (REPL/CLI commands used)
- Expected vs actual behavior
- Your environment (OS, Go version, AWS region)

### Suggesting New Modules or Payloads

Open an issue with the label `new-module` or `new-payload` describing:
- The AWS service and privilege escalation technique
- The attack path (e.g., `Principal A → iam:PassRole + lambda:CreateFunction → Principal B`)
- Whether it corresponds to an existing [pathfinding.cloud](https://pathfinding.cloud) path ID
- Whether a [pathfinding-labs](https://github.com/DataDog/pathfinding-labs) scenario exists to validate against

### Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b my-new-module`)
3. Make your changes following the conventions in [CLAUDE.md](CLAUDE.md)
4. Run `make build` and `make test`
5. Validate your module against a deployed [pathfinding-labs](https://github.com/DataDog/pathfinding-labs) scenario
6. Open a pull request against `main`

### Module and Payload Conventions

- Use the [`/create-module`](.claude/skills/create-module) skill for scaffolding — it has the full templates and checklist
- Every new command/subcommand/option needs matching REPL and CLI handlers, plus tab completion and tests (see the checklist in [CLAUDE.md](CLAUDE.md))
- Exploit modules go in `pkg/exploits/<module-name>/` and are picked up automatically by `make build` (no manual wiring needed)
- New commands and features MUST have both unit and integration tests
- See [CLAUDE.md](CLAUDE.md) for the full architecture and development guide

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
