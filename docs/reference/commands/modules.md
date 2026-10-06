# `pathrunner modules`

List and search modules

## Usage

```
pathrunner modules
```

## Subcommands

### `pathrunner modules list`

List all available modules

```
pathrunner modules list [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--wide` |  | bool | `false` | Include description column |

### `pathrunner modules mark-results`

Record per-payload test results for a module

```
pathrunner modules mark-results <module-id> <scenario-id> <results-json-file>
```

### `pathrunner modules mark-status`

Set module test status (tested|untested|failing|needs-update)

```
pathrunner modules mark-status <module-id> <status>
```

### `pathrunner modules mark-tested`

Mark a module as tested

```
pathrunner modules mark-tested <module-id> [lab-name]
```

### `pathrunner modules search`

Search modules by keyword

```
pathrunner modules search <query>
```

### `pathrunner modules status`

Show test status for modules

```
pathrunner modules status [module-id]
```

### `pathrunner modules summary`

Show module count by service

```
pathrunner modules summary
```

