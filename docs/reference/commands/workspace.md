# `pathrunner workspace`

Manage pathrunner workspaces

Create, switch, save, delete, and manage pathrunner workspaces

## Usage

```
pathrunner workspace
```

## Subcommands

### `pathrunner workspace cleanup`

Clean up AWS resources in current workspace

```
pathrunner workspace cleanup [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--all` |  | bool | `false` | Clean up all resources without interactive prompt |
| `--module` |  | string | — | Only clean up resources created by a specific module ID |
| `--yes` | `-y` | bool | `false` | Skip interactive confirmation prompt |

### `pathrunner workspace create`

Create new workspace

```
pathrunner workspace create <name>
```

### `pathrunner workspace delete`

Delete workspace

```
pathrunner workspace delete <name>
```

### `pathrunner workspace history`

Show command history with timestamps

```
pathrunner workspace history
```

### `pathrunner workspace list`

List all workspaces

```
pathrunner workspace list
```

### `pathrunner workspace report`

Generate cleanup report for handoff to client/admin

```
pathrunner workspace report [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--module` |  | string | — | Only report resources from a specific module ID |
| `--output` | `-o` | string | — | Write report to file (format inferred from extension: .html or .md) |

### `pathrunner workspace save`

Save current workspace state

```
pathrunner workspace save
```

### `pathrunner workspace switch`

Switch to different workspace

```
pathrunner workspace switch <name>
```

