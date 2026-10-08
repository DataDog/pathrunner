# `pathrunner identity`

Manage AWS identities

Add, list, switch, and manage AWS credential identities

## Usage

```
pathrunner identity
```

## Subcommands

### `pathrunner identity add`

Add AWS identity

```
pathrunner identity add [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--access` |  | string | — | Access key ID (requires --secret) |
| `--check-admin` |  | bool | `false` | Auto-check admin privileges after adding |
| `--from-clipboard` |  | bool | `false` | Read credentials from clipboard or stdin |
| `--from-file` |  | string | — | Read credentials from file |
| `--from-output` |  | bool | `false` | Extract credentials from last exploit output |
| `--from-profile` |  | string | — | AWS profile name (alias for --profile) |
| `--name` |  | string | — | Custom name for the identity |
| `--profile` |  | string | — | AWS profile name |
| `--secret` |  | string | — | Secret access key |
| `--switch` |  | bool | `false` | Auto-switch to the new identity without prompting |
| `--token` |  | string | — | Session token (optional) |

### `pathrunner identity check`

Check if identity has admin privileges

```
pathrunner identity check [name]
```

### `pathrunner identity clear`

Remove identity or clear expired identities

```
pathrunner identity clear [identity-name] [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--expired` |  | bool | `false` | Remove all expired identities |

### `pathrunner identity current`

Show current identity details

```
pathrunner identity current
```

### `pathrunner identity list`

List all configured identities

```
pathrunner identity list
```

### `pathrunner identity refresh`

Refresh current identity credentials

```
pathrunner identity refresh
```

### `pathrunner identity show`

Show current identity details

```
pathrunner identity show
```

### `pathrunner identity switch`

Switch to different identity

```
pathrunner identity switch <name>
```

