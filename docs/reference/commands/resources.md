# `pathrunner resources`

List and explore imported AWS resources

View AWS resources imported from cloudfox output

## Usage

```
pathrunner resources
```

## Subcommands

### `pathrunner resources clear`

Remove imported resources from the resource store

```
pathrunner resources clear [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--account` |  | string | — | Clear resources for a specific AWS account ID |
| `--all` |  | bool | `false` | Clear all imported resources |

### `pathrunner resources import`

Import cloudfox output data (alias for 'cloudfox import')

```
pathrunner resources import [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--path` |  | string | — | Cloudfox output directory path |

### `pathrunner resources list`

List imported resources, optionally filtered by service

```
pathrunner resources list [service] [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--account` |  | string | — | AWS account ID |
| `--wide` |  | bool | `false` | Show ARN and type columns |

### `pathrunner resources status`

Show import status

```
pathrunner resources status
```

### `pathrunner resources summary`

Show resource counts by service and region

```
pathrunner resources summary [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--account` |  | string | — | AWS account ID |

