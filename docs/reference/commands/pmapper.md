# `pathrunner pmapper`

Import and analyze PMapper privilege escalation graphs

Import PMapper graph data, find escalation paths, and map them to pathrunner modules

## Usage

```
pathrunner pmapper
```

## Subcommands

### `pathrunner pmapper analyze`

Analyze escalation paths for current identity

```
pathrunner pmapper analyze [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--all` |  | bool | `false` | Analyze all workspace identities |

### `pathrunner pmapper import`

Import PMapper graph data

```
pathrunner pmapper import [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--path` |  | string | — | PMapper data directory path |

### `pathrunner pmapper status`

Show graph metadata and module coverage

```
pathrunner pmapper status
```

