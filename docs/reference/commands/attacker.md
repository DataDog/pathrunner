# `pathrunner attacker`

Manage attacker account identity

Configure an attacker-controlled AWS account for deploying resources used during exploitation

## Usage

```
pathrunner attacker
```

## Subcommands

### `pathrunner attacker clear`

Remove attacker identity (alias for 'attacker identity remove')

```
pathrunner attacker clear
```

### `pathrunner attacker identity`

Manage attacker identity

```
pathrunner attacker identity
```

#### `pathrunner attacker identity add`

Configure attacker identity credentials

```
pathrunner attacker identity add
```

##### `pathrunner attacker identity add keys`

Configure from access keys

```
pathrunner attacker identity add keys [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--access` |  | string | — | AWS access key ID |
| `--region` |  | string | — | AWS region (default: us-east-1) |
| `--secret` |  | string | — | AWS secret access key |
| `--token` |  | string | — | AWS session token (optional) |

##### `pathrunner attacker identity add profile`

Configure from AWS profile

```
pathrunner attacker identity add profile [name]
```

#### `pathrunner attacker identity remove`

Remove attacker identity

```
pathrunner attacker identity remove
```

#### `pathrunner attacker identity show`

Show current attacker identity

```
pathrunner attacker identity show
```

#### `pathrunner attacker identity validate`

Validate attacker credentials

```
pathrunner attacker identity validate
```

### `pathrunner attacker infra`

Manage attacker infrastructure

```
pathrunner attacker infra
```

#### `pathrunner attacker infra bucket`

Manage S3 bucket deployments

```
pathrunner attacker infra bucket
```

##### `pathrunner attacker infra bucket create`

Create an S3 bucket for code hosting or exfiltration

```
pathrunner attacker infra bucket create [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--region` |  | string | — | AWS region for the bucket |
| `--type` |  | string | — | Bucket type: code or exfil (default: exfil) |

##### `pathrunner attacker infra bucket destroy`

Destroy deployed bucket(s)

```
pathrunner attacker infra bucket destroy [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--name` |  | string | — | Specific bucket name to destroy (destroys all if omitted) |

##### `pathrunner attacker infra bucket status`

Show deployed buckets

```
pathrunner attacker infra bucket status
```

#### `pathrunner attacker infra destroy`

Tear down ALL deployed infrastructure

```
pathrunner attacker infra destroy
```

#### `pathrunner attacker infra ec2`

Deploy pathrunner to an EC2 instance

```
pathrunner attacker infra ec2
```

##### `pathrunner attacker infra ec2 create`

Create or update EC2 deployment

```
pathrunner attacker infra ec2 create [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--region` |  | string | — | AWS region for the EC2 instance |

##### `pathrunner attacker infra ec2 destroy`

Tear down EC2 deployment

```
pathrunner attacker infra ec2 destroy
```

##### `pathrunner attacker infra ec2 status`

Show EC2 deployment status

```
pathrunner attacker infra ec2 status
```

##### `pathrunner attacker infra ec2 update`

Update pathrunner binary on existing EC2 instance

```
pathrunner attacker infra ec2 update
```

#### `pathrunner attacker infra ecr`

Manage ECR repository deployments

```
pathrunner attacker infra ecr
```

##### `pathrunner attacker infra ecr create`

Create an ECR repo and push the bedrock runtime container image

```
pathrunner attacker infra ecr create [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--region` |  | string | — | AWS region for the ECR repository |

##### `pathrunner attacker infra ecr destroy`

Destroy all deployed ECR repositories

```
pathrunner attacker infra ecr destroy
```

##### `pathrunner attacker infra ecr status`

Show deployed ECR repositories

```
pathrunner attacker infra ecr status
```

#### `pathrunner attacker infra status`

Show all deployed infrastructure

```
pathrunner attacker infra status
```

### `pathrunner attacker listener`

Manage the unified credential collector and shell listener

```
pathrunner attacker listener
```

#### `pathrunner attacker listener log`

Show recent listener events

```
pathrunner attacker listener log [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--count` |  | int | `50` | Number of recent events to show |

#### `pathrunner attacker listener start`

Start the unified listener (HTTPS creds + TLS shells)

```
pathrunner attacker listener start [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--host` |  | string | — | Bind address (default: 0.0.0.0) |
| `--https-port` |  | int | `0` | Credential collection port (default: 8443) |
| `--public-ip` |  | string | — | Override auto-detected public IP |
| `--shell-port` |  | int | `0` | Reverse shell port (default: 4444) |

#### `pathrunner attacker listener status`

Show listener state and statistics

```
pathrunner attacker listener status
```

#### `pathrunner attacker listener stop`

Stop the listener

```
pathrunner attacker listener stop
```

### `pathrunner attacker set`

Configure attacker account credentials (alias for 'attacker identity add')

```
pathrunner attacker set
```

#### `pathrunner attacker set keys`

Configure from access keys

```
pathrunner attacker set keys [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--access` |  | string | — | AWS access key ID |
| `--region` |  | string | — | AWS region (default: us-east-1) |
| `--secret` |  | string | — | AWS secret access key |
| `--token` |  | string | — | AWS session token (optional) |

#### `pathrunner attacker set profile`

Configure from AWS profile

```
pathrunner attacker set profile [name]
```

### `pathrunner attacker show`

Show current attacker identity (alias for 'attacker identity show')

```
pathrunner attacker show
```

### `pathrunner attacker validate`

Validate attacker credentials (alias for 'attacker identity validate')

```
pathrunner attacker validate
```

