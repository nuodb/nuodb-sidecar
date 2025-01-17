# NuoDB operations

An HTTP server that allows remote operations on NuoDB engine containers.

## Feature

- Pre-post backup hooks for snapshot-based NuoDB backup
- Support for custom scripts to be invoked on HTTP requests

## Confugration

### Sidecar configuration

The application must have write access to NuoDB archive and journal volumes which can be mounted using container `volumeMounts`.
It is required that the `shareProcessNamespace` Pod spec field is set to `true`.

### Environment variables

| Name             | Description                                            | Default   | Type | Required |
|------------------|--------------------------------------------------------|-----------|------|---------|
| `FREEZE_MODE` | The freeze mode to be used when executing backup hooks. | `null` | `hotsnap`, `fsfreeze` or `suspend` | `true` |
| `NUODB_ARCHIVE_DIR` | NuoDB archive directory path. | `/mnt/archive` | string | `false` |
| `NUODB_JOURNAL_DIR` | NuoDB archive directory path. Must be set if external journal is enabled. | `null` | string | `false` |
| `FREEZE_TIMEOUT` | Timeout in seconds after which the archive will be automatically unfrozen. | `null` | int | `false` |

### Commands

#### server

Starts HTTP server for backup operations.

| Argument         | Description                                            | Default   |
|------------------|--------------------------------------------------------|-----------|
| `--port` | The local port used by the server to listen on. | `80` |
| `--handler-config` | Path to the YAML file which contains custom handlers to register on the HTTP server. | `/etc/nuodb/handlers.json` |

#### pre-hook

Executes pre-backup hook.

| Argument         | Description                                            | Default   |
|------------------|--------------------------------------------------------|-----------|
| `--backup-id` | The ID associated with this backup. Required. | `null` |
| `--opaque-file` | Path to a file containing user-defined information to associate with the backup. | `null` |
| `--timeout` | Timeout in seconds after which the archive will be automatically unfrozen. Zero means no timeout. | `0` |

#### post-hook

Executes post-backup hook.

| Argument         | Description                                            | Default   |
|------------------|--------------------------------------------------------|-----------|
| `--backup-id` | The ID associated with this backup. Required. | `null` |
| `--force` | Unfreeze the archive even if the supplied backup ID doesn't match the one for the current backup. | `false` |
