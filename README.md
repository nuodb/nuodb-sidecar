# NuoDB sidecar container image

![Build status](https://github.com/nuodb/nuodb-sidecar/actions/workflows/test/badge.svg)

The NuoDB sidecar container image bundles additional tools which help running NuoDB database in Kubernetes cluster.

## Requirements

| Software   | Release Requirements                           |
|------------|------------------------------------------------|
| Kubernetes |  The latest and previous minor released versions of Kubernetes. |
| NuoDB      |  Version [6.0.2](https://hub.docker.com/r/nuodb/nuodb/tags) and onwards. |

## Tools

| Command          | Description                                            |
|------------------|--------------------------------------------------------|
| [config_watcher](./config_watcher/README.md) | Watches for changes in `ConfigMap` or `Secret` resources and creates files out of resource's `data` in a target directory. |
| [nuodb-operations](./nuodb-operations/README.md) | Starts a server with NuoDB backup hooks and optionally custom operation handlers. |

## Usage

Follow the instructions on the [NuoDB Helm charts](https://github.com/nuodb/nuodb-helm-charts/blob/master/README.md#nuodb-helm-chart-installation) installation page.

NuoDB sidecar is used in [Admin](https://github.com/nuodb/nuodb-helm-charts/tree/master/stable/admin) and [Database](https://github.com/nuodb/nuodb-helm-charts/tree/master/stable/database) charts when enabling NuoDB collector (see `nuocollector.watcher` Helm variable).
NuoDB sidecar is used in [Database](https://github.com/nuodb/nuodb-helm-charts/tree/master/stable/database) chart when enabling database backup hooks (see `database.backupHooks.image`).

## Contribute

### Test requirements

| Software   | Release Requirements                           |
|------------|------------------------------------------------|
| Python     |  Version 3.12 and onwards. |
| Docker     |  Version 27.4.0 and onwards. |

### Development environment

To develop and test the tools localy, follow below steps.

- Create Python virtual environment with IDE or by running:

```sh
python3 -m venv .venv
source .venv/bin/activate
```

- Install Python dependencies for the tool that is under development. E.g.

```sh
python3 -m pip install -r config_watcher/requirements.txt
python3 -m pip install -r config_watcher/test-requirements.txt
```

- Make the necessary changes

- Run static analysis

```sh
make fmt lint
```

- Run the tests

```sh
make test
```
