# Configuration watcher

This is an application that watches for changes on `ConfigMap` or `Secret` resources with a specified label selector and stores their `data` as files in a local directory.
An optional HTTP/s webhook URL is executed on a resource change.
The main purpose of the config watcher is to run as a sidecar for applications that need their configuration to be updated dynamically from the Kubernetes cluster state.

## Feature

- Create, update, and delete files from `ConfigMap` or `Secret` resource `data` field.
- Execute optional HTTP/s webhook URL on resource change
- Multi-namespace support

## Confugration

### Kubernetes API server

The config watcher needs read access to watched resources (either `configmaps` or `secrets`) for all watched namespaces.
For example, below is a `Role` that allows read access to `configmaps` in a single namespace.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: config-watcher
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "watch", "list"]
```

### Environment variables

| Name             | Description                                            | Default   | Type | Required |
|------------------|--------------------------------------------------------|-----------|------|---------|
| `LABEL_SELECTOR` | Kubernetes [label selector](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors) used for filtering the resources.  | `null` | string | `true` |
| `TARGET_DIRECTORY` | Local directory path where the files will be created.  | `null` | string | `true` |
| `RESOURCE_TYPE` | Resource type to watch for changes.  | `config_map` | `config_map` or `secret` | `false` |
| `NAMESPACES` | A comma-separated list of Kubernetes namespaces to watch for resource changes. If the application is running in-cluster the default namespace will be inferred from `/var/run/secrets/kubernetes.io/serviceaccount/namespace` file. | `default` | string | `false` |
| `WATCH_TIMEOUT` | Server-side timeout in seconds for the watch API call. The config watcher will reinitialize a new watch API call once this timeout expires. | `60` | `seconds` | `false` |
| `WEBHOOK_URL` | Webhook URL to send a request to after a file content update. | `null` | `string` | `false` |
| `WEBHOOK_METHOD` | Webhook method. | `GET` | `GET`, `POST`, `PUT` or `PATCH` | `false` |
| `WEBHOOK_PAYLOAD` | JSON payload for the webhook. | `null` | `JSON` | `false` |
| `WEBHOOK_TIMEOUT` | Timeout in seconds for the webhook request. | `60` | `seconds` | `false` |
| `WEBHOOK_VERIFY` | Whether to verify the webhook server's TLS certificate. | `true` | `boolean` | `false` |
| `RETRY_COUNT` | The number of retries for all requests. | `5` | `int` | `false` |
| `SHUTDOWN_TIMEOUT` | Timeout in seconds for graceful shutdown of the application. If set to a value greater than `0`, the watcher container may be reported in `Terminating` state. | `0` | `seconds` | `false` |
