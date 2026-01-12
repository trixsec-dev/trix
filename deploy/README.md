# trix Server Deployment

Deploy trix as a long-running server that monitors Trivy findings and sends notifications.

## Prerequisites

- Kubernetes cluster with [Trivy Operator](https://aquasecurity.github.io/trivy-operator/) installed
- kubectl with kustomize support

## Installation

### 1. Create the database secret

Before deploying, create a secret with PostgreSQL credentials:

```bash
kubectl create namespace trix-system

kubectl create secret generic trix-db-credentials -n trix-system \
  --from-literal=POSTGRES_USER=trix \
  --from-literal=POSTGRES_PASSWORD=$(openssl rand -base64 24) \
  --from-literal=POSTGRES_DB=trix
```

Or use your preferred secret management (External Secrets, Sealed Secrets, etc.).

### 2. Deploy

```bash
kubectl apply -k github.com/trixsec-dev/trix/deploy
```

Or clone and customize:

```bash
git clone https://github.com/trixsec-dev/trix.git
cd trix/deploy

# Edit server.yaml to configure notifications
kubectl apply -k .
```

## Configuration

Edit `server.yaml` to configure notifications:

```yaml
env:
  - name: TRIX_NOTIFY_SLACK
    value: "https://hooks.slack.com/services/..."
  - name: TRIX_NOTIFY_SEVERITY
    value: "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
```

| Variable | Description | Default |
|----------|-------------|---------|
| `TRIX_POLL_INTERVAL` | How often to poll Trivy CRDs | `5m` |
| `TRIX_NAMESPACES` | Namespaces to watch (comma-separated, empty=all) | all |
| `TRIX_NOTIFY_SLACK` | Slack incoming webhook URL | - |
| `TRIX_NOTIFY_WEBHOOK` | Generic webhook URL | - |
| `TRIX_NOTIFY_SEVERITY` | Minimum severity to notify | `CRITICAL` |
| `TRIX_LOG_FORMAT` | `json` or `text` | `json` |
| `TRIX_LOG_LEVEL` | `debug`, `info`, `warn`, `error` | `info` |

## Verify

```bash
kubectl get pods -n trix-system
kubectl logs -n trix-system deployment/trix-server
```
