# trix

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.0](https://img.shields.io/badge/AppVersion-0.1.0-informational?style=flat-square)

Kubernetes Security Scanner with AI-Powered Triage and Continuous Monitoring

**Homepage:** <https://github.com/davealtena/trix>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| Dave Altena |  | <https://github.com/davealtena> |

## Source Code

* <https://github.com/davealtena/trix>

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2+
- [Trivy Operator](https://aquasecurity.github.io/trivy-operator/) installed in your cluster

## Installation

```bash
helm repo add trix https://davealtena.github.io/trix
helm repo update
helm install trix trix/trix -n trix-system --create-namespace
```

### With Slack notifications

```bash
helm install trix trix/trix -n trix-system --create-namespace \
  --set notifications.slack.enabled=true \
  --set notifications.slack.webhookUrl="https://hooks.slack.com/services/..."
```

### With external PostgreSQL

```bash
helm install trix trix/trix -n trix-system --create-namespace \
  --set postgresql.enabled=false \
  --set postgresql.external.host=my-postgres.example.com \
  --set postgresql.external.user=trix \
  --set postgresql.external.password=secret \
  --set postgresql.external.database=trix
```

## Uninstallation

```bash
helm uninstall trix -n trix-system
```

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity rules |
| config.logFormat | string | `"json"` | Log format (json or text) |
| config.logLevel | string | `"info"` | Log level (debug, info, warn, error) |
| config.minSeverity | string | `"CRITICAL"` | Minimum severity for notifications (CRITICAL, HIGH, MEDIUM, LOW) |
| config.namespaces | string | `""` | Namespaces to watch (comma-separated, empty for all) |
| config.pollInterval | string | `"5m"` | Poll interval for Trivy CRDs |
| fullnameOverride | string | `""` | Override the full name |
| healthCheck.port | int | `8080` | Port for health endpoints |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| image.repository | string | `"ghcr.io/davealtena/trix"` | Image repository |
| image.tag | string | `""` | Image tag (defaults to appVersion) |
| imagePullSecrets | list | `[]` | Image pull secrets |
| livenessProbe.httpGet.path | string | `"/healthz"` |  |
| livenessProbe.httpGet.port | string | `"health"` |  |
| livenessProbe.initialDelaySeconds | int | `10` |  |
| livenessProbe.periodSeconds | int | `30` |  |
| nameOverride | string | `""` | Override the name |
| nodeSelector | object | `{}` | Node selector |
| notifications.slack.enabled | bool | `false` | Enable Slack notifications |
| notifications.slack.existingSecret | string | `""` | Use existing secret for Slack webhook |
| notifications.slack.existingSecretKey | string | `"webhook-url"` | Key in existing secret |
| notifications.slack.webhookUrl | string | `""` | Slack webhook URL (use existingSecret for production) |
| notifications.webhook.enabled | bool | `false` | Enable generic webhook notifications |
| notifications.webhook.url | string | `""` | Webhook URL |
| podAnnotations | object | `{}` | Pod annotations |
| podSecurityContext | object | `{"fsGroup":65534,"runAsNonRoot":true,"runAsUser":65534}` | Pod security context |
| postgresql.database | string | `"trix"` | PostgreSQL database |
| postgresql.enabled | bool | `true` | Deploy PostgreSQL as part of this chart |
| postgresql.external | object | `{"database":"trix","existingSecret":"","existingSecretPasswordKey":"password","existingSecretUserKey":"username","host":"","password":"","port":5432,"sslMode":"disable","user":"trix"}` | Use external PostgreSQL |
| postgresql.external.database | string | `"trix"` | External PostgreSQL database |
| postgresql.external.existingSecret | string | `""` | Use existing secret for PostgreSQL credentials |
| postgresql.external.existingSecretPasswordKey | string | `"password"` | Key for password in existing secret |
| postgresql.external.existingSecretUserKey | string | `"username"` | Key for username in existing secret |
| postgresql.external.host | string | `""` | External PostgreSQL host |
| postgresql.external.password | string | `""` | External PostgreSQL password (use existingSecret for production) |
| postgresql.external.port | int | `5432` | External PostgreSQL port |
| postgresql.external.sslMode | string | `"disable"` | SSL mode |
| postgresql.external.user | string | `"trix"` | External PostgreSQL user |
| postgresql.image.pullPolicy | string | `"IfNotPresent"` |  |
| postgresql.image.repository | string | `"postgres"` |  |
| postgresql.image.tag | string | `"16-alpine"` |  |
| postgresql.password | string | `""` | PostgreSQL password (auto-generated if empty) |
| postgresql.persistence.accessMode | string | `"ReadWriteOnce"` | Access mode |
| postgresql.persistence.enabled | bool | `true` | Enable persistence |
| postgresql.persistence.size | string | `"1Gi"` | PVC size |
| postgresql.persistence.storageClass | string | `""` | Storage class (empty for default) |
| postgresql.resources | object | `{"limits":{"memory":"512Mi"},"requests":{"cpu":"100m","memory":"128Mi"}}` | PostgreSQL resources |
| postgresql.user | string | `"trix"` | PostgreSQL user |
| readinessProbe.httpGet.path | string | `"/readyz"` |  |
| readinessProbe.httpGet.port | string | `"health"` |  |
| readinessProbe.initialDelaySeconds | int | `5` |  |
| readinessProbe.periodSeconds | int | `10` |  |
| replicaCount | int | `1` | Number of replicas (only 1 supported for now due to database state) |
| resources | object | `{"limits":{"cpu":"200m","memory":"256Mi"},"requests":{"cpu":"50m","memory":"64Mi"}}` | Resource requests and limits |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true}` | Container security context |
| serviceAccount.annotations | object | `{}` | Annotations for the service account |
| serviceAccount.create | bool | `true` | Create a service account |
| serviceAccount.name | string | `""` | Name of the service account (generated if not set) |
| tolerations | list | `[]` | Tolerations |

## Configuration Examples

### Minimal configuration

```yaml
notifications:
  slack:
    enabled: true
    webhookUrl: "https://hooks.slack.com/services/..."
```

### Production configuration

```yaml
config:
  pollInterval: "5m"
  minSeverity: "HIGH"
  namespaces: "production,staging"

notifications:
  slack:
    enabled: true
    existingSecret: "my-slack-secret"
    existingSecretKey: "webhook-url"

postgresql:
  enabled: false
  external:
    host: "postgres.example.com"
    existingSecret: "my-postgres-secret"
    sslMode: "require"

resources:
  requests:
    memory: 128Mi
    cpu: 100m
  limits:
    memory: 512Mi
    cpu: 500m
```

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
