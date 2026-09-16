# Observability & health

First-class metrics, a built-in health dashboard, ready-made Grafana and alerting assets, and SIEM-bound audit forwarding.

## What it is

Helix IAM exposes Prometheus metrics and a console health view so you always know how authentication is performing across your realms.

### Metrics

Prometheus scrapes the standard endpoint. Alongside JVM and HTTP metrics, Helix IAM publishes purpose-built counters, each **tagged by realm**:

| Counter | Measures |
| --- | --- |
| `helix_login_total` | Login attempts / outcomes |
| `helix_tokens_issued_total` | Tokens issued |
| `helix_mfa_challenge_total` | MFA challenges raised |
| `helix_admin_write_total` | Administrative write operations |

### Health dashboard

The console **Health dashboard** summarises component health, realm inventory, and live login/token metrics in one place:

```
GET /admin/realms/{realm}/health
GET /admin/metrics/summary
```

## Over the monitoring endpoints

The actuator endpoints are **anonymous** — Prometheus and your load balancer scrape them with **no session, cookie or bearer token**. The examples below assume you have set `$HELIX_URL` — see [Authenticating to the API](../getting-started/api-authentication.md) — but note they need **no** `-b cookies.txt` and no CSRF.

### Scrape metrics — `GET /actuator/prometheus`

```bash
curl -s "$HELIX_URL/actuator/prometheus" | grep '^helix_'
```
```
helix_admin_write_total{method="DELETE",outcome="denied",realm="master"} 3.0
helix_admin_write_total{method="DELETE",outcome="success",realm="master"} 11.0
helix_admin_write_total{method="POST",outcome="denied",realm="master"} 1.0
helix_admin_write_total{method="POST",outcome="success",realm="master"} 11.0
helix_login_total{outcome="success",realm="master"} 11.0
```

The purpose-built counters carry a `realm` tag, so a single Prometheus target gives you per-realm login, token and admin-write rates.

### Liveness & readiness — `GET /actuator/health`

Point your load balancer and Kubernetes probes here — no auth required:

```bash
curl -s "$HELIX_URL/actuator/health"
```
```json
{
  "status": "DOWN",
  "groups": ["liveness", "readiness"],
  "components": {
    "db":              { "status": "UP" },
    "diskSpace":       { "status": "UP" },
    "livenessState":   { "status": "UP" },
    "ping":            { "status": "UP" },
    "readinessState":  { "status": "UP" },
    "redis":           { "status": "DOWN" },
    "ssl":             { "status": "UP" }
  }
}
```

Overall `status` aggregates **every** component, so one optional dependency drags the top-level status to `DOWN` — above, the eval stack runs without Redis, yet `livenessState` and `readinessState` stay `UP`. That is exactly why you should probe the group endpoints — `GET /actuator/health/liveness` and `GET /actuator/health/readiness` — to gate restarts and traffic independently of optional dependencies.

### Build & version — `GET /actuator/info`

```bash
curl -s "$HELIX_URL/actuator/info"
```

Populate this with build/version metadata to confirm which release is running — see [Upgrades & migrations](upgrades.md#confirm-the-running-version).

## Dashboards & alerts

A ready-to-import Grafana dashboard and a set of Prometheus alert rules ship in:

```
deploy/observability/
```

Import the dashboard into Grafana and load the alert rules into Prometheus to get production monitoring in minutes.

### Latency histograms

Enable HTTP latency histograms to unlock p99 panels:

```bash
HELIX_HTTP_HISTOGRAM=true
```

Leave this off unless you need percentile latency, since histograms add metric cardinality.

## Audit forwarding to SIEM

The audit log records administrative and authentication events and can be **forwarded to your SIEM** for long-term retention, correlation and alerting — pair it with [admin RBAC](admin-roles.md) so every write is attributable.

## See also

- [Admin roles (RBAC)](admin-roles.md)
- [Backup & disaster recovery](backup.md)
- [Security hardening](security.md)
- [Configuration](../getting-started/configuration.md)
