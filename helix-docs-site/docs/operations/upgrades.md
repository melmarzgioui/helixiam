# Upgrades & migrations

Roll forward to a new release with a backward-compatible schema and a zero-downtime deployment order.

## What it is

Helix IAM manages its database schema one of two ways:

- **Built-in bootstrap (default).** An idempotent bootstrap brings the schema to the required shape on startup. No extra configuration.
- **Versioned Flyway migrations (opt-in).** Versioned migration scripts are applied on startup, giving you an auditable, ordered migration history.

Enable Flyway-managed migrations with:

```bash
HELIX_MIGRATIONS_ENABLED=true
HELIX_SQL_INIT_MODE=never
```

Setting `HELIX_SQL_INIT_MODE=never` hands schema ownership entirely to the versioned migrations so the two mechanisms don't overlap.

## Migration discipline

Migrations are **additive and backward-compatible**: a new release runs against the previous schema, and the previous release tolerates the new schema. This is what makes rolling upgrades safe.

!!! danger "Never edit a released migration"
    Once a migration has shipped and been applied anywhere, it is immutable. To change the schema, **add a new migration**. Editing an applied migration breaks checksum validation and corrupts the migration history.

## Zero-downtime rolling upgrade

Deploy in this order:

1. **Back up first.** Take a fresh database backup — see [Backup & disaster recovery](backup.md).
2. **Roll out helix-iam-server.** The first pod/instance to start applies any pending migrations; because
   migrations are backward-compatible, the still-running old instances keep working against the same
   schema during the rollout. Session and token state lives in PostgreSQL (and Redis, if configured), not
   in any one instance, so a rolling replacement drops no logins and no in-flight sessions.
3. **Deploy the console.**

Following this order, end users never see an outage during an upgrade.

## Confirm the running version

Before and after an upgrade, check which release is live and that it came up healthy. Both endpoints are **anonymous** — no session or token needed — so they work from any host that can reach the server. See [Authenticating to the API](../getting-started/api-authentication.md) for `$HELIX_URL`.

```bash
# Build / version metadata — populate the info contributor to surface git + build details
curl -s "$HELIX_URL/actuator/info"

# Readiness after the rollout settles — probe the group, not the aggregate
curl -s "$HELIX_URL/actuator/health/readiness"
```
```json
{ "status": "UP" }
```

!!! tip "Verify the migration ran"
    With Flyway enabled, helix-iam-server logs the applied versions on startup, and `flyway_schema_history` in the database records every applied migration and its checksum. A `readiness` of `UP` after the restart confirms the schema reached the shape the new release expects. See [Observability & health](observability.md#over-the-monitoring-endpoints).

## How to upgrade

1. Read the release notes for the target version.
2. Back up the database (and `/jks` if you seed keys from files).
3. Roll out helix-iam-server, then the console.
4. Confirm the running version with `GET /actuator/info` and health on the [observability dashboard](observability.md).

## See also

- [Backup & disaster recovery](backup.md)
- [Observability & health](observability.md)
- [Security hardening](security.md)
- [Configuration](../getting-started/configuration.md)
