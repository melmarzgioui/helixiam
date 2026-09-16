# Backup & disaster recovery

One database holds your durable state — back it up well and recovery is straightforward.

## What it is

Helix IAM's persistent state lives in a single **PostgreSQL** database: realms, users, clients, keys, policy and audit history. helix-iam-server itself holds nothing that needs backing up beyond that database — protecting your deployment comes down to protecting that one database (plus, in one case below, your keystore, and Redis if you rely on session continuity across a Redis restart).

## Scripts & scheduling

Backup and restore tooling ships in `deploy/backup/`:

```bash
# Take a logical backup (pg_dump)
deploy/backup/backup.sh

# Restore into a target database (pg_restore)
deploy/backup/restore.sh
```

A Kubernetes **CronJob** is included for scheduled, unattended backups, and a **DR runbook** walks through full recovery.

!!! danger "DB_ENCRYPTION is part of your backup"
    Sensitive columns are encrypted with `DB_ENCRYPTION`. A database backup is **useless without the exact same key**, and the key must never change after first boot. Store `DB_ENCRYPTION` securely and separately from the database dump, back it up, and never rotate it. See [security hardening](security.md).

!!! warning "Back up /jks if you seed keys from files"
    If you seed the master-realm signing key from files, include the `/jks` keystore in your backup. Without it, a restored database will not match the published JWKS and tokens will fail to verify. See [Realm keys](realm-keys.md).

## Realm export — portable config backup

The `pg_dump` above is your authoritative, byte-for-byte backup. Alongside it, Helix can export a **single realm** as a self-contained JSON document — realm settings, clients, roles, users, flows, identity providers and more. It is the right tool for migrating a realm between environments, snapshotting config into version control, or seeding a fresh install; it complements (does not replace) the database backup. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### Export a realm — `GET /admin/realms/{realm}/export`

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/export" > $REALM-export.json
jq 'keys' $REALM-export.json
```
```json
[
  "adminRoles", "agents", "applications", "authorizationServices",
  "clientProtocolMappers", "clientRoles", "clientScopes", "clients",
  "flows", "formatVersion", "groups", "identityProviders",
  "messageTemplates", "messagingProviders", "organizations", "realm",
  "requiredEnv", "resourceIndicators", "roles", "samlClients",
  "scimTargets", "serviceAccountRoles", "users", "webhooks", "workloadIdentity"
]
```

The document carries a `formatVersion` and a `requiredEnv` list naming the secrets (identity-provider client secrets, token endpoints) the target environment must supply — the export never contains those secret **values**:

```bash
jq '{formatVersion, requiredEnv}' $REALM-export.json
```
```json
{
  "formatVersion": 2,
  "requiredEnv": [
    "HELIX_MASTER_IDP_EIDAS_CLIENTSECRET",
    "HELIX_MASTER_IDP_EIDAS_TOKENURL"
  ]
}
```

### Re-import — `POST /admin/realms/{realm}/import`

Restore or seed a realm by POSTing the exported document back (a write, so refresh the CSRF token first):

```bash
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/export" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  --data-binary @"$REALM-export.json" \
  "$HELIX_URL/admin/realms/$REALM/import"
```

!!! note "Config, not durable state"
    Realm export is a **configuration** backup, not a substitute for the database dump: it does not carry event history, encrypted credential material, or live sessions. Use it for migration and config-as-code; use `pg_dump` for full disaster recovery. A Keycloak realm JSON can be imported via `POST /admin/realms/{realm}/import/keycloak`.

## RPO and RTO

- **RPO (recovery point objective)** equals your **backup interval** — the most data you can lose. A nightly backup means up to ~24 h of loss. Tighten the RPO toward zero with **WAL archiving / point-in-time recovery (PITR)**.
- **RTO (recovery time objective)** is how long restore takes: provision PostgreSQL, run `restore.sh`, restore `/jks` if used, and start helix-iam-server and the console. Because the server carries no state outside the database, it returns to service as soon as the database is up.

## How to recover

1. Provision a PostgreSQL instance.
2. Run `deploy/backup/restore.sh` against it.
3. Restore the `/jks` keystore if you seed keys from files.
4. Ensure `DB_ENCRYPTION` matches the original.
5. Start helix-iam-server, then the console.

## See also

- [Realm keys](realm-keys.md)
- [Upgrades & migrations](upgrades.md)
- [Security hardening](security.md)
- [Configuration](../getting-started/configuration.md)
