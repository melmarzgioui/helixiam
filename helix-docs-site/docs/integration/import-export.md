# Import / Export & Migration

Move a realm's **entire configuration** between environments as a single file — export it, commit it, and apply it elsewhere — and migrate in from an existing identity provider.

## What it is

Helix IAM treats a realm's configuration as portable, version-controllable data. You can **export** a realm as one self-contained document and **import** it into another — to promote config from staging to production, seed a new tenant, or keep configuration in git. Secrets are never written to the file as literals: they appear as **`${ENV_VAR}` placeholders** and are resolved from the environment on import. The same document can be **dropped into a folder** that the server reads on startup (config-as-code).

| Endpoint / mechanism | Purpose |
| --- | --- |
| `GET /admin/realms/{realm}/export` | Export the realm as a JSON document, secrets as `${ENV_VAR}` placeholders |
| `POST /admin/realms/{realm}/import?onConflict=…` | Apply a realm document — overwrite, skip, or fail on conflicts |
| **drop-in folder** (`/realms`) | Apply `*.json` / `*.yaml` realm files on startup, idempotently |
| migration import | Translate a realm-export from a previous provider — see [Migrate](#migrate-from-another-provider) |

## The file format (v2)

A single self-describing document per realm. The **realm id comes from the path or file name**, never the document — so an export re-homes into any realm. Unset slices may be omitted; unknown fields are ignored (forward-compatible).

```json
{
  "formatVersion": 2,
  "realm":  { "displayName": "Gov", "captchaSecretKey": "${HELIX_GOV_CAPTCHA_SECRET}" },
  "roles":  [ { "name": "ledger-writer" } ],
  "clientScopes": [ { "name": "billing", "claims": [ { "key": "dept", "mandatory": false } ] } ],
  "clients": [ { "clientId": "billing", "grantTypes": ["authorization_code","client_credentials"],
                 "redirectUris": ["https://billing.example.com/callback"], "scopes": ["openid","billing"] } ],
  "identityProviders": [ { "alias": "google", "protocol": "oidc",
      "config": { "clientId": "…", "clientSecret": "${HELIX_GOV_IDP_GOOGLE_CLIENTSECRET}" } } ],
  "flows": [ { "alias": "browser", "executions": [ /* … */ ] } ],
  "samlClients": [ /* … */ ], "organizations": [ /* … */ ],
  "requiredEnv": [ "HELIX_GOV_CAPTCHA_SECRET", "HELIX_GOV_IDP_GOOGLE_CLIENTSECRET" ]
}
```

- **`requiredEnv`** lists every environment variable the file references — set these before importing elsewhere.
- **Excluded by design:** realm signing keys (each environment mints its own) and user password / MFA secrets.
- Both **JSON and YAML** are accepted by the drop-in folder loader; the export endpoint returns JSON.

## Export a realm

```bash
curl https://auth.example.com/admin/realms/acme/export \
  -H "Authorization: Bearer $ADMIN_TOKEN" > acme-realm.json
```

The document captures the realm's configuration. Every secret is emitted as a `${ENV_VAR}` placeholder — never the literal value — so the export is safe to review, commit, and share. The `requiredEnv` array tells you exactly which variables to provide on the target.

### What's included

A realm export bundles every configurable slice the admin console manages:

- **Realm settings** — login/token/session policy, branding, CAPTCHA, password policy
- **Applications**, their **OIDC clients**, and **SAML relying parties**
- **Per-client OIDC detail** — **protocol mappers**, **client roles**, **service-account role grants**, **resource-indicator allow-lists** (RFC 8707), and **authorization services** (UMA resource server: resources, scopes, policies, permissions)
- **Roles**, **client scopes** (with claim mappings), and **groups** (hierarchy + role mappings)
- **Identity providers** / federation brokers and **authentication flows**
- **Organizations** and **admin-RBAC** role grants
- **Webhooks**, **SCIM targets**, **messaging providers** + **message templates**, and **workload-identity** credentials
- **Users** — profiles and their realm-role / group assignments

Per-client slices carry the **OAuth client id** as their key, so they re-home into any realm: on import each is matched to the target realm's client and applied (a slice whose client isn't present in the target is skipped, never orphaned).

**Never exported** — regenerate or provision these on the target: realm **signing keys**, user **passwords and MFA secrets**, **GDPR consent ledgers** and **DSAR** (data-subject access request) records, and all runtime state (sessions, tokens, audit log). These are per-user runtime data, not realm configuration. Every secret-bearing config field above is emitted as a `${ENV_VAR}` placeholder, not a literal.

## Import a realm

```bash
# overwrite (default): upsert — existing resources are updated in place
curl -X POST "https://auth.example.com/admin/realms/acme/import?onConflict=overwrite" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  --data @acme-realm.json
```

Import is an **idempotent upsert by natural key** (client `clientId`, role `name`, scope `name`, IdP `alias`, …): re-importing converges the target realm to the document's state without duplicating. The response summarises, per slice, how many entries were `created`, `updated`, or `skipped`.

### Conflict modes

`onConflict` controls how an entry whose key already exists is treated:

| `onConflict` | Behaviour |
| --- | --- |
| `overwrite` *(default)* | Update existing resources in place. |
| `skip` | **Block** — leave existing resources untouched; only create new ones. |
| `fail` | Like `skip`, but each collision is listed in the response's `conflicts` array so you can reject the apply. |

### Secret resolution

A `${VAR}` placeholder is resolved from the server's environment. Set the variables listed in `requiredEnv` before importing:

```bash
export HELIX_GOV_CAPTCHA_SECRET=…              # value from your secrets manager
export HELIX_GOV_IDP_GOOGLE_CLIENTSECRET=…
```

If a referenced variable is missing the secret is **left unset** (the rest of the import still applies). Strict mode — failing when any required variable is missing — is available for the folder loader below.

## Config-as-code: the drop-in folder

Mount a directory of realm-config files and Helix applies them on startup — one file per realm, the **file name is the realm id**:

```text
deploy/realms/
  gov.json        # → realm "gov"
  partner.yaml    # → realm "partner"
```

The bundled `docker-compose.yml` already mounts `./deploy/realms` into helix-iam-server. Configure it with:

| Variable | Default | Meaning |
| --- | --- | --- |
| `HELIX_REALMS_LOCATION` | `/realms` | Folder scanned on startup |
| `HELIX_REALMS_ON_CONFLICT` | `skip` | `skip` (never clobber a live realm) / `overwrite` / `fail` |
| `HELIX_REALMS_REQUIRE_ENV` | `false` | `true` = fail a file whose required secret env var is missing |

The loader is **idempotent and non-fatal**: a restart re-applies cleanly (default `skip` makes it a no-op against an unchanged realm), and a malformed or partially-failing file is logged and skipped without stopping startup. This is the recommended way to ship a realm's configuration alongside your deployment — see `deploy/realms/example-realm.json.sample`.

### On Kubernetes (Helm)

The Helm chart renders your realm files into a ConfigMap and mounts it at `/realms` on helix-iam-server. Enable it in `values.yaml` — each key under `realms.files` becomes one file (the key is the realm id + extension), and the `${ENV_VAR}` secrets are supplied from Kubernetes Secret(s) listed in `realms.secretRefs` (loaded with `envFrom`):

```yaml
realms:
  enabled: true
  onConflict: skip          # skip | overwrite | fail
  requireEnv: false
  secretRefs: [ helix-realm-secrets ]   # Secret keys = the ${ENV_VAR} names the files reference
  files:
    gov.json: |
      {
        "formatVersion": 2,
        "realm": { "realmId": "gov", "displayName": "Government" },
        "webhooks": [ { "name": "audit", "url": "https://…", "secret": "${HELIX_GOV_AUDIT_SECRET}" } ],
        "requiredEnv": [ "HELIX_GOV_AUDIT_SECRET" ]
      }
    partner.yaml: |
      formatVersion: 2
      realm: { realmId: partner, displayName: Partner }
```

```bash
kubectl create secret generic helix-realm-secrets --from-literal=HELIX_GOV_AUDIT_SECRET=…
helm upgrade --install helix ./deploy/helm/helix-iam -f my-values.yaml
```

The same `HELIX_REALMS_LOCATION` / `HELIX_REALMS_ON_CONFLICT` / `HELIX_REALMS_REQUIRE_ENV` knobs apply; the chart sets them from the `realms.*` values.

!!! tip "Promote config like code"
    Keep the exported file in git, store the `requiredEnv` secrets in your secrets manager, and either `POST /import` from your pipeline or drop the file in `deploy/realms`. Because every path is idempotent, the same document converges any target realm to the same state.

## Migrate from another provider

Moving to Helix from an existing identity provider is a paste-and-go step. In the console's **Import / export** screen, choose the migration import and upload (or paste) a standard realm-export JSON from your current system — Helix translates the portable slices and upserts them into the target realm: **OIDC clients** (grant types derived from the source), **realm roles**, and **identity providers**. The exact request shape is in the live [API reference](api-reference.md).

!!! note "Users in a migration come across separately"
    Password hashes from another provider are not portable, so user **credentials** are not brought in by the *migration* import. Provision users via [SCIM](scim.md), [LDAP federation](../federation/ldap.md), or bulk user import — then decommission the old system. (A native Helix realm export/import *does* carry user **profiles and role/group assignments** — never passwords or MFA secrets.)

!!! note "Imported users have no password yet"
    Because exports never carry credentials, a user brought in by a realm import (or the drop-in folder) is created **without a password** and flagged with the `UPDATE_PASSWORD` required action. The account exists with all its roles and group memberships, but the person must **set a password** — via a reset link, the [account console](../manage/users.md), an admin, or a passwordless / federated login — **before their first sign-in**. This is standard config-as-code behaviour: profiles ship in the file, secrets are established per environment.

## See also

- [SCIM provisioning](scim.md)
- [LDAP federation](../federation/ldap.md)
- [Terraform provider](terraform.md)
- [Manage realms](../manage/realms.md)
