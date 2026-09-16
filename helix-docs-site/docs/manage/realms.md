# Realms

A realm is an isolated **identity domain** in Helix IAM — a self-contained tenant with its own users, applications, roles, signing keys, authentication flows, federation, and branding. A realm is **protocol-agnostic**: the same realm can act as an OpenID Connect / OAuth 2.1 provider **and** a SAML 2.0 Identity Provider, broker external IdPs (social, enterprise, eIDs), and issue tokens to non-human identities (AI agents and workloads) — all over one shared user base and policy set.

## What it is

Every realm is a self-contained security domain. Nothing leaks between realms — users, keys, sessions, and configuration are all partitioned by realm. Tenants, environments (dev/staging/prod), or business units are typically modelled as separate realms.

The bootstrap realm is named `master`. It exists from first start and is used to administer the server and to create additional realms.

### Protocols a realm speaks

A single realm exposes multiple protocol surfaces at once — you don't pick one at realm creation:

| Role | Endpoint (per realm) | Docs |
| --- | --- | --- |
| **OIDC / OAuth 2.1 provider** | `https://<host>/realms/<realm>` — discovery at `/.well-known/openid-configuration` | [OIDC clients](oidc-clients.md) |
| **SAML 2.0 Identity Provider** | `https://<host>/realms/<realm>/saml/idp/metadata` | [SAML relying parties](saml-clients.md) |
| **Federation broker** (inbound) | brokers upstream OIDC/SAML/LDAP/eID logins into this realm | [Federation & eIDs](../federation/index.md) |
| **Workload identity federation** | keyless token exchange for Kubernetes/CI JWTs | [Workload identity](../integration/workload-identity.md) |
| **Agent / NHI delegation** | RFC 8693 on-behalf-of token exchange | [Agents](../integration/agents.md) |

An [Application](applications.md) is the protocol-agnostic parent that can own an OIDC client and a SAML relying party together, sharing one subject-claim mapping and login flow across both.

!!! note
    Because the issuer URL contains the realm name, the realm name is effectively part of every OIDC token's `iss` claim and the SAML IdP entity ID. Choose stable, URL-safe realm names.

### What a realm isolates

Everything below is scoped to one realm and never spans realms:

- **Identities** — human users & credentials ([Users](users.md)), AI **agents / non-human identities** ([Agents](../integration/agents.md)), and workload identities ([Workload identity](../integration/workload-identity.md)).
- **Applications** — the protocol-agnostic parent, plus its OIDC clients ([OIDC clients](oidc-clients.md)) and SAML relying parties ([SAML relying parties](saml-clients.md)).
- **Authorization model** — realm & client roles ([Roles](roles.md)), hierarchical groups ([Groups](groups.md)), client scopes & claim mappers ([Client scopes & claims](scopes-and-claims.md)), and fine-grained admin RBAC ([Admin roles](../operations/admin-roles.md)).
- **Organizations (B2B)** — member companies with their own domains and identity providers ([Organizations](organizations.md)).
- **Federation** — brokered identity providers and eID connectors (DigiD, eHerkenning, eIDAS) ([Federation & eIDs](../federation/index.md)).
- **Authentication** — per-realm login flows, MFA, passkeys, device push, and risk-based policy ([Authentication](../authentication/index.md)).
- **Signing keys / JWKS** — each realm has its own rotating key set ([Realm keys](../operations/realm-keys.md)).
- **Sessions & SSO** — unified SSO sessions with per-realm idle/max/remember-me policy ([Sessions](sessions.md)).
- **Branding & login theming** — per-realm login appearance ([Login theming](../operations/theming.md)).
- **Integrations** — outbound webhooks ([Webhooks](../integration/webhooks.md)), SCIM provisioning ([SCIM](../integration/scim.md)), and notification providers ([Notifications](../operations/notifications.md)).
- **Audit & privacy** — a searchable audit log ([Events & audit](events.md)) and GDPR/privacy configuration ([GDPR](../operations/gdpr.md)).

## In the console

Realms are selected and switched from the realm switcher at the top of the admin console. Realm-wide configuration (realm settings, keys, theming, notifications) lives under **Manage → Realms**; the day-to-day objects inside a realm (applications, users, agents, roles, sessions) live under the other **Manage** groups.

## Common tasks

1. **Create a realm** — from the realm switcher, open **Create realm**, give it a unique name, and save. The realm starts with a default authentication flow, a generated signing key set, and an admin role and user. Both the OIDC and SAML IdP surfaces are available immediately.
2. **Switch realms** — use the realm switcher; every **Manage** screen then operates on the selected realm.
3. **Register an application** — add an [Application](applications.md) and attach an OIDC client, a SAML relying party, or both; they share the app's subject claim and login flow.
4. **Configure tokens & sessions** — in **Manage → Realms → Realm settings**, adjust access/refresh token lifetimes and the session idle/max/remember-me policies (see [Realm settings](../operations/realm-settings.md)).
5. **Brand the login page** — in **Manage → Realms → Login theming**, set the realm's login appearance (logo, colors, copy).
6. **Manage signing keys** — rotate or inspect the realm's keys in **Manage → Realms → Realm keys**.
7. **Export / import a realm** — capture the realm's full configuration — across *every* domain above — as a portable document and apply it to another environment, with secrets carried as `${ENV}` placeholders ([Import / export & migration](../integration/import-export.md)).

!!! warning
    Deleting a realm permanently removes all of its users, agents, applications, clients, relying parties, roles, groups, sessions, and keys. This cannot be undone.

!!! danger
    Treat the `master` realm as privileged infrastructure. Compromise of `master` is compromise of the whole server. Restrict who holds admin roles there and prefer per-tenant realms for application users.

## Over the API

Realm-wide configuration is read and written through the realm's **settings** resource; the whole realm can be exported and imported as one document. All admin endpoints are scoped under `/admin/realms/{realm}` and use session + CSRF auth — see [Authenticating to the API](../getting-started/api-authentication.md).

!!! note
    Creating and deleting realms is a console operation (the realm switcher → **Create realm** / **Delete realm**). There is no realm create/delete REST endpoint; the admin API operates *within* an existing realm.

### Read realm settings

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/settings"
```
```json
{
  "realmId": "master",
  "displayName": "Master",
  "accessTokenTtlSeconds": 3600,
  "refreshTokenTtlSeconds": 5184000,
  "requireMfa": false,
  "passwordMinLength": 12,
  "enabled": true,
  "ssoSessionIdleTimeoutSeconds": 1800,
  "ssoSessionMaxLifetimeSeconds": 36000,
  "lockoutEnabled": false,
  "maxLoginFailures": 5
}
```

Update the same resource with `PUT` (tokens, sessions, password policy, lockout, risk, branding). Refresh the CSRF token after the read, then write — see the [auth guide](../getting-started/api-authentication.md) for the `helix()` helper.

### Export the whole realm

The export is a single portable document spanning every domain (clients, SAML clients, roles, scopes, identity providers, flows, organizations, applications, webhooks, SCIM targets, workload identities, messaging, admin roles, groups, users, agents), with secrets replaced by `${ENV}` placeholders listed under `requiredEnv`.

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/export" -o realm-export.json
```

### Realm admin endpoints

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /settings` · `PUT /settings` | Read / update realm-wide configuration |
| `GET /export` | Export the realm's full configuration |
| `POST /import` | Import a configuration document into the realm |

Every object *inside* a realm has its own `/admin/realms/{realm}/…` sub-resource (applications, oidc clients, saml-clients, users, agents, roles, groups, identity-providers, webhooks, scim-targets, …). See the full [API reference](../integration/api-reference.md) and [Import / export & migration](../integration/import-export.md).

## See also

- [Applications](applications.md) — the protocol-agnostic app parent (OIDC + SAML)
- [Agents (AI / non-human identity)](../integration/agents.md)
- [Federation & eIDs](../federation/index.md)
- [Import / export & migration](../integration/import-export.md)
- [Realm settings](../operations/realm-settings.md)
- [Authentication flows](../authentication/flows.md)
