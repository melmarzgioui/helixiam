# Architecture

Helix IAM runs as a **single standalone service** plus a console, backed by PostgreSQL, Redis and SMTP.

```
                    ┌──────────────── Ingress / Load balancer (TLS) ──────────────┐
                    │                                                             │
            ┌───────▼────────┐                                          ┌─────────▼───────┐
            │ helix-iam-server│  OAuth2 / OIDC / SAML2 + admin REST API │  console × M    │
            │      × N        │  + identity domain (users, clients,     │  nginx SPA      │
            │                 │    roles, keys, sessions, audit)        │                 │
            └───────┬────────┘                                          └─────────────────┘
        ┌───────────┼───────────────┐
   ┌────▼────┐  ┌────▼────┐    ┌──────▼──────┐
   │Postgres │  │  Redis  │    │    SMTP      │
   │ HA/PITR │  │ session │    │ notifications│
   └─────────┘  └─────────┘    └──────────────┘
```

## One service

**helix-iam-server** is the whole backend: it serves the OAuth2/OIDC endpoints (authorize, token,
userinfo, JWKS, discovery, logout), the SAML 2.0 IdP, and the realm-scoped admin REST API, and it owns
the PostgreSQL database directly — no separate persistence tier, no cross-service calls. What used to be
a publisher/subscriber split behind a message broker is now in-process method calls inside one
deployable.

- **PostgreSQL** holds all durable state — users, clients, roles, keys, sessions, audit — optionally via
  a read replica (`DB_RO_HOST`).
- **Redis** backs the HTTP session tier (and, optionally, the token store — see
  [Configuration](configuration.md)).
- **SMTP** (or another configured provider) delivers email notifications — OTP codes, password resets,
  magic links.

**Console** is an nginx image serving the admin and account single-page apps and reverse-proxying the
admin/account API to helix-iam-server (same-origin, so no CORS).

## Why one service

- **Simplicity** — one deployable, one database, no message broker to run, size, or fail over. Fewer
  moving parts to operate and to reason about in production.
- **One source of truth** — the server is the only writer to PostgreSQL, which keeps the schema and
  invariants in one place.
- **Horizontal scale** — run multiple `helix-iam-server` replicas behind the load balancer; session and
  token state lives in PostgreSQL (and, optionally, Redis) rather than in any one instance, so draining a
  pod doesn't sign anyone out.
- **Multi-tenant** — realms partition all data; each realm is its own OIDC issuer **and** SAML 2.0 IdP
  with its own keys.

## Request flow (human login)

1. An app redirects the browser to `…/realms/<realm>/oauth2/authorize` (OIDC) or POSTs a SAML `AuthnRequest`.
2. The server runs the realm's [authentication flow](../authentication/flows.md) (password, MFA, …),
   reading/writing session state in Postgres/Redis.
3. On success it issues an authorization code (OIDC) or SAML assertion; the app exchanges the code at the
   token endpoint for ID, access and refresh tokens signed by the realm's [keys](../operations/realm-keys.md).

## Request flow (machine, workload & agent token exchange)

Not every caller is a browser. The server also mints tokens for non-interactive callers with **no
session and no stored secret**:

1. A caller presents a credential — a client's `client_credentials`, a Kubernetes/CI **workload JWT**
   ([Workload identity](../integration/workload-identity.md)), or, for **on-behalf-of delegation**, a
   user `subject_token` + an [agent](../integration/agents.md) `actor_token`
   ([Agent authorization](../integration/agent-authorization.md)).
2. The server verifies it against the configured external issuer's JWKS (workload) or the realm's own
   signing key (delegation), and enforces the agent's lifecycle gate (a suspended agent is denied here).
3. It mints a short-lived realm-signed access token — carrying `nhi: true` for non-human callers, and an
   `act` claim naming the acting agent for delegated tokens. Endpoints include `…/oauth2/token`,
   `…/workload-identity/token`, and `…/agent/delegation/token`.

See [Observability](../operations/observability.md) for the metrics the server exposes and
[Backup & DR](../operations/backup.md) for what to back up (just the database).
