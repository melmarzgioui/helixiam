<p align="center">
  <img src=".github/helix-avatar-500.png" alt="HelixIAM" width="120" height="120">
</p>

<h1 align="center">HelixIAM</h1>

<p align="center">
  Standalone OAuth2 · OIDC · SAML 2.0 identity server — one deployable, no message broker.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache-2.0"></a>
</p>

**HelixIAM** is a standalone OAuth2 / OIDC / SAML 2.0 identity provider — one Spring Boot
deployable, backed by PostgreSQL, Redis and SMTP. There is no message broker and no separate
persistence tier: `helix-iam-server` serves the OAuth2/OIDC endpoints (authorize, token,
userinfo, JWKS, discovery, logout), the SAML 2.0 IdP, and the realm-scoped admin REST API, and it
owns PostgreSQL directly. It supports multi-tenant **realms** (each its own OIDC issuer and SAML
IdP with its own signing keys), workload identity federation (keyless K8s/CI JWT exchange), and
AI-agent / non-human-identity token delegation (RFC 8693 on-behalf-of).

The admin console (**helix-dashboard**) is a **separate deployable by design**, so the identity
server and the console scale independently.

## Components

| Component | What it is |
|---|---|
| [`helix-iam-server`](helix-iam-server/) | The identity server: OAuth2/OIDC/SAML2 IdP + admin REST API, single Spring Boot jar, owns PostgreSQL. |
| [`helix-dashboard`](helix-dashboard/) | The admin console — React app + design system, deployed as its own image, talks to `helix-iam-server`'s admin API. |
| [`helix-docs-site`](helix-docs-site/) | Product documentation site (MkDocs Material). |
| [`helixiam-website`](helixiam-website/) | Public marketing site (helixiam.com). |
| [`helix-sandbox-rp`](helix-sandbox-rp/) | A transparent OIDC/SAML relying-party test harness — login, OTP/MFA, refresh, silent SSO, SLO, with every token shown decoded. |
| [`helix-mcp-demo`](helix-mcp-demo/) | Demo of MCP (Model Context Protocol) resource-server auth against HelixIAM. |
| [`terraform-provider-helix`](terraform-provider-helix/) | Terraform provider to manage realms, applications and roles via the admin API. |

## Quickstart

This is the proven local recipe (PostgreSQL + Redis in Docker, build and run the server jar
directly). Requires Java 21, Maven, and Docker.

```bash
# 1. PostgreSQL + Redis
docker run -d --name hlx-pg -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=kubeiam -p 5432:5432 postgres:16-alpine
docker run -d --name hlx-redis -p 6379:6379 redis:7-alpine

# 2. Build
cd helix-iam-server
mvn -o clean package -DskipTests

# 3. Run (dev profile picks up localhost Postgres/Redis defaults)
java -jar target/helix-iam-server-1.0.0-SNAPSHOT.jar \
  --spring.profiles.active=dev \
  --server.port=8080 \
  --DB_HOST=localhost --DB_PORT=5432 --DB_NAME=kubeiam --DB_USERNAME=postgres --DB_PASSWORD=password \
  --REDIS_HOST=localhost --REDIS_PORT=6379

# 4. Confirm it's up
curl http://localhost:8080/realms/master/.well-known/openid-configuration
curl http://localhost:8080/actuator/health
```

On first boot the server seeds the `master` realm with an `admin` / `admin` user (see
[Bootstrap admin](#configuration) below — change this immediately outside of local dev), default
`user` / `auditor` roles, and a self-generated RSA signing keypair (no external key mount
required to start).

To also run the console, see [`helix-dashboard`](helix-dashboard/) — it is built and deployed
separately and talks to the server's admin API.

## Configuration

Everything is environment-driven. The essentials (sourced from
[`application.properties`](helix-iam-server/src/main/resources/application.properties)):

**Database**

| Variable | Purpose |
|---|---|
| `DB_HOST` / `DB_PORT` / `DB_NAME` | PostgreSQL location (default DB name `kubeiam`) |
| `DB_USERNAME` / `DB_PASSWORD` | PostgreSQL credentials |
| `DB_RO_HOST` | optional read-replica host (defaults to `DB_HOST`) |
| `DB_ENCRYPTION` | hex key encrypting secrets at rest (TOTP seeds, signing keys, IdP secrets); keep stable for the life of the install |

**Session store (Redis)**

| Variable | Purpose |
|---|---|
| `REDIS_HOST` / `REDIS_PORT` | Redis location for the HTTP session store (`spring.data.redis.host`/`.port`, default `localhost:6379`); the underlying Spring properties can also be set directly as `SPRING_DATA_REDIS_HOST` / `SPRING_DATA_REDIS_PORT` |

**External URLs**

| Variable | Purpose |
|---|---|
| `SP_BASE_URL` | the SP/console origin (used for CORS + redirects) |
| `IDP_BASE_URL` | this IdP's own external base URL (issuer, broker callbacks) |
| `HELIX_SAML_IDP_ENTITY_ID` | SAML 2.0 IdP entity id |
| `HELIX_SAML_IDP_SIGNING_CERTIFICATE` / `HELIX_SAML_IDP_SIGNING_PRIVATE_KEY` | optional externally-supplied SAML signing material (PEM, `\n` read as newline); when unset the IdP derives its SAML credential from the realm's own OIDC signing key |

**Notifications (SMTP)**

| Property | Purpose |
|---|---|
| `helix.notification.provider` | `smtp` (default) or `log` (dev, no mail server) |
| `helix.notification.smtp.host` / `.port` / `.username` / `.password` / `.starttls` | global SMTP fallback used when no realm-level provider is configured |
| `helix.notification.smtp.from-address` / `.from-name` | default sender identity |

Per-realm email/SMS/push providers (SMTP/HTTP, Twilio/HTTP, FCM/APNs) can also be configured from
the admin console/API and take priority over the global SMTP fallback above.

**Bootstrap admin**

| Variable | Purpose |
|---|---|
| `HELIX_ADMIN_USERNAME` / `HELIX_ADMIN_PASSWORD` | the master-realm admin user created on first boot. Username defaults to `admin`. **If `HELIX_ADMIN_PASSWORD` is unset, a strong random password is generated and printed to the logs once** — set it explicitly for any non-local use. |

**Feature toggles**

| Variable | Default | Purpose |
|---|---|---|
| `USER_REGISTRATION_ENABLED` | `true` | platform-wide self-registration switch |
| `MAINTENANCE` | `false` | maintenance mode |
| `HELIX_SESSION_STORE` | `redis` | HTTP session store |
| `HELIX_TOKEN_STORE` | *(unset)* | unset = built-in Postgres-backed token store; `redis` for the high-throughput tier |
| `HELIX_FLOW_ENGINE_ENABLED` | `false` | data-driven authentication-flow engine |
| `HELIX_SAML_IDP_ENABLED` | `true` | enable the SAML 2.0 IdP role |
| `HELIX_SQL_INIT_MODE` | `always` | idempotent `schema.sql` init (mutually exclusive with Flyway) |
| `HELIX_MIGRATIONS_ENABLED` | `false` | manage the schema with Flyway (`db/migration/V*`) instead |

See [`helix-docs-site`](helix-docs-site/) for the full documentation (architecture, install,
configuration reference, API guides), and
[`helix-iam-server/README.md`](helix-iam-server/README.md) for module-level build/test/run
instructions.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
