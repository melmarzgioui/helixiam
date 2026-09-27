<p align="center">
  <img src=".github/helix-avatar-500.png" alt="HelixIAM" width="120" height="120">
</p>

<h1 align="center">HelixIAM</h1>

<p align="center">
  <b>The open-source identity server for AI agents, workloads, and people.</b><br>
  Self-hostable OAuth2 · OIDC · SAML 2.0 — a Keycloak alternative built for the agent era.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/OAuth2%20·%20OIDC%20·%20SAML%202.0-standards--based-2f6b52.svg" alt="Standards: OAuth2, OIDC, SAML 2.0">
  <img src="https://img.shields.io/badge/self--hosted-Docker%20·%20Helm%20·%20K8s-informational.svg" alt="Self-hosted">
  <a href="https://docs.helixiam.com"><img src="https://img.shields.io/badge/docs-helixiam.com-2f6b52.svg" alt="Docs"></a>
</p>

**HelixIAM** is a self-hostable, open-source identity and access management (IAM) server that
treats **AI agents and machine workloads as first-class identities** — not an afterthought bolted
onto a human IdP. It's a full OAuth2 / OIDC provider and SAML 2.0 IdP (multi-tenant **realms**,
MFA, passkeys, SSO, federation) and it adds on-behalf-of delegation for AI agents (RFC 8693),
keyless workload identity federation (K8s/CI JWT exchange), and EU eID connectors — on one Spring
Boot deployable backed by PostgreSQL and Redis. No message broker, no third-party control plane,
no telemetry.

### Why HelixIAM?

- 🤖 **Built for AI agents & workloads** — give each agent a real, scoped, revocable identity; mint
  on-behalf-of tokens (RFC 8693) whose authority only ever narrows; kill-switch a runaway agent.
  Keyless workload identity federation for Kubernetes and CI.
- 🔐 **A complete standards IdP** — OpenID Connect, OAuth 2.1, SAML 2.0, WebAuthn/passkeys, FAPI,
  DPoP, PAR. Any standard client works; no proprietary lock-in.
- 🇪🇺 **Sovereign & European** — self-host on your own infrastructure, per-realm signing keys, EU
  data residency, and DigiD / eHerkenning / eIDAS connectors.
- 📦 **Trustworthy supply chain** — cosign-signed release images with an attested SBOM; CodeQL +
  dependency scanning in CI.
- 🔁 **A [Keycloak alternative](https://helixiam.com/keycloak-alternative/)** with a realm importer
  to migrate in — modern, and agent-native.

The admin console (**helix-dashboard**) is a **separate deployable by design**, so the identity
server and the console scale independently.

## Components

| Component | What it is |
|---|---|
| [`helix-iam-server`](helix-iam-server/) | The identity server: OAuth2/OIDC/SAML2 IdP + admin REST API, single Spring Boot jar, owns PostgreSQL. |
| [`helix-dashboard`](helix-dashboard/) | The admin console — React app + design system, deployed as its own image, talks to `helix-iam-server`'s admin API. |
| [`helix-sandbox-rp`](helix-sandbox-rp/) | A transparent OIDC/SAML relying-party test harness — login, OTP/MFA, refresh, silent SSO, SLO, with every token shown decoded. |
| [`helix-mcp-demo`](helix-mcp-demo/) | Demo of MCP (Model Context Protocol) resource-server auth against HelixIAM. |
| [`terraform-provider-helix`](terraform-provider-helix/) | Terraform provider to manage applications and realm roles as code via the admin API. |

## Quickstart

The fastest way to run the whole stack — server, admin console, PostgreSQL, Redis and a mail
catcher — is Docker. No Java or Maven required:

```bash
docker compose up
```

Then open:

- **Admin console** — <http://localhost:8090> (demo login `admin` / `admin`)
- **Server / IdP** — <http://localhost:8080> (e.g. `/realms/master/.well-known/openid-configuration`)
- **Mailpit** (outbound email) — <http://localhost:8025>

The compose stack is **demo configuration only** — weak passwords, a throwaway encryption key and
cookies over plain HTTP. Do not reuse those values anywhere real.

### Build and run from source (for development)

Requires Java 21, Maven and Docker.

```bash
# 1. PostgreSQL + Redis
docker run -d --name hlx-pg -e POSTGRES_USER=helix -e POSTGRES_PASSWORD=helix \
  -e POSTGRES_DB=helixiam -p 5432:5432 postgres:16-alpine
docker run -d --name hlx-redis -p 6379:6379 redis:7-alpine

# 2. Build (online — a fresh clone must download dependencies; do NOT use `mvn -o`)
cd helix-iam-server
mvn -B clean package -DskipTests

# 3. Run (the dev profile fills in localhost defaults and a demo encryption key)
java -jar target/helix-iam-server-1.0.0-SNAPSHOT.jar \
  --spring.profiles.active=dev \
  --DB_HOST=localhost --DB_PORT=5432 --DB_NAME=helixiam --DB_USERNAME=helix --DB_PASSWORD=helix \
  --REDIS_HOST=localhost --REDIS_PORT=6379 \
  --HELIX_ADMIN_PASSWORD=admin   # omit to get a random one-time password (see below)

# 4. Confirm it's up
curl http://localhost:8080/realms/master/.well-known/openid-configuration
curl http://localhost:8080/actuator/health
```

On first boot the server seeds the `master` realm, default `user` / `auditor` roles, and a
self-generated RSA signing keypair (no external key mount required to start). The bootstrap admin
**username** defaults to `admin`. The **password** is `HELIX_ADMIN_PASSWORD` when set (the
docker-compose stack and the command above set it to `admin` for convenience); **when it is left
unset, a strong random password is generated once and written (0600) to
`HELIX_ADMIN_PASSWORD_FILE`, default `$TMPDIR/helixiam-admin-password`; only the path is logged** — sign in, change it,
and set `HELIX_ADMIN_PASSWORD` for any non-local use (see [Bootstrap admin](#configuration)).

To run only the console separately, see [`helix-dashboard`](helix-dashboard/).

## Configuration

Everything is environment-driven. The essentials (sourced from
[`application.properties`](helix-iam-server/src/main/resources/application.properties)):

**Database**

| Variable | Purpose |
|---|---|
| `DB_HOST` / `DB_PORT` / `DB_NAME` | PostgreSQL location (default DB name `helixiam`) |
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

**Notifications (email)**

| Property | Purpose |
|---|---|
| `helix.notification.provider` | `smtp` (default) or `log` (dev, no mail server) |
| `helix.notification.email.driver` | the global email default: `smtp` (default), `cloudflare` or `log` |
| `helix.notification.email.from-address` / `.from-name` | default sender identity (else `helix.notification.smtp.from-address` / `.from-name`) |
| `helix.notification.smtp.host` / `.port` / `.username` / `.password` / `.password-file` | global SMTP; the port defaults to 587, or 465 with implicit TLS |
| `helix.notification.smtp.tls-mode` | `STARTTLS_REQUIRED` (default), `STARTTLS_OPTIONAL`, `IMPLICIT` (SMTPS) or `NONE` (dev profile only); the boolean `.starttls` is deprecated (`true` = `STARTTLS_REQUIRED`, `false` = `STARTTLS_OPTIONAL`) |
| `helix.notification.smtp.connect-timeout` / `.read-timeout` / `.ehlo-name` / `.ca-bundle-file` | SMTP timeouts, EHLO name, and extra trusted CA certificates (PEM) for a private relay |
| `helix.notification.cloudflare.account-id` / `.api-token` / `.api-token-file` | Cloudflare Email Service (HTTPS); the token needs Account → Email Sending → Edit, and the sender's domain must be onboarded |
| `helix.notification.cloudflare.base-url` / `.connect-timeout` / `.read-timeout` / `.ca-bundle-file` | optional; the base URL must be `https` outside the dev profile |

Secrets given as files (`password-file`, `api-token-file`) are read at every send, so a rotated secret needs no
restart. Per-realm email/SMS/push providers (email: `SMTP`, `CLOUDFLARE`, `HTTP`, `LOG`; SMS: Twilio/HTTP; push:
FCM/APNs) are configured from the admin console/API (`PUT /admin/realms/{realm}/messaging/providers`) and take
priority over the global default above.

**Bootstrap admin**

| Variable | Purpose |
|---|---|
| `HELIX_ADMIN_USERNAME` / `HELIX_ADMIN_PASSWORD` | the master-realm admin user created on first boot. Username defaults to `admin`. **If `HELIX_ADMIN_PASSWORD` is unset, a strong random password is generated once and written (0600) to `HELIX_ADMIN_PASSWORD_FILE` (default `$TMPDIR/helixiam-admin-password`); the password itself is never logged** — set it explicitly for any non-local use. |
| `HELIX_BOOTSTRAP_CLIENT_ID` | optional bootstrap **service account** for provisioning: on first boot a confidential `client_credentials` client with this id is created in the master realm, holding the master `admin` role (administers every realm through the admin API with a bearer token). Create-only — an existing client is never changed; rotate with `POST /admin/realms/master/clients/{id}/secret`. |
| `HELIX_BOOTSTRAP_CLIENT_SECRET_FILE` / `HELIX_BOOTSTRAP_CLIENT_SECRET` | its secret (32–120 printable ASCII characters), preferably from a file (e.g. a mounted Kubernetes secret; the file wins when both are set). Without an acceptable secret no client is created and an error is logged (never the value). |

**Provisioning and MFA.** `MFA_ENABLED` (`mfa.enabled`, default `true`) is a deployment-wide switch: `true` sends
*every* password sign-in in *every* realm through TOTP; `false` leaves it to each realm's `requireMfa` (and to users
who enrolled). Neither applies to `client_credentials` tokens. So automation should not sign in as the bootstrap admin
user (which forced operators to set `MFA_ENABLED=false` globally): use the bootstrap service account above, keep
`MFA_ENABLED=true` or set per-realm `requireMfa`, and grant other service accounts narrower roles
(`view-users`, `manage-users`, …) through `POST /admin/realms/{r}/clients/{clientId}/service-account/roles`.

**Feature toggles**

| Variable | Default | Purpose |
|---|---|---|
| `USER_REGISTRATION_ENABLED` | `true` | platform-wide self-registration switch |
| `MAINTENANCE` | `false` | maintenance mode |
| `HELIX_SESSION_STORE` | `redis` (`queue` in the `dev` profile) | HTTP session store: `redis`, or `queue` to keep sessions in PostgreSQL (no Redis needed). With `redis`, startup fails with a clear message if Redis is unreachable (`HELIX_REDIS_STARTUP_CHECK=false` to skip the check) |
| `HELIX_TOKEN_STORE` | *(unset)* | unset = built-in Postgres-backed token store; `redis` for the high-throughput tier |
| `HELIX_FLOW_ENGINE_ENABLED` | `false` | data-driven authentication-flow engine |
| `HELIX_SAML_IDP_ENABLED` | `true` | enable the SAML 2.0 IdP role |
| `HELIX_SQL_INIT_MODE` | `never` | legacy idempotent `schema.sql` init; set `always` together with `HELIX_MIGRATIONS_ENABLED=false` |
| `HELIX_MIGRATIONS_ENABLED` | `true` | Flyway (`db/migration/V*`) manages the schema (default everywhere: app, image, Helm) |
| `HELIX_EGRESS_ALLOWED_PRIVATE_HOSTS` | *(empty)* | private hosts outbound calls (email/SMS HTTP drivers, webhooks, SCIM, federation) may reach, e.g. `mailer.mail.svc.cluster.local,sms-gateway.internal:8080`: exact host names or IP literals, optionally with a port. Matched by the configured name, never by the address it resolves to; link-local/cloud-metadata, multicast and wildcard addresses stay blocked. Global, not per realm, because realm admins configure the outbound URLs. |
| `HELIX_EGRESS_ALLOW_PRIVATE` | `false` | **deprecated**: lets *every* outbound URL reach private and loopback addresses (still honoured; logged as insecure). Use `HELIX_EGRESS_ALLOWED_PRIVATE_HOSTS`. |

### Theming

Realms and organizations are themed through a structured, validated theme (colours for light and dark, fonts,
shape, logo and other assets, layout, localised texts, legal links) set with `PUT /admin/realms/{r}/theme` or mounted
as file themes from `HELIX_THEME_DIRECTORY`. It applies to every user-facing page and email. Custom CSS remains only
as a restricted escape hatch. See [`docs/THEMING.md`](docs/THEMING.md) for the model, the admin API, the `--hx-*`
CSS variables contract, file themes, the CSP and migration from 1.0.

| Variable | Default | Purpose |
|---|---|---|
| `HELIX_THEME_ALLOWED_IMAGE_ORIGINS` | *(empty)* | https origins that custom-CSS `url()` may load images from, for every realm (comma-separated) |
| `HELIX_THEME_DIRECTORY` | *(empty)* | directory of file themes; empty turns file themes off |
| `HELIX_THEME_RELOAD_INTERVAL_SECONDS` | `30` | how often the theme directory is checked for changes; `0` = startup only |

### Rate limits

Sensitive POST endpoints are rate limited **per client IP address** (the first `X-Forwarded-For` address
when present) and endpoint group, in memory on each replica (token bucket):

| Endpoints | Burst | Refill | Properties |
|---|---|---|---|
| sign-in: `/login`, OTP/flow submit, password reset, registration | 20 | 20 / minute | `helix.ratelimit.login.burst`, `helix.ratelimit.login.refill-per-minute` |
| `/oauth2/token` (all grants) | 120 | 120 / minute | `helix.ratelimit.token.burst`, `helix.ratelimit.token.refill-per-minute` |

Excess requests get `429 Too Many Requests`. **In-cluster callers usually share one egress or pod IP**, so
several backend services using `client_credentials` or token exchange from the same node count against one
bucket: raise `helix.ratelimit.token.*` for such deployments (or put HelixIAM behind a proxy that forwards
the real client address in `X-Forwarded-For`), and size it for your peak token traffic. `helix.ratelimit.enabled=false` turns
the limiter off (only behind another rate-limiting layer). The limit is not per OAuth client in 1.0.

### Memory

Measured at `-Xmx512m`: about 590 MB RSS idle and 650 MB under light load. The container image sizes the heap
at 75 % of the container limit (`-XX:MaxRAMPercentage=75`), so give the container **at least 1 GiB**; the Helm
chart defaults to a 768 MiB request and a 1536 MiB limit.

See the [documentation site](https://docs.helixiam.com) for the full documentation (architecture,
install, configuration reference, API guides), and
[`helix-iam-server/README.md`](helix-iam-server/README.md) for module-level build/test/run
instructions.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
