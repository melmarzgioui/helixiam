# Configuration

Everything is environment-driven, so the same images run on a laptop or in production. The essentials:

## Database

| Variable | Purpose |
|----------|---------|
| `DB_HOST` / `DB_PORT` / `DB_NAME` | PostgreSQL location |
| `DB_USERNAME` / `DB_PASSWORD` | credentials |
| `DB_RO_HOST` | optional read-replica host (defaults to `DB_HOST`) |
| `DB_ENCRYPTION` | **required** — 32-char hex key encrypting secrets at rest (TOTP seeds, signing keys, IdP secrets). **Immutable after first boot.** |

## Session store (Redis)

Helix IAM keeps HTTP sessions in Redis by default.

| Variable | Purpose |
|----------|---------|
| `REDIS_HOST` / `REDIS_PORT` | Redis location for the HTTP session store |

## Notifications (SMTP, SMS, push)

Message delivery isn't an environment variable — it's **per-realm configuration** you set from the
console or admin API (SMTP/HTTP for email, Twilio/HTTP for SMS, FCM/APNs for push), so each realm/tenant
can send from its own accounts. See [Notifications](../operations/notifications.md).

## External URLs

| Variable | Purpose |
|----------|---------|
| `IDP_BASE_URL` | the IdP's own external base URL (issuer / federation callbacks) |
| `SP_BASE_URL` | the primary app/console origin (CORS) |
| `HELIX_SAML_IDP_ENTITY_ID` | SAML IdP entity id |

!!! info "Use https in production"
    WebAuthn passkeys require a secure origin. Set the base URLs to real `https://` hostnames.

## Bootstrap admin

| Variable | Purpose |
|----------|---------|
| `HELIX_ADMIN_USERNAME` / `HELIX_ADMIN_PASSWORD` | the master-realm admin created on first boot |

## Feature toggles

| Variable | Default | Purpose |
|----------|---------|---------|
| `USER_REGISTRATION_ENABLED` | `true` | platform-wide master switch for self-registration; each realm also has its own **Allow self-registration** toggle, and both must be on for that realm's `/register` to accept sign-ups — see [Realm settings — Registration](../operations/realm-settings.md#registration) |
| `MFA_ENABLED` | `false` | force MFA enrollment |
| `HELIX_SESSION_STORE` | `redis` | HTTP session store — `redis` is the shipped default |
| `HELIX_TOKEN_STORE` | *(unset)* | leave unset for the built-in Postgres-backed token store, or set `redis` for the high-throughput Redis tier |
| `HELIX_FLOW_ENGINE_ENABLED` | `false` | drive post-password steps with the flow engine |
| `HELIX_MIGRATIONS_ENABLED` | `false` | manage the schema with Flyway (see [Upgrades](../operations/upgrades.md)) |
| `HELIX_AUDIT_ENABLED` | `true` | emit the audit log |

!!! danger "Never change DB_ENCRYPTION after first boot"
    Existing encrypted rows become unreadable. Back the key up and keep it stable for the life of the
    install.

The full list, with defaults, is in `.env.example`.
