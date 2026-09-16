# helix-iam-server

The HelixIAM identity server: a single Spring Boot application serving OAuth2/OIDC endpoints
(authorize, token, userinfo, JWKS, discovery, logout), a SAML 2.0 IdP, and the realm-scoped admin
REST API. It owns its PostgreSQL schema directly — no message broker, no separate persistence
tier. See the [root README](../README.md) for the full project overview and
[`../helix-docs-site`](../helix-docs-site/) for product documentation.

## Prerequisites

- Java 21 (see `<java.version>` in `pom.xml`)
- Maven (no wrapper is committed — use a locally installed `mvn`)
- PostgreSQL (for running the app; the test suite spins up its own via Testcontainers)
- Redis (for running the app with the default `redis` session store; tests run with
  `spring.session.store-type=none` and don't need Redis)
- Docker (required by the test suite's Testcontainers-backed PostgreSQL, and for local
  Postgres/Redis containers when running the app)

## Build & test

```bash
mvn -o clean test        # unit + integration tests (Testcontainers spins up Postgres itself)
mvn -o clean verify       # same, plus any additional verification bound to the verify phase
mvn -o clean package -DskipTests   # build the runnable jar without running tests
```

`-o` (offline) matches how this module is built in this environment; drop it if you need Maven to
resolve dependencies online.

## Run locally

```bash
# Postgres + Redis
docker run -d --name hlx-pg -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=kubeiam -p 5432:5432 postgres:16-alpine
docker run -d --name hlx-redis -p 6379:6379 redis:7-alpine

mvn -o clean package -DskipTests

java -jar target/helix-iam-server-1.0.0-SNAPSHOT.jar \
  --spring.profiles.active=dev \
  --server.port=8080 \
  --DB_HOST=localhost --DB_PORT=5432 --DB_NAME=kubeiam --DB_USERNAME=postgres --DB_PASSWORD=password \
  --REDIS_HOST=localhost --REDIS_PORT=6379
```

Then:

```bash
curl http://localhost:8080/realms/master/.well-known/openid-configuration
curl http://localhost:8080/actuator/health
```

The `dev` profile (`application-dev.properties`) overlays local-friendly defaults (Postgres on
`localhost`, MFA off) on top of the base `application.properties`. On first boot the app runs
`schema.sql` (idempotent, `spring.sql.init.mode=always` by default; set `HELIX_MIGRATIONS_ENABLED=true`
to use Flyway instead — see `src/main/resources/db/migration`) and seeds the `master` realm: an
an `admin` user (username via `HELIX_ADMIN_USERNAME`, default `admin`; password via
`HELIX_ADMIN_PASSWORD` — **if unset, a strong random password is generated and printed to the logs
once on first boot**), default `user` / `auditor` roles, and a self-generated RSA signing keypair.

## Key configuration

The full reference lives in the [root README](../README.md#configuration) and
[`../helix-docs-site`](../helix-docs-site/); the source of truth is
[`src/main/resources/application.properties`](src/main/resources/application.properties). At a
glance:

- **Datasource**: `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USERNAME` / `DB_PASSWORD`, optional
  `DB_RO_HOST` read replica, `DB_ENCRYPTION` (secrets-at-rest key — keep stable after first boot).
- **Redis**: `REDIS_HOST` / `REDIS_PORT` for the HTTP session store.
- **Base URLs**: `SP_BASE_URL`, `IDP_BASE_URL`.
- **SAML IdP**: `HELIX_SAML_IDP_ENABLED`, `HELIX_SAML_IDP_ENTITY_ID`,
  `HELIX_SAML_IDP_SIGNING_CERTIFICATE` / `HELIX_SAML_IDP_SIGNING_PRIVATE_KEY` (optional; falls
  back to a key derived from the realm's OIDC signing key).
- **Notifications**: `helix.notification.provider` (`smtp`/`log`) and
  `helix.notification.smtp.*` as the global SMTP fallback; per-realm providers are configured via
  the admin API/console.
- **Admin bootstrap**: `HELIX_ADMIN_USERNAME` / `HELIX_ADMIN_PASSWORD`.

See `src/main/java/group/mfnr/authorization/service/realm/RealmAdminBootstrapService.java` for the
admin-bootstrap behavior and `ADAPTERS.md` / `VENDOR-MAP.md` in this directory for internal
architecture notes (the in-process adapter layer from the former publisher/subscriber merge).
