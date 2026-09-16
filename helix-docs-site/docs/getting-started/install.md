# Install

Helix IAM ships as two images — **helix-iam-server** (OAuth2/OIDC/SAML + admin API, owns PostgreSQL) and
**console** — plus PostgreSQL and Redis.

## Docker Compose

```bash
cp .env.example .env
#  set DB_ENCRYPTION (openssl rand -hex 16) and HELIX_ADMIN_PASSWORD; review the URLs for production
./deploy/bootstrap/gen-keys.sh        # one-time signing keypair
docker compose up -d
```

- Console: `http://localhost:${CONSOLE_PORT:-8080}`
- OIDC discovery: `http://localhost:${IDP_PORT:-8083}/realms/master/.well-known/openid-configuration`

The published images are pulled by default; build from source with `make images` (runs the Maven build
then `docker build` for both).

## Kubernetes (Helm)

```bash
cd deploy/helm/helix-iam
helm dependency build                 # fetch the PostgreSQL + Redis subcharts
helm install helix . \
  --set secrets.dbEncryption=$(openssl rand -hex 16) \
  --set secrets.adminPassword=CHANGE_ME \
  --set ingress.enabled=true \
  --set ingress.consoleHost=helix.example.com \
  --set ingress.issuerHost=idp.helix.example.com
```

Use a managed PostgreSQL / Redis instead of the bundled subcharts:

```bash
helm install helix . \
  --set postgresql.enabled=false --set database.host=pg.internal --set database.password=... \
  --set redis.enabled=false      --set redis.host=redis.internal \
  --set secrets.dbEncryption=...,secrets.adminPassword=...
```

!!! warning "Signing keys in production"
    By default the chart generates the master-realm signing keypair into an `emptyDir`, which is
    regenerated if the server pod reschedules. For key continuity, mount a persistent volume or a
    pre-created Secret at `/jks` on helix-iam-server.

## After install

- Change the admin password and confirm the OIDC discovery document loads.
- Set `IDP_BASE_URL` / `SP_BASE_URL` to your real **https** hostnames (WebAuthn requires https).
- Walk the [Security hardening](../operations/security.md) checklist before going live.

See also the full [Configuration](configuration.md) reference.
