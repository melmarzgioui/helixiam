# Quickstart

Pick a path. The **trial** is one command with throwaway secrets for a first look; **production** runs
the exact same three services — helix-iam-server, console, PostgreSQL (plus Redis for sessions) — with
*your* secrets and persistent storage, on Docker Compose or Kubernetes.

=== "Trial (ephemeral)"

    Zero config, throwaway secrets, nothing left behind — ideal for a first look.

    ```bash
    ./eval.sh up
    # open http://localhost:8080  →  log in as  admin / admin
    ```

    That command generates a signing keypair, then starts PostgreSQL, Redis, helix-iam-server and the
    console with safe-but-throwaway defaults.

    - **Console:** <http://localhost:8080> — sign in as `admin` / `admin`.
    - **OIDC discovery:** `http://localhost:8083/realms/master/.well-known/openid-configuration`

    Tear it down (discards all state, database included):

    ```bash
    ./eval.sh down
    ```

    !!! warning "Trial only"
        The trial uses baked-in secrets and a disposable database. Never use `deploy/eval.env` secrets
        in production — for anything beyond a look, use one of the production paths.

=== "Production · Docker Compose"

    A persistent, self-contained stack driven by your own `.env` — the same `docker-compose.yml` the
    trial layers on, minus the throwaway overlay.

    ```bash
    cp .env.example .env
    #  set DB_ENCRYPTION   (openssl rand -hex 16)
    #  set HELIX_ADMIN_PASSWORD
    #  set SP_BASE_URL / IDP_BASE_URL to your real https:// hostnames
    ./deploy/bootstrap/gen-keys.sh          # one-time signing keypair
    docker compose up -d
    ```

    - **Console:** `http://localhost:${CONSOLE_PORT:-8080}`
    - **OIDC discovery:** `http://localhost:${IDP_PORT:-8083}/realms/master/.well-known/openid-configuration`

    The database lives in a named volume (`helix-pgdata`), so it survives restarts. Published images are
    pulled by default; build from source with `make images`. Full reference: **[Install](install.md)** and
    **[Configuration](configuration.md)**.

=== "Production · Kubernetes (Helm)"

    ```bash
    cd deploy/helm/helix-iam
    helm dependency build                   # fetch the PostgreSQL + Redis subcharts
    helm install helix . \
      --set secrets.dbEncryption=$(openssl rand -hex 16) \
      --set secrets.adminPassword=CHANGE_ME \
      --set ingress.enabled=true \
      --set ingress.consoleHost=helix.example.com \
      --set ingress.issuerHost=idp.helix.example.com
    ```

    Point at a managed database / Redis instead of the bundled subcharts:

    ```bash
    helm install helix . \
      --set postgresql.enabled=false --set database.host=pg.internal --set database.password=... \
      --set redis.enabled=false      --set redis.host=redis.internal \
      --set secrets.dbEncryption=...,secrets.adminPassword=...
    ```

    !!! warning "Signing keys in production"
        By default the chart generates the master-realm signing keypair into an `emptyDir`, regenerated
        if the server pod reschedules. For key continuity, mount a persistent volume or a
        pre-created Secret at `/jks` on helix-iam-server.

!!! info "Production checklist"
    Before going live: change the admin password, set `IDP_BASE_URL` / `SP_BASE_URL` to your real
    **https** hostnames (WebAuthn requires https), and walk the
    [Security hardening](../operations/security.md) guide.

## Next steps

1. Change the admin password from the console after first login.
2. [Register your first application](../manage/applications.md) and wire an app to it with the
   [OIDC quickstart](../integration/oidc-quickstart.md) — or add a [SAML relying party](../manage/saml-clients.md).
3. Give a bot or AI assistant a first-class identity with [Agents](../integration/agents.md), or let a
   Kubernetes/CI workload authenticate keylessly with [Workload identity](../integration/workload-identity.md).
4. Read [Core concepts](concepts.md) to understand realms, applications, agents and flows.
