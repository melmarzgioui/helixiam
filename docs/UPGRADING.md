# Upgrading HelixIAM

## From 1.0.x to the Spring Boot 4 release

This release moves the server from Spring Boot 3.5 (Spring Security 6.5, Spring Authorization Server 1.5) to Spring
Boot 4.1 (Spring Security 7.1). It reads everything 1.0 stored: signed-in sessions, authorization codes, refresh
tokens, device codes and consents in progress, in PostgreSQL and in Redis alike. **The reverse does not hold.** 1.0
cannot read what the new version writes, so the two versions must not serve traffic at the same time, and a rollback
signs users out.

### What 1.0 cannot read

| Written by the new version | Read by a 1.0 pod (queue / PostgreSQL store) | Read by a 1.0 pod (Redis store) |
|---|---|---|
| A browser session (any sign-in; it carries Spring Security 7's sign-in factor, a class 1.0 does not have) | dropped with a `HTTP session dropped` WARN: the user is signed out | **HTTP 500** on every request carrying that session cookie, until the session expires or is deleted |
| An OAuth2 authorization the new version created **or rewrote**: a new sign-in or authorization code, a code exchange, a refresh (rotation), a revocation, a consent, a device-flow step | treated as absent: refresh fails (`invalid_grant`), introspection answers `active: false`, the user signs in again | **HTTP 500** for that token (refresh, introspection, revocation, logout), until the entry expires or is deleted |

(The new version itself never answers 500 for a Redis entry it cannot read: it treats it as absent and drops such a
session, as the PostgreSQL stores do.)

Access tokens are JWTs and stay valid for their lifetime on either version: their signature does not depend on the
store. Store locations: PostgreSQL tables `helix_authorization`, `helix_authorization_token` (tokens) and
`helix_http_session` (sessions with `HELIX_SESSION_STORE=queue`); Redis keys `spring:session:*` (sessions, the default
store) and `helix:authz:*` (tokens with `HELIX_TOKEN_STORE=redis`).

### Before upgrading: roles named `FACTOR_…`

The release reserves the `FACTOR_` prefix (any case) for Spring Security 7's sign-in factors (`FACTOR_PASSWORD` marks
every password login). From the upgrade on, a role with such a name is ignored: it grants nothing in admin RBAC and never
appears in a token. List them first; an empty result means there is nothing to do:

```bash
psql "$DATABASE_URL" -f deploy/scripts/factor-roles-check.sql
```

It covers realm roles, client roles, service-account roles and agent roles. Rename any it lists (create the new role,
move its users, grants and mappings, delete the old one) before upgrading.

### Upgrade procedure

1. **Back up** PostgreSQL, the token store included (for example `pg_dump` of the whole database; the tables above
   are part of it). With Redis, also take a snapshot (`redis-cli BGSAVE`, then copy `dump.rdb`).
2. **Do not mix versions: no old pod may run while a new one serves.** A rolling update, or scaling down to one replica,
   still runs old and new side by side. Pick one:
   - **Helm, Recreate** (every old pod stops before a new one starts; the server is unavailable for one start-up,
     typically under a minute):

     ```bash
     helm upgrade helixiam deploy/helm/helixiam --reuse-values --server-side=false \
       --set image.tag=<new version> --set strategy.type=Recreate
     ```

     `--server-side=false` is needed once, with Helm 4, because the 1.0 chart never rendered `spec.strategy`: under
     Helm 4's default server-side apply the `rollingUpdate` block Kubernetes defaulted would survive and the API
     server would reject the Deployment (`spec.strategy.rollingUpdate: Forbidden`). With Helm 3 leave the flag out
     (it always applies client-side). From this release on the chart renders the strategy in full, so later strategy
     changes need no flag.
   - **Or scale to zero first**, then upgrade (the upgrade restores `replicaCount`):

     ```bash
     kubectl -n <namespace> scale deploy/helixiam --replicas=0
     kubectl -n <namespace> wait --for=delete pod -l app.kubernetes.io/name=helixiam --timeout=180s
     helm upgrade helixiam deploy/helm/helixiam --reuse-values --set image.tag=<new version>
     ```
   - Docker Compose / plain containers: stop every old container, then start the new ones.
3. **Check** readiness (`/actuator/health/readiness`), one sign-in, and one refresh of a token issued before the
   upgrade.
4. Later releases can go back to rolling updates: `--set strategy.type=RollingUpdate`.

Operators who set Spring properties directly (instead of the `HELIX_*` settings and Helm values) must rename them; see
the BREAKING checklist in `CHANGES-1.0.md`.

### Rolling back to 1.0

Rolling back is possible, but it signs users out and drops every authorization the new version wrote or rewrote (see
the table). The 1.0 chart has no `strategy` value, so `helm rollback` alone would roll back with a rolling update and
mix the versions. Instead:

1. **Scale to zero** and wait until every pod of the new version is gone:

   ```bash
   kubectl -n <namespace> scale deploy/helixiam --replicas=0
   kubectl -n <namespace> wait --for=delete pod -l app.kubernetes.io/name=helixiam --timeout=180s
   ```
2. **Delete what 1.0 cannot read from Redis** (PostgreSQL stores: nothing to delete, 1.0 drops what it cannot read):
   the sessions (`spring:session:*`, the default session store), and with `HELIX_TOKEN_STORE=redis` the tokens
   (`helix:authz:*`; every client then needs a new sign-in or `client_credentials` token). Otherwise every request
   carrying such a cookie or token gets HTTP 500 from 1.0 until it expires. `deploy/scripts/redis-delete-keys.sh`
   does it with SCAN and UNLINK and covers the usual connection settings:

   ```bash
   # REDIS_HOST, REDIS_PORT; REDIS_PASSWORD (requirepass) or REDIS_USER + REDIS_PASSWORD (ACL);
   # REDIS_TLS=1 + REDIS_CACERT (+ REDIS_CERT, REDIS_KEY for a client certificate); REDIS_CLUSTER=1 for a cluster.
   REDIS_HOST=redis.example.internal REDIS_PASSWORD=... deploy/scripts/redis-delete-keys.sh 'spring:session:*'
   REDIS_HOST=redis.example.internal REDIS_PASSWORD=... deploy/scripts/redis-delete-keys.sh 'helix:authz:*'

   # or inside the Redis pod (no local redis-cli needed):
   kubectl -n <namespace> exec -i deploy/redis -- sh -s 'spring:session:*' < deploy/scripts/redis-delete-keys.sh
   ```
3. **Roll back**: `helm rollback helixiam <revision before the upgrade>` (`helm history helixiam` lists it). This
   restores the 1.0 image and its `replicaCount`.
4. **Check** that the pods are back (`kubectl -n <namespace> get deploy helixiam`); if the replica count stayed at 0,
   scale back up (`kubectl -n <namespace> scale deploy/helixiam --replicas=<n>`).

Restoring the step 1 backup instead undoes every other change made since the upgrade (users, clients, realm settings,
audit log), so use it only when nothing else changed.

### How this procedure is tested

`e2e/monthfold/k3d-helm-upgrade.sh` installs v1.0.0-rc.8 on k3d with the default strategy (Helm 4), signs in and issues
tokens there, upgrades as above (Recreate; it checks that no old and new pod ever ran at the same time, that the data
and the earlier tokens survive), switches the strategy both ways, then rolls back as above and checks 1.0 serves again.
`e2e/redis-delete-keys-check.sh` runs the Redis script against a password, an ACL user, TLS and a cluster.
`FactorRolesCheckQueryE2eTest` runs the `FACTOR_` query against the real schema.
