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

### Upgrade procedure

1. **Back up** PostgreSQL, the token store included (for example `pg_dump` of the whole database; the tables above
   are part of it). With Redis, also take a snapshot (`redis-cli BGSAVE`, then copy `dump.rdb`).
2. **Do not mix versions.** Pick one:
   - Helm: upgrade with `--set strategy.type=Recreate` (every old pod stops before a new one starts; the server is
     unavailable for one start-up, typically under a minute):

     ```bash
     helm upgrade helixiam deploy/helm/helixiam --reuse-values \
       --set image.tag=<new version> --set strategy.type=Recreate
     ```
   - or scale to one replica first (`--set replicaCount=1`), upgrade, wait for readiness, then scale back up.
   - Docker Compose / plain containers: stop every old container, then start the new ones.
3. **Check** readiness (`/actuator/health/readiness`), one sign-in, and one refresh of a token issued before the
   upgrade.
4. Later releases can go back to the default rolling update (`--set strategy=null` or remove the value).

Operators who set Spring properties directly (instead of the `HELIX_*` settings and Helm values) must rename them; see
the BREAKING checklist in `CHANGES-1.0.md`.

### Rolling back to 1.0

Rolling back is possible, but it signs users out and drops every authorization the new version wrote or rewrote (see
the table). Roll back the same way you upgraded (Recreate, or one replica), then:

- **Redis session store (the default):** before the 1.0 pods take traffic, delete the sessions the new version wrote,
  or every user with such a cookie gets HTTP 500 until it expires:

  ```bash
  redis-cli --scan --pattern 'spring:session:*' | xargs -r -n 500 redis-cli del
  ```
- **Redis token store (`HELIX_TOKEN_STORE=redis`):** likewise delete `helix:authz:*`; every client then needs a new
  sign-in or `client_credentials` token.
- **PostgreSQL stores:** nothing to delete; 1.0 drops what it cannot read.
- Restoring the step 1 backup instead undoes every other change made since the upgrade (users, clients, realm
  settings, audit log), so use it only when nothing else changed.
