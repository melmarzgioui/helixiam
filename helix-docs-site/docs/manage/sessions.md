# Sessions

The Sessions screen is the unified view of **active identities** in a realm — the people, AI agents and service accounts that currently hold a live session or token — with per-row detail and revocation.

## What it is

Helix IAM uses a **single, unified SSO session model**. When a user authenticates, one SSO session is created and every application they sign into rolls up under it — one login, many client sessions, one place to see and revoke them. The Sessions screen presents that as one row per active identity.

### Only active tokens are shown

The list shows **only live sessions and tokens**. An authorization whose token has expired is dropped, and a session whose tokens have all expired disappears entirely. A token counts as active while it is still valid — using the refresh-token lifetime where one exists (so a session that is still *refreshable* remains listed, as in Keycloak/WSO2), otherwise the access-token lifetime. The same application is shown once per session (its most recent authorization), and "Signed in" reflects the most recent authentication.

### Identity types

Each row is tagged with the kind of identity behind it:

| Type | What it is | How it's identified |
| --- | --- | --- |
| **User** | A person's browser SSO session | Interactive login, resolved to the user's **username** |
| **Agent** | An AI / non-human identity (NHI) | The session's client is bound to an agent registration |
| **Service account** | A machine token (`client_credentials`) | Non-interactive grant; shown with the client's name |
| **Workload** | A federated workload (WIF) | Token carries the workload-identity claims (rarely a session) |

The **User** column resolves the subject to a readable **username** rather than the raw subject id. On an admin, RBAC-gated screen this is expected behaviour (it is how you identify and manage sessions); it is not a privacy concern — end-user "your sessions" views only ever show a user their own.

### Session policies

Per-realm policies control session lifetime (see [Realm settings](../operations/realm-settings.md)):

- **Idle timeout** — end the session after inactivity.
- **Max lifetime** — hard cap regardless of activity.
- **Remember me** — optionally extend sessions across browser restarts.

### Logout & propagation

Revoking a session propagates to the applications that were part of it:

- **OIDC back-channel logout** — server-to-server logout notifications.
- **OIDC front-channel logout** — browser-driven logout via hidden iframes.
- **SAML Single Logout (SLO)** — logout across SAML relying parties.
- **Federated SLO** — propagate logout upstream to a brokered identity provider.

Revoking a **user/agent session** performs a cascading Single Logout; revoking a **service-account** row revokes that token. Revoking your **own** session signs you out of the console.

## In the console

Sessions live under **Manage → Sessions**. The screen is one filterable table — **Type · Identity · App(s) · Signed in · Expires**:

- **Search** by identity or app, and **filter by type** (User / Agent / Service account / Workload). Both filter server-side.
- Your own session is badged **"You · current session"**.
- **Click any row** to open a side **drawer** with full detail: type, identity (username + subject id), realm, sign-in/expiry times, every app with its grant type and scopes, and the session id — plus the revoke action.

To work the screen:

1. Open **Manage → Sessions** to see every active identity — people, agents, and service accounts currently signed in.
2. **Search** by name or app, or narrow to a single identity type.
3. **Click a row** to open the detail drawer and inspect the session's apps, scopes, and id.
4. **Revoke** to end a user/agent session (Single Logout) or revoke a service-account token.
5. Set **session policies** (idle timeout, max lifetime, remember-me) in [Realm settings](../operations/realm-settings.md).

The console signs in through its own standard OIDC client, so an admin's console login appears here like any other session — see [Admin console client](admin-console-client.md).

## Storage

The Sessions view is **store-agnostic**: identity resolution and filtering run above the token store, so the screen behaves identically whether the realm's token store is the default Postgres-backed store (authorizations in the database) or the Redis store (`HELIX_TOKEN_STORE=redis`, the high-throughput tier). No configuration is needed to switch — the same rows, types and filters apply.

!!! tip
    Use cascade revoke during incident response: revoking a user's session signs them out of every connected application in one action.

## Over the API

Active identities are listed under `/admin/realms/{realm}/sessions`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List active identities

Filter with free-text `q` and/or `type` (`user` / `agent` / `service_account` / `workload`); both filter server-side. Each row's `clients` array is the applications rolled up under that SSO session, and `revokeMode` (`SLO` for a user/agent session, token revoke for a service account) is how a `DELETE` on the row behaves.

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/sessions?type=user"
```
```json
[
  {
    "id": "399a1cf6-486b-4f1b-99c8-15bfc3f67474",
    "identityType": "USER",
    "principalName": "alice",
    "displayName": "alice",
    "realm": "acme",
    "issuedAt": null,
    "expiresAt": null,
    "revokeMode": "SLO",
    "clients": [
      {
        "clientId": "helix-console",
        "grantType": "authorization_code",
        "scopes": ["openid", "profile"],
        "issuedAt": null,
        "expiresAt": null
      }
    ]
  }
]
```

### Revoke a session

Use the row's `id`. For a user/agent session this performs a cascading Single Logout across every connected application; for a service-account row it revokes that token.

```bash
# Refresh CSRF after any GET, then revoke (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/sessions" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

# Delete — returns 204 No Content
curl -s -b cookies.txt -X DELETE -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/sessions/399a1cf6-486b-4f1b-99c8-15bfc3f67474"
```

!!! warning
    Revoking your **own** session (the row badged "You · current session") signs you out of the console.

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /sessions?q=&type=` | List active identities, filtered by free-text `q` and/or `type` (`user`/`agent`/`service_account`/`workload`) |
| `DELETE /sessions/{id}` | Revoke a session — Single Logout for a user/agent session, token revoke for a service account |

See the [API reference](../integration/api-reference.md) for the complete schema of every field.

## See also

- [Admin console client](admin-console-client.md)
- [Users](users.md)
- [OIDC clients](oidc-clients.md)
- [SAML clients](saml-clients.md)
- [Events & audit](events.md)
- [Realms](realms.md)
