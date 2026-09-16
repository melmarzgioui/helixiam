# OIDC clients

An OIDC client is the OAuth2 / OpenID Connect face of an [application](applications.md) — it defines how a relying party obtains tokens from the realm's issuer.

## What it is

OIDC clients speak OAuth2 and OpenID Connect against the realm issuer (`https://<host>/realms/<realm>`). Each client is either:

- **Confidential** — holds a client secret and authenticates at the token endpoint (server-side apps, backends).
- **Public** — has no secret and must use **PKCE** (SPAs, mobile, native apps).

### Grant types

Clients can be enabled for any of:

- `authorization_code` (with PKCE) — interactive login
- `refresh_token` — long-lived sessions
- `client_credentials` — service-to-service (uses a service account)
- `password` — resource owner password (legacy; avoid for new apps)
- `device` — device authorization grant for input-constrained devices
- `CIBA` — Client-Initiated Backchannel Authentication
- `token-exchange` (RFC 8693) — exchange a token for another, including **on-behalf-of delegation** where an [agent](../integration/agents.md) acts *for* a user (see [Agent authorization](../integration/agent-authorization.md))

### Key settings

- **Redirect URIs** — exact-match callback URLs for the code flow.
- **Web origins** — allowed CORS origins; these are enforced at runtime, not cosmetic.
- **Scopes** — the [client scopes](scopes-and-claims.md) this client may request.
- **Per-client keys / JWKS** — client-specific signing keys or a registered JWKS for `private_key_jwt`.
- **Service accounts** — the identity used for `client_credentials`; can hold its own roles.
- **Authorization Services (UMA)** — fine-grained resource/policy/permission model for resource-server authorization.
- **Advanced token settings** — token lifetimes, subject-claim override, audience handling, and **resource indicators** (RFC 8707) to narrow a token's audience to a specific resource server.
- **Agent binding** — an OIDC client can be the issuance binding for an [agent (non-human identity)](../integration/agents.md); the agent authenticates through this client (e.g. `client_credentials` or a workload JWT) and its tokens gain the `nhi` marker and lifecycle gate.

!!! warning
    Public clients must use PKCE. Never embed a client secret in a browser app, SPA, or mobile binary — register it as a public client instead.

## In the console

OIDC clients live under **Manage**, either via the parent [application](applications.md) or the clients list. Clients are always shown by their application/client display name, never by a raw UUID.

## Common tasks

1. **Register a client** — open **Applications → Create** (or **Clients → Create**), pick confidential or public, and add redirect URIs and web origins.
2. **Enable grant types** — turn on only the flows the client actually uses.
3. **Assign scopes** — attach the [client scopes](scopes-and-claims.md) that define which claims appear in tokens.
4. **Configure a service account** — for `client_credentials`, enable the service account and assign it [roles](roles.md).
5. **Enable Authorization Services** — define resources, policies, and permissions for UMA-style authorization.
6. **Rotate the secret / keys** — regenerate the client secret or rotate per-client keys when needed.

!!! tip
    **Dynamic Client Registration** is supported at `/connect/register` for programmatic, on-the-fly client creation per [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591).

## Manage over the API

All client management is available under `/admin/realms/{realm}/clients`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List clients

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/clients"
```
```json
[
  { "clientId": "helix-console", "name": "Helix Console", "publicClient": true,  "grantTypes": ["authorization_code","refresh_token"] },
  { "clientId": "kubedna-cli",   "name": "KubeDNA CLI",   "publicClient": true,  "grantTypes": ["authorization_code","device"] }
]
```

### Create a confidential client

`publicClient: false` mints a client **secret**, returned once in the create response.

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "clientId": "acme-web",
        "name": "Acme Web",
        "publicClient": false,
        "grantTypes": ["authorization_code", "refresh_token"],
        "redirectUris": ["https://app.example.com/callback"],
        "webOrigins": ["https://app.example.com"]
      }' \
  "$HELIX_URL/admin/realms/$REALM/clients"
```
```json
{
  "id": "19d467c0-fe42-46e2-a708-eb2c450cb17a",
  "clientId": "acme-web",
  "name": "Acme Web",
  "publicClient": false,
  "secret": "CyISWxzvGCkhqUld5Pm-GCVtcYvCtSu3",
  "grantTypes": ["authorization_code", "refresh_token"],
  "redirectUris": ["https://app.example.com/callback"],
  "webOrigins": ["https://app.example.com"],
  "scopes": []
}
```

!!! warning "Save the secret now"
    The `secret` is shown only in the create (and secret-rotation) response. Store it in your secret manager immediately. A public client (`"publicClient": true`) has no secret and must use **PKCE**.

### Update or delete a client

Use the returned `id` for subsequent calls:

```bash
# Update (e.g. add a redirect URI) — PUT the full desired state
curl -s -b cookies.txt -X PUT \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{ "clientId": "acme-web", "redirectUris": ["https://app.example.com/callback", "https://app.example.com/silent-renew"] }' \
  "$HELIX_URL/admin/realms/$REALM/clients/19d467c0-fe42-46e2-a708-eb2c450cb17a"

# Delete — returns 204 No Content
curl -s -b cookies.txt -X DELETE -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/clients/19d467c0-fe42-46e2-a708-eb2c450cb17a"
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /clients` · `POST /clients` | List / create clients |
| `GET` · `PUT` · `DELETE /clients/{id}` | Read / update / delete a client |
| `GET` · `POST /clients/{id}/authz/resources` | UMA resources |
| `GET` · `POST /clients/{id}/authz/policies` | UMA policies |
| `GET` · `POST /clients/{id}/authz/permissions` | UMA permissions |
| `POST /connect/register` | [Dynamic Client Registration](../integration/api-reference.md#dynamic-client-registration) |

See the [API reference](../integration/api-reference.md) for the complete schema of every field.

## See also

- [Applications](applications.md)
- [Scopes & claims](scopes-and-claims.md)
- [SAML clients](saml-clients.md)
- [Agents (AI / non-human identity)](../integration/agents.md)
- [Sessions](sessions.md)
- [API reference](../integration/api-reference.md)
