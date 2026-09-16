# Authenticating to the API

Every code example in these docs talks to a running Helix IAM server. This page sets up the two things every example needs: **where the server is** and **how to authenticate**. Read it once, then copy-paste your way through the rest of the docs.

## Set your base URL and realm

All examples use two shell variables so you can paste them unchanged. Set them once per terminal:

```bash
# Production install — adjust to your host and realm
export HELIX_URL=https://auth.example.com
export REALM=acme
```

!!! tip "Trying the eval stack?"
    If you started Helix with `./eval.sh up` (the [quickstart](quickstart.md)), use the local values instead — every example on the site works verbatim against them:
    ```bash
    export HELIX_URL=http://localhost:8083
    export REALM=master
    ```

## Two API surfaces, two ways to authenticate

Helix exposes two kinds of endpoint, and they authenticate differently:

| Surface | Path prefix | Auth | Used for |
| --- | --- | --- | --- |
| **Protocol** | `/realms/{realm}/…` | OAuth2 / OIDC **bearer tokens** | Login, token issuance, userinfo, logout — what your *apps* call |
| **Admin API** | `/admin/realms/{realm}/…` | Admin **session + CSRF** | Managing realms, clients, users, roles — what your *operators & scripts* call |

The rest of this page covers admin-API auth (the session flow). For protocol/token flows, see the [OIDC quickstart](../integration/oidc-quickstart.md).

## Admin API: log in and get a session

The admin API is protected by an authenticated **admin session** with **CSRF** protection — the same security the console uses. Three steps: fetch a CSRF token, log in, then call the API. A cookie jar (`-c/-b cookies.txt`) carries the session between calls.

```bash
# 1. Fetch the login page to obtain a CSRF token (stored in the cookie jar)
curl -s -c cookies.txt "$HELIX_URL/realms/$REALM/login" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

# 2. Log in — establishes the admin session
curl -s -b cookies.txt -c cookies.txt \
  -d "username=admin&password=admin&_csrf=$CSRF" \
  "$HELIX_URL/realms/$REALM/login" >/dev/null

# 3. Read is now authorized — list the realm's users
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/users"
```
```json
[
  {
    "realmId": "master",
    "userId": "c1a848b2-cf68-45d5-85d1-97101cb702a8",
    "username": "admin",
    "email": null,
    "enabled": true,
    "locked": false,
    "mfaEnabled": false,
    "roles": ["admin"],
    "attributes": {},
    "createdAt": 1783001276475
  }
]
```

!!! note "Default admin credentials"
    A fresh realm is seeded with an `admin` user. On the eval stack the password is `admin`; on a real install it comes from `HELIX_ADMIN_PASSWORD`. See [realm admin bootstrap](../manage/realms.md).

## Writes need the CSRF header

`GET` requests need only the session cookie. **State-changing requests** (`POST`, `PUT`, `DELETE`) must also carry the current CSRF token in the `X-XSRF-TOKEN` header.

There is one subtlety: **logging in rotates the CSRF token**, so read the *fresh* value from the cookie jar after any `GET` before you write:

```bash
# Refresh the CSRF token from the authenticated session, then create a user
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/users" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{"username":"alice","email":"alice@example.com","enabled":true}' \
  "$HELIX_URL/admin/realms/$REALM/users"
```
```json
{
  "realmId": "acme",
  "userId": "684db0eb-4afe-44f9-ad16-37a64f3496ea",
  "username": "alice",
  "email": "alice@example.com",
  "enabled": true,
  "locked": false,
  "mfaEnabled": false,
  "roles": [],
  "attributes": {},
  "createdAt": 1783339573376
}
```

!!! tip "Reusable helper"
    Drop this into your shell profile and call `helix GET /admin/realms/$REALM/users` or `helix POST /admin/realms/$REALM/users '{...}'`:
    ```bash
    helix() {
      local method=$1 path=$2 body=${3:-}
      curl -s -b cookies.txt -c cookies.txt "$HELIX_URL$path" >/dev/null
      local csrf; csrf=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)
      curl -s -b cookies.txt -X "$method" \
        -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $csrf" \
        ${body:+-d "$body"} "$HELIX_URL$path"
    }
    ```

## Status codes you'll see

| Code | Meaning |
| --- | --- |
| `200` / `201` / `204` | Success (read / created / deleted) |
| `400` | Validation error — the response body lists the offending fields |
| `401` | No valid admin session — log in again |
| `403` | Session is valid but lacks the [admin permission](../operations/admin-roles.md) for this route, or the CSRF token is missing/stale on a write |
| `404` | Unknown realm or resource |

## Machine-to-machine surfaces (bearer, not session)

Some APIs are designed for automation and use their **own bearer token** instead of an admin session — no cookie jar required:

- **SCIM 2.0** (`/scim/v2/…`) — provisioning from an IdP, authenticated by a per-realm SCIM token. See [SCIM](../integration/scim.md).
- **Dynamic Client Registration** (`/connect/register`) — self-service client onboarding, authenticated by an initial access token. See [API reference](../integration/api-reference.md).
- **Workload identity & agent delegation** (`/workload-identity/token`, `/agent/delegation/token`) — authenticated by a cryptographically-verified workload JWT. See [Workload identity](../integration/workload-identity.md).

## See also

- [OIDC quickstart](../integration/oidc-quickstart.md) — get a user token for the protocol endpoints
- [API reference](../integration/api-reference.md) — the full OpenAPI spec
- [Admin roles (RBAC)](../operations/admin-roles.md) — which admin permission each route needs
