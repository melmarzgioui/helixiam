# Users

Users are the accounts in a realm — their credentials, attributes, roles, and lifecycle are managed here.

## What it is

A user belongs to exactly one realm. Users sign in with **username or email**, and credentials are protected with **Argon2id** password hashing. Helix IAM enforces a configurable **password policy**, keeps **password history** to prevent reuse, and runs a **HIBP breach check** to reject known-compromised passwords.

Other capabilities:

- **Required actions** — a framework for pending steps a user must complete at next login (e.g. update password, verify email, configure OTP).
- **Per-user roles** — direct [role](roles.md) assignments in addition to roles inherited from [groups](groups.md).
- **Credentials management** — list, reset, and remove a user's credentials.
- **Admin impersonation** — start a session as the user for support and debugging.
- **Bulk import** — load many users at once.
- **GDPR** — export or delete a user's personal data on request.

!!! note
    Login accepts either username or email. Email is supported as a user attribute; make sure your subject-claim choice (see [Scopes & claims](scopes-and-claims.md)) reflects how downstream apps identify users.

## In the console

Users live under **Manage → Users & access → Users**. Users are always shown by their username, never by a raw subject id.

1. Open **Manage → Users & access → Users**, then click **Create**.
2. Set the **username** and **email**, add any attributes, and save.
3. From the user's **Credentials** tab, set a password (subject to policy, history, and the HIBP check) or send a reset.
4. Under **Required actions**, add a step the user must complete at next login (e.g. configure OTP).
5. From the **Roles** tab, assign realm or client [roles](roles.md) directly — or add the user to a [group](groups.md) that already holds them.
6. Use **Import** to load a batch of users at once, **Impersonate** to reproduce an issue as the user, and **GDPR** to export or erase their data.

!!! warning
    Admin impersonation creates a real session as the user and is a sensitive operation. Impersonation and credential resets are recorded in the [audit log](events.md) — restrict who can perform them.

!!! danger
    GDPR delete is irreversible and removes the user's personal data. Export first if you may need a record.

## Over the API

All user management is available under `/admin/realms/{realm}/users`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List users

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/users"
```
```json
[
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
]
```

### Create a user

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
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

### Set a password, assign a role, delete

Use the returned `userId` for subsequent calls:

```bash
# Set (or reset) the password — enforced against policy, history, and HIBP
curl -s -b cookies.txt -X PUT \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{"newPassword":"S3cure-passphrase!"}' \
  "$HELIX_URL/admin/realms/$REALM/users/684db0eb-4afe-44f9-ad16-37a64f3496ea/password"

# Assign a realm role
curl -s -b cookies.txt -X POST \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{"name":"billing-admin"}' \
  "$HELIX_URL/admin/realms/$REALM/users/684db0eb-4afe-44f9-ad16-37a64f3496ea/roles"

# Delete the user — returns 204 No Content
curl -s -b cookies.txt -X DELETE -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/users/684db0eb-4afe-44f9-ad16-37a64f3496ea"
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /users` · `POST /users` | List / create users |
| `GET` · `PUT` · `DELETE /users/{userId}` | Read / update / delete a user |
| `POST /users/import` | Bulk import |
| `GET` · `POST /users/{userId}/credentials` | List / manage credentials |
| `PUT /users/{userId}/password` | Set password |
| `GET` · `POST /users/{userId}/roles` | User role mappings |
| `GET` · `POST /users/{userId}/required-actions` | Required actions |
| `POST /users/{userId}/impersonate` | Start impersonation |
| `GET` · `DELETE /users/{userId}/gdpr` | GDPR export / delete |

See the [API reference](../integration/api-reference.md) for the complete schema of every field.

## See also

- [Roles](roles.md)
- [Groups](groups.md)
- [Organizations](organizations.md)
- [Sessions](sessions.md)
- [Events & audit](events.md)
