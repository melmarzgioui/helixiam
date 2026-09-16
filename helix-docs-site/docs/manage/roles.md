# Roles

Roles are named permissions you assign to users and groups to drive authorization decisions in your applications.

## What it is

Helix IAM supports two kinds of roles:

- **Realm roles** — defined at the realm level and meaningful across the whole realm.
- **Client roles** — defined on a specific [OIDC client](oidc-clients.md) and scoped to that application.

Roles can be assigned directly to [users](users.md) or to [groups](groups.md). Users gain a role either by direct assignment or by being a member of a group that holds it (see [Groups](groups.md)). Effective roles surface in issued tokens according to the client's [scopes & claims](scopes-and-claims.md) configuration.

!!! tip
    Use realm roles for broad, cross-application capabilities (e.g. `admin`, `support`) and client roles for application-specific permissions (e.g. an app's `editor` or `viewer`). Assign roles to groups rather than individuals to keep access manageable.

## In the console

Realm roles live under **Manage → Users & access → Roles**; client roles are managed from their owning [OIDC client](oidc-clients.md). Each realm is bootstrapped with system `admin`, `user`, and `auditor` roles.

1. Open **Manage → Users & access → Roles**, then click **Create** and name the realm role.
2. For a client role, open the [OIDC client](oidc-clients.md) instead and add a role scoped to that application.
3. Assign a role to a [user](users.md) from the user's **Roles** tab, or to a [group](groups.md) so every member inherits it.
4. Click a role to review its user and group assignments before you change or remove it.

!!! warning
    Removing a role that applications check for authorization can immediately revoke access for every user and group that held it. Review assignments before deleting a role. **System roles cannot be deleted.**

## Over the API

Realm roles live under `/admin/realms/{realm}/roles`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List roles

Each realm ships with three system roles (`system: true`); `defaultRole` marks the role auto-granted to new users.

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/roles"
```
```json
[
  { "realmId": "acme", "roleId": "8d3a79d3-40e4-4497-8543-234685e689a8", "name": "admin",   "system": true,  "defaultRole": false },
  { "realmId": "acme", "roleId": "9ec2e116-e56b-458d-b11d-1efbfd1c492a", "name": "user",    "system": true,  "defaultRole": true  },
  { "realmId": "acme", "roleId": "6c898aa8-98dc-4597-87be-9352dd5f21da", "name": "auditor", "system": true,  "defaultRole": false }
]
```

### Create a realm role

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/roles" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{"name":"billing-admin","description":"Manage billing"}' \
  "$HELIX_URL/admin/realms/$REALM/roles"
```
```json
{
  "realmId": "acme",
  "roleId": "14a78f34-...",
  "name": "billing-admin",
  "system": false,
  "defaultRole": false
}
```

### Delete a role

Use the returned `roleId`:

```bash
# Delete — returns 204 No Content (system roles cannot be deleted)
curl -s -b cookies.txt -X DELETE -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/roles/14a78f34-..."
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /roles` · `POST /roles` | List / create realm roles |
| `GET` · `PUT` · `DELETE /roles/{roleId}` | Read / update / delete a realm role |
| `GET` · `POST /users/{userId}/roles` | User role mappings |
| `GET` · `POST /groups/{groupId}/roles` | Group role mappings |

Client roles are managed under the owning client. See the [API reference](../integration/api-reference.md).

## See also

- [Users](users.md)
- [Groups](groups.md)
- [Scopes & claims](scopes-and-claims.md)
- [OIDC clients](oidc-clients.md)
