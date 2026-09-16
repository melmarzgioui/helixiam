# Admin roles (RBAC)

Scope exactly what each administrator can see and do with fine-grained, role-based access control.

## What it is

Not every administrator should hold the keys to everything. Helix IAM's admin RBAC grants **admin permissions to the realm's [roles](../manage/roles.md)** — so who can administer what is driven by the same roles you already assign to users. A help-desk operator role might reset credentials but never touch signing keys; a realm-owner role manages its own realm but not the platform.

Grants are drawn from a fixed catalogue of discrete **permissions**, each gating a class of administrative action (managing users, editing realm settings, managing clients, viewing events, and so on). The `realm-admin` permission is the super-grant. Assign the smallest set that lets an admin do their job — least privilege by construction.

Every realm is seeded with sensible defaults: the `admin` role holds `realm-admin`; the `auditor` role holds the read-only `view-*` permissions; the default `user` role holds none.

## In the console

1. Open **Manage → Users & access → Admin roles**.
2. Pick a [realm role](../manage/roles.md) and tick the admin permissions it should grant.
3. **Save** — the grants take effect on the next request from anyone holding that role.

Admins see only the screens and actions their role's permissions allow; everything else is hidden or denied.

## How to design roles

- Start from the permission catalogue and group by job function (operator, realm owner, auditor, security).
- Separate **read** from **write** where the catalogue allows it — the seeded `auditor` role (view-only) is the canonical example.
- Keep highly privileged permissions (`realm-admin`, `manage-realm`, `manage-events`) on a small number of tightly held roles.
- Pair RBAC with the [audit log](observability.md) so every administrative write is attributable to a named admin.

## Over the API

Admin RBAC lives under `/admin/realms/{realm}/admin-roles`. It edits the permission grants **on existing realm roles** — there is no separate admin-role object to create or delete. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List roles and their grants

Each entry is a realm role plus the admin permissions it currently holds:

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/admin-roles"
```
```json
[
  { "realmId": "acme", "roleId": "8d3a79d3-40e4-4497-8543-234685e689a8", "roleName": "admin",   "permissions": ["realm-admin"] },
  { "realmId": "acme", "roleId": "9ec2e116-e56b-458d-b11d-1efbfd1c492a", "roleName": "user",    "permissions": [] },
  { "realmId": "acme", "roleId": "6c898aa8-98dc-4597-87be-9352dd5f21da", "roleName": "auditor", "permissions": ["view-clients","view-events","view-users"] }
]
```

### Read the permission catalogue

The catalogue is fixed; `permissions` values in a grant must be `key`s from this list:

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/admin-roles/permissions"
```
```json
[
  { "key": "realm-admin",               "label": "Full realm administration" },
  { "key": "view-users",                "label": "View users" },
  { "key": "manage-users",              "label": "Manage users" },
  { "key": "view-clients",              "label": "View clients / applications" },
  { "key": "manage-clients",            "label": "Manage clients / applications" },
  { "key": "manage-roles",              "label": "Manage realm & client roles" },
  { "key": "manage-identity-providers", "label": "Manage identity providers & federation" },
  { "key": "manage-authorization",      "label": "Manage authorization (flows, scopes, claims, authz services)" },
  { "key": "manage-organizations",      "label": "Manage organizations & groups" },
  { "key": "manage-realm",              "label": "Manage realm settings, notifications & provisioning" },
  { "key": "view-events",               "label": "View events & sessions" },
  { "key": "manage-events",             "label": "Manage events config & revoke sessions" }
]
```

### Set a role's grants

`PUT /admin-roles/{roleId}` replaces the permission set for that role. Use the `roleId` from the list above:

```bash
# Refresh CSRF after any GET, then PUT (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/admin-roles" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

# Grant the auditor role read access to users and events (replaces its current grants)
curl -s -b cookies.txt -X PUT \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{"permissions":["view-users","view-clients","view-events"]}' \
  "$HELIX_URL/admin/realms/$REALM/admin-roles/6c898aa8-98dc-4597-87be-9352dd5f21da"
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /admin-roles` | List realm roles with their admin-permission grants |
| `GET /admin-roles/permissions` | Read the fixed permission catalogue |
| `PUT /admin-roles/{roleId}` | Replace the admin permissions granted to a role |

Realm roles themselves are created and deleted under `/roles` — see [Roles](../manage/roles.md).

## See also

- [Roles](../manage/roles.md)
- [Security hardening](security.md)
- [Observability & health](observability.md)
- [Realm settings](realm-settings.md)
