# Groups

Groups organize users into a hierarchy and grant roles in bulk — members inherit the roles mapped to their group.

## What it is

A group is a named collection of [users](users.md). Groups are **hierarchical**: each group can have a parent (and therefore children), forming a tree. A group has:

- **Members** — the users that belong to it.
- **Group-role mappings** — the [roles](roles.md) granted to every member.

Members inherit the roles of the group. This makes groups the recommended way to manage access at scale: assign roles to a group once, then add and remove users from the group to grant or revoke that access.

!!! note
    Use groups for "who they are" (department, team, tenant) and let role mappings express "what they can do." This keeps individual user records clean and access auditable.

## In the console

Groups live under **Manage → Users & access → Groups**. Opening a group shows its members, its role mappings, and its place in the hierarchy.

1. Open **Manage → Users & access → Groups**, then click **Create**, name the group, and optionally nest it under a parent.
2. Add [users](users.md) as **members** — they immediately inherit the group's roles.
3. Map realm or client [roles](roles.md) to the group so every member receives them.
4. Create child groups under a parent to model nested structure (department → team).
5. Remove a member to revoke the roles they held only through that group.

!!! tip
    Prefer mapping roles to groups over assigning them directly to users. Onboarding and offboarding then become a single group membership change.

## Over the API

All group management is available under `/admin/realms/{realm}/groups`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List groups

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/groups"
```
```json
[
  {
    "realmId": "acme",
    "groupId": "3ce69318-...",
    "name": "engineering",
    "parentId": null,
    "memberCount": 0,
    "roleNames": []
  }
]
```

### Create a group

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/groups" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{"name":"engineering"}' \
  "$HELIX_URL/admin/realms/$REALM/groups"
```
```json
{
  "realmId": "acme",
  "groupId": "3ce69318-...",
  "name": "engineering",
  "parentId": null,
  "memberCount": 0,
  "roleNames": []
}
```

!!! tip "Nested groups"
    To nest a group under a parent, add its `groupId` as `parentId` in the create body — e.g. `{"name":"platform-team","parentId":"3ce69318-..."}`.

### Delete a group

Use the returned `groupId`:

```bash
# Delete — returns 204 No Content
curl -s -b cookies.txt -X DELETE -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/groups/3ce69318-..."
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /groups` · `POST /groups` | List / create groups |
| `GET` · `PUT` · `DELETE /groups/{groupId}` | Read / update / delete a group (incl. parent) |
| `GET` · `POST` · `DELETE /groups/{groupId}/members` | Manage members |
| `GET` · `POST` · `DELETE /groups/{groupId}/roles` | Group-role mappings |

See the [API reference](../integration/api-reference.md) for the complete schema of every field.

## See also

- [Users](users.md)
- [Roles](roles.md)
- [Organizations](organizations.md)
