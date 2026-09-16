# Organizations

Organizations model B2B tenancy inside a realm — they group members so you can represent the companies, customers, or partners that share one realm.

## What it is

An **organization** is a first-class entity within a realm that has its own **members** (users). Organizations are how Helix IAM supports B2B scenarios: a single realm hosts many customer organizations, each with its own set of users, while still sharing the realm's clients, roles, and login experience.

Use organizations when:

- one deployment serves multiple business customers ("tenants within a tenant"),
- you need to scope or report on users by the company they belong to,
- partner or supplier users must be grouped distinctly from internal users.

!!! note
    Organizations and [groups](groups.md) are complementary. Organizations express *who the customer is* (B2B membership); groups and [roles](roles.md) express *what users can do*. A user can be an organization member and also hold group-based roles.

## In the console

Organizations live under **Manage → Users & access → Organizations**. Opening an organization shows its members; users are managed under [Users](users.md).

1. Open **Manage → Users & access → Organizations**, then click **Create**.
2. Set the **name**, **display name**, and any verified **domains**, then save.
3. Add existing [users](users.md) as **members** to represent that customer's people.
4. Remove a member to detach a user from the organization without deleting the user account.
5. Review an organization's membership to audit who belongs to which customer.

!!! tip
    Combine organizations with [groups](groups.md) and [roles](roles.md): map roles to groups for capabilities, and use organization membership to scope and report on B2B tenancy.

## Over the API

All organization management is available under `/admin/realms/{realm}/organizations`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List organizations

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/organizations"
```
```json
[
  {
    "realmId": "acme",
    "orgId": "008b4fd5-...",
    "name": "acme",
    "displayName": "Acme Corp",
    "domains": ["acme.example.com"],
    "enabled": true,
    "memberCount": 0,
    "createdAt": null
  }
]
```

### Create an organization

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/organizations" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "name": "acme",
        "displayName": "Acme Corp",
        "domains": ["acme.example.com"],
        "enabled": true
      }' \
  "$HELIX_URL/admin/realms/$REALM/organizations"
```
```json
{
  "realmId": "acme",
  "orgId": "008b4fd5-...",
  "name": "acme",
  "displayName": "Acme Corp",
  "domains": ["acme.example.com"],
  "enabled": true,
  "memberCount": 0,
  "createdAt": null
}
```

### Delete an organization

Use the returned `orgId`:

```bash
# Delete — returns 204 No Content
curl -s -b cookies.txt -X DELETE -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/organizations/008b4fd5-..."
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /organizations` · `POST /organizations` | List / create organizations |
| `GET` · `PUT` · `DELETE /organizations/{orgId}` | Read / update / delete an organization |
| `GET` · `POST` · `DELETE /organizations/{orgId}/members` | Manage members |

See the [API reference](../integration/api-reference.md) for the complete schema of every field.

## See also

- [Users](users.md)
- [Groups](groups.md)
- [Roles](roles.md)
- [Realms](realms.md)
