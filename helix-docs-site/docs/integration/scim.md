# SCIM Provisioning

Keep users and groups in sync automatically — in from your HR system or IdP, and out to your downstream apps — over the open SCIM 2.0 standard.

## What it is

Helix IAM is a full **SCIM 2.0 server**, and it provisions in both directions:

- **Inbound** — your HR system or upstream IdP pushes users and groups *into* Helix. Joiners, movers, and leavers flow through automatically.
- **Outbound** — Helix provisions accounts *out* to your downstream SCIM-capable apps, so deprovisioning a user in Helix removes their access everywhere.

## Bearer auth, not admin session

The SCIM API is a **machine-to-machine** surface. Unlike the [admin API](../getting-started/api-authentication.md) (session + CSRF), it is authenticated by a **per-realm SCIM token** presented as a bearer token — no cookie jar, no CSRF header:

```
Authorization: Bearer <scim-token>
```

Mint the token for the realm from the console, then hand it to your provisioning source. All SCIM requests use the SCIM media type `application/scim+json`.

## In the console

SCIM lives under **Integration → Provisioning → SCIM**.

1. Open **Integration → Provisioning → SCIM** and issue a **SCIM token** for the realm.
2. Copy the token into your HR system or IdP's provisioning connector as the bearer credential.
3. Point the connector at the realm's SCIM base URL, `/realms/{realm}/scim/v2`.
4. Start from **ServiceProviderConfig** to confirm which capabilities Helix advertises, then map your source attributes.

## Inbound (Helix as the SCIM server)

Point your provisioning source at the realm's SCIM endpoints under `/realms/{realm}/scim/v2` and authenticate with the per-realm SCIM token.

### Create a user

```bash
curl -s -X POST "$HELIX_URL/realms/$REALM/scim/v2/Users" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "jane@example.com",
        "name": { "givenName": "Jane", "familyName": "Doe" },
        "emails": [{ "value": "jane@example.com", "primary": true }],
        "active": true
      }'
```

The server responds `201 Created` with the provisioned SCIM resource, including its server-assigned `id` — use that for subsequent read, replace, patch, and delete calls on `/Users/{id}`.

!!! note "Bearer required"
    Every SCIM call must carry `Authorization: Bearer <scim-token>`. Requests without it are rejected with `401 Unauthorized`.

### Endpoints

| Method & path (under `/realms/{realm}/scim/v2`) | Purpose |
| --- | --- |
| `GET /Users` · `POST /Users` | List / create users |
| `GET` · `PUT` · `PATCH` · `DELETE /Users/{id}` | Read / replace / patch / deactivate a user |
| `GET /Groups` · `POST /Groups` | List / create groups |
| `GET` · `PUT` · `PATCH` · `DELETE /Groups/{id}` | Read / replace / patch / delete a group |
| `GET /ServiceProviderConfig` | Capabilities Helix supports |
| `GET /Schemas` | Resource schemas |
| `GET /ResourceTypes` | Available resource types |

!!! tip "Standards-based, vendor-neutral"
    Any SCIM 2.0 client works — start from `ServiceProviderConfig` to discover exactly what Helix supports, then map your source attributes.

## Outbound (Helix to downstream targets)

Register the apps Helix should provision into as **SCIM targets**, managed over the admin API (session + CSRF):

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /scim-targets` · `POST /scim-targets` | List / register downstream targets |
| `PUT` · `DELETE /scim-targets/{id}` | Update / remove a target |

Each target stores the downstream base URL and credentials. When a user is created, updated, or deactivated in Helix, the change is pushed to every connected target — one source of truth, consistent access everywhere.

## See also

- [Users](../manage/users.md)
- [Groups](../manage/groups.md)
- [Webhooks](webhooks.md)
- [LDAP federation](../federation/ldap.md)
- [Import / export & migration](import-export.md)
