# GDPR & privacy

Built-in tooling to honour data-subject rights — export, erasure and consent — for both administrators and end users.

## What it is

Helix IAM ships the operations you need to meet data-subject requests under GDPR and comparable privacy regimes:

- **Right to access / portability** — export everything Helix IAM holds about a user as a structured file.
- **Right to erasure** — delete a user and their associated data.
- **Consent management** — view and manage the consent records a user has granted.

These actions are available to administrators through the admin API and console, and to end users directly through the **account console** for self-service.

## In the console

Open **Users → _select a user_ → Privacy (GDPR)** to:

1. **Export** the user's data for a portability or access request.
2. **Review consents** the user has granted and revoke any that no longer apply.
3. **Delete** the user to satisfy an erasure request.

!!! warning "Erasure is irreversible"
    Deleting a user removes their account and associated records. Confirm the request and your retention obligations first — and ensure the action is captured in your [audit log](../manage/events.md) for accountability.

## Over the API

Data-subject operations are realm- and user-scoped under `/admin/realms/{realm}/users/{userId}/gdpr`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### Export a user's data — `GET …/gdpr/export`

Satisfies a right-to-access / portability request. The response is a structured, versioned document (`schema: helix.gdpr.export/v1`) covering profile, attributes, roles, memberships, credentials, federated links, consents and login events:

```bash
USER_ID=684db0eb-4afe-44f9-ad16-37a64f3496ea
curl -s -b cookies.txt \
  "$HELIX_URL/admin/realms/$REALM/users/$USER_ID/gdpr/export"
```
```json
{
  "generatedAt": 1783341227374,
  "schema": "helix.gdpr.export/v1",
  "realmId": "acme",
  "userId": "684db0eb-4afe-44f9-ad16-37a64f3496ea",
  "profile": { "username": "alice", "email": null, "enabled": true, "createdAt": 1783001276475 },
  "attributes": {},
  "roles": ["user"],
  "realmMemberships": [ { "realmId": "acme", "joinedAt": null } ],
  "organizations": [],
  "credentials": [],
  "federatedLinks": [],
  "consents": [],
  "loginEvents": []
}
```

### Read consent records — `GET …/gdpr/consents`

```bash
curl -s -b cookies.txt \
  "$HELIX_URL/admin/realms/$REALM/users/$USER_ID/gdpr/consents"
```
```json
[]
```

### Erase a user — `DELETE …/gdpr`

Satisfies a right-to-erasure request. This is a **write**, so refresh the CSRF token first:

```bash
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/users" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt -X DELETE -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/users/$USER_ID/gdpr"
```

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /users/{userId}/gdpr/export` | Export everything held about a user (access / portability) |
| `GET /users/{userId}/gdpr/consents` | Read the user's consent records |
| `DELETE /users/{userId}/gdpr` | Erase the user and associated data (right to erasure) |

## End-user self-service

End users can exercise their own rights from the account console without contacting an administrator — authenticated by the **user's own** session, not an admin session:

| Method & path | Purpose |
| --- | --- |
| `GET /account/gdpr/export` | Download my own data |
| `GET /account/gdpr/consents` | List consents I've granted |
| `DELETE /account/gdpr/consents/{clientId}` | Revoke consent for one application |

This keeps routine privacy requests off your support desk while staying fully auditable.

## See also

- [Events & audit](../manage/events.md)
- [Compliance program](../compliance/compliance-program.md)
- [Admin roles (RBAC)](admin-roles.md)
- [Security hardening](security.md)
