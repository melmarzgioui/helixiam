# Applications

An application is a protocol-agnostic service provider — a single human-named entity that can own an OIDC client and/or a SAML relying party while sharing one subject-claim, one login flow, and one display name.

## What it is

In Helix IAM, an **application** models "the thing your users sign in to" independently of how it speaks to the identity provider. One application can have:

- a child **[OIDC client](oidc-clients.md)** (OAuth2 / OpenID Connect), and/or
- a child **[SAML relying party](saml-clients.md)** (SAML 2.0).

The application is the parent. It carries the shared, protocol-independent settings:

- a human **display name** used everywhere in the console (never a raw client ID or UUID),
- the **subject claim** to use as the token subject,
- the **login flow** (authentication journey) users follow to sign in.

This lets one service offer both OIDC and SAML to its users while presenting a single, consistent identity and sign-in experience.

!!! tip
    Start by creating the application, then attach an OIDC client, a SAML relying party, or both. Settings you set on the application (display name, subject claim, login flow) are inherited by the children.

## In the console

Applications live under **Manage → Applications & clients → Applications**, each shown by its display name. Opening an application lets you manage its OIDC and SAML children and the shared identity settings from one place.

1. Open **Manage → Applications & clients → Applications**, click **Create**, give it a display name, and save.
2. **Add OIDC** — from the application, add an [OIDC client](oidc-clients.md) and configure redirect URIs, scopes, and grant types.
3. **Add SAML** — from the application, add a [SAML relying party](saml-clients.md) and configure ACS URLs, signing, and NameID.
4. **Set the subject claim** — choose which user attribute becomes the token subject (see [Scopes & claims](scopes-and-claims.md)).
5. **Choose the login flow** — bind the [authentication journey](../authentication/flows.md) users follow to sign in.
6. **Delete an application** — removes it and cascade-deletes its child OIDC client and SAML relying party.

!!! warning
    Deleting an application cascade-deletes its child OIDC client and SAML relying party. If you only want to stop one protocol, remove that child instead of the whole application.

## Over the API

Applications live under `/admin/realms/{realm}/applications`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List applications

Each entry carries the shared, protocol-independent settings (`displayName`, `subjectClaim`, `authFlowAlias`) that its OIDC and SAML children inherit.

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/applications"
```
```json
[
  { "realmId": "acme", "name": "helix-example-app", "subjectClaim": null, "authFlowAlias": "helix-example-app-sso", "enabled": true, "displayName": null },
  { "realmId": "acme", "name": "Helix CLI",         "subjectClaim": null, "authFlowAlias": null,                    "enabled": true, "displayName": "Helix CLI" },
  { "realmId": "acme", "name": "Helix Admin Console","subjectClaim": null,"authFlowAlias": null,                    "enabled": true, "displayName": "Helix Admin Console" }
]
```

### Create an application

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/applications" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{"name":"acme-suite","displayName":"Acme Suite"}' \
  "$HELIX_URL/admin/realms/$REALM/applications"
```
```json
{
  "realmId": "acme",
  "name": "acme-suite",
  "description": null,
  "subjectClaim": null,
  "authFlowAlias": null,
  "enabled": true,
  "displayName": "Acme Suite"
}
```

### Update or delete an application

Applications are keyed by **name**, not a UUID — use the `name` for subsequent calls:

```bash
# Update shared settings — PUT the desired state
curl -s -b cookies.txt -X PUT \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{"name":"acme-suite","displayName":"Acme Suite","subjectClaim":"email"}' \
  "$HELIX_URL/admin/realms/$REALM/applications/acme-suite"

# Delete — cascades to child OIDC client + SAML RP; returns 204 No Content
curl -s -b cookies.txt -X DELETE -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/applications/acme-suite"
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /applications` · `POST /applications` | List / create applications |
| `GET` · `PUT` · `DELETE /applications/{name}` | Read / update / delete (delete cascades to children) |

Child objects are managed via the OIDC `/clients` and SAML `/saml-clients` endpoints; see those pages. Full details in the [API reference](../integration/api-reference.md).

## See also

- [OIDC clients](oidc-clients.md)
- [SAML clients](saml-clients.md)
- [Scopes & claims](scopes-and-claims.md)
- [Authentication flows](../authentication/flows.md)
