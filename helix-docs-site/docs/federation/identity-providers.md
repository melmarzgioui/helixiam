# Identity Providers

Let people sign in with an account they already have — Helix IAM brokers the login, provisions the user automatically, and keeps you in control of every attribute.

## What it is

Helix IAM acts as an **identity broker**. Instead of holding a credential itself, the realm delegates authentication to a trusted external source — another OpenID Connect or SAML 2.0 provider, an LDAP/Active Directory directory, a social login, or one of the built-in **EU electronic IDs** (DigiD, eHerkenning, eIDAS). When a user returns from the upstream source, Helix takes over the session.

The broker model gives you three things out of the box:

- **Just-in-time (JIT) provisioning** — the first time someone logs in through a provider, Helix creates the local [user](../manage/users.md) automatically from the upstream identity, so there is no pre-registration step.
- **Account linking** — an incoming federated identity can be linked to an existing local account, so one person keeps one Helix identity across multiple login methods.
- **Configurable mappers** — per provider, you map upstream claims/attributes onto Helix user attributes, roles, and groups, so downstream applications see a consistent profile regardless of where the user authenticated.

Every provider is one record with the same shape: a stable **`alias`**, a **`protocol`** that selects the broker (`oidc`, `saml`, `ldap`, or an eID scheme), and a flat **`config`** map of protocol-specific settings. Providers are scoped **per realm** and are loaded and refreshed from the store at runtime, so adding or reconfiguring a provider takes effect without redeploying anything.

**Federated single logout (SLO)** propagates a Helix logout back to the upstream provider where the protocol supports it, so ending a session ends it everywhere.

## In the console

Providers live under the **Federation & eIDs** section. Each realm manages its own set.

1. Open **Federation & eIDs → Identity providers** to see every provider configured in the realm.
2. Click **Add identity provider** to launch the wizard, then choose the provider type — the fields adapt to the protocol you pick (see the sibling pages: [OIDC & social](oidc-social.md), [SAML](saml.md), [LDAP/AD](ldap.md), [DigiD](digid.md), [eHerkenning](eherkenning.md), [eIDAS](eidas.md)).
3. Provide the connection details for the upstream source — endpoints or metadata, client/SP credentials, and trust material as the protocol requires.
4. Define **attribute/claim mappers** to translate the upstream identity into Helix user attributes, roles, and groups.
5. Decide **account linking** behaviour for returning users and confirm **JIT provisioning** for first-time logins.
6. Optionally enable **federated SLO** so logout propagates upstream, then save. The provider is picked up on the next registry refresh and appears on the realm's sign-in options.

!!! tip
    Providers are always shown by their **display name** in the console and on the login page — the raw `alias` is only the stable key used in URLs and the API.

## Over the API

All provider management lives under `/admin/realms/{realm}/identity-providers`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List providers

Each entry echoes its `alias`, `protocol`, `displayName`, `enabled` flag, and the protocol-specific `config` map.

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/identity-providers"
```
```json
[
  { "realmId": "acme", "alias": "google",       "protocol": "oidc", "displayName": "Google",         "enabled": true },
  { "realmId": "acme", "alias": "partner-saml", "protocol": "saml", "displayName": "Partner Corp",   "enabled": true },
  { "realmId": "acme", "alias": "digid",        "protocol": "digid","displayName": "DigiD",          "enabled": true }
]
```

### Create a provider

`POST` the provider record. The `alias` and `protocol` are required; `config` carries the protocol-specific settings — see each sibling page for the keys that protocol reads.

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/identity-providers" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "alias": "google",
        "protocol": "oidc",
        "displayName": "Google",
        "enabled": true,
        "config": { "clientId": "…", "clientSecret": "…" }
      }' \
  "$HELIX_URL/admin/realms/$REALM/identity-providers"
```
```json
{
  "realmId": "acme",
  "alias": "google",
  "protocol": "oidc",
  "displayName": "Google",
  "enabled": true,
  "config": { "clientId": "…", "clientSecret": "…" }
}
```

### Update or delete a provider

The `alias` is the key for every subsequent call:

```bash
# Update — PUT the full desired state
curl -s -b cookies.txt -X PUT \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{ "alias": "google", "protocol": "oidc", "displayName": "Google Workspace", "enabled": true, "config": { "clientId": "…", "clientSecret": "…" } }' \
  "$HELIX_URL/admin/realms/$REALM/identity-providers/google"

# Delete — returns 204 No Content
curl -s -b cookies.txt -X DELETE -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/identity-providers/google"
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /identity-providers` · `POST /identity-providers` | List / create providers |
| `GET` · `PUT` · `DELETE /identity-providers/{alias}` | Read / update / delete a provider |
| `POST /user-federation/{alias}/sync` | Import / refresh directory users (LDAP/AD — see [LDAP](ldap.md)) |

See the [API reference](../integration/api-reference.md) for the complete schema of every field.

## See also

- [OIDC & social brokers](oidc-social.md) · [SAML broker](saml.md) · [LDAP / Active Directory](ldap.md)
- EU eIDs: [DigiD](digid.md) · [eHerkenning](eherkenning.md) · [eIDAS](eidas.md)
- [Users & credentials](../manage/users.md) — how JIT-provisioned users appear and are managed
- [Authentication flows](../authentication/flows.md) — where a broker step fits in the sign-in journey
- [API reference](../integration/api-reference.md)
