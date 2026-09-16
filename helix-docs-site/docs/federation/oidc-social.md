# OIDC & Social Brokers

Let users sign in with any standard OpenID Connect provider or a social account, and have Helix IAM provision and own the resulting identity.

## What it is

Helix IAM brokers authentication to any standards-compliant **OpenID Connect** provider, and to popular **social logins** built on the same protocol. Helix initiates the OIDC authorization flow, validates the upstream tokens, and then maps the resulting identity into the realm.

The value is consistency: however your users choose to authenticate, downstream applications integrated with Helix always receive the same well-shaped profile and tokens.

- **Claim mapping** — translate upstream ID-token and UserInfo claims into Helix user attributes, roles, and groups.
- **JIT provision + link** — first-time users are created automatically; returning users can be linked to an existing local [account](../manage/users.md).
- **Per-realm** — each realm manages its own set of OIDC and social providers.

An OIDC broker is an [identity provider](identity-providers.md) with `protocol: "oidc"`. Its `config` carries the upstream endpoints (from the provider's discovery document) and the client credentials the provider issued to Helix as a relying party.

## In the console

1. Open **Federation & eIDs → Identity providers** and click **Add identity provider**.
2. Choose **OIDC** (or a named social provider such as Google or Microsoft).
3. Register Helix as a client with the upstream provider and bring back the **client credentials** (`clientId` / `clientSecret`) and the provider's **discovery/issuer** details — either the discovery document or the individual endpoints.
4. Choose the **scopes** to request so the upstream returns the claims you need (`openid` is always included).
5. Define **claim mappers** from upstream claims to Helix user attributes, roles, and groups.
6. Set **account linking** and confirm **JIT provisioning** behaviour, then save. The provider is loaded at runtime and appears on the realm's sign-in options.

!!! tip
    Request only the scopes you actually map. A lean scope set keeps consent screens clear and the provisioned profile predictable.

## Over the API

An OIDC broker is created like any [identity provider](identity-providers.md), with `protocol: "oidc"`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List OIDC brokers

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/identity-providers"
```
```json
[
  { "realmId": "acme", "alias": "keycloak-oidc", "protocol": "oidc", "displayName": "Partner SSO", "enabled": true }
]
```

### Create an OIDC broker

The `config` map carries the upstream connection. For a **generic OIDC** provider, supply the endpoints from its discovery document; for a **social preset** (`protocol: "social"`, `provider: "google"|"microsoft"`) the endpoints are built in and you supply only the client credentials.

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/identity-providers" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "alias": "partner-sso",
        "protocol": "oidc",
        "displayName": "Partner SSO",
        "enabled": true,
        "config": {
          "clientId": "helix-broker",
          "clientSecret": "…",
          "issuer": "https://idp.partner.example/",
          "authorizationEndpoint": "https://idp.partner.example/authorize",
          "tokenEndpoint": "https://idp.partner.example/token",
          "jwksUri": "https://idp.partner.example/jwks",
          "scopes": "openid email profile"
        }
      }' \
  "$HELIX_URL/admin/realms/$REALM/identity-providers"
```
```json
{
  "realmId": "acme",
  "alias": "partner-sso",
  "protocol": "oidc",
  "displayName": "Partner SSO",
  "enabled": true,
  "config": {
    "clientId": "helix-broker",
    "clientSecret": "…",
    "issuer": "https://idp.partner.example/",
    "authorizationEndpoint": "https://idp.partner.example/authorize",
    "tokenEndpoint": "https://idp.partner.example/token",
    "jwksUri": "https://idp.partner.example/jwks",
    "scopes": "openid email profile"
  }
}
```

!!! note "Config keys"
    `clientId`, `clientSecret`, `issuer`, `authorizationEndpoint`, `tokenEndpoint`, `jwksUri`, and a space- or comma-separated `scopes` (defaults to `openid`). An optional `endSessionEndpoint` enables RP-initiated logout upstream.

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /identity-providers` · `POST /identity-providers` | List / create providers |
| `GET` · `PUT` · `DELETE /identity-providers/{alias}` | Read / update / delete a provider |

See [Identity providers](identity-providers.md) for the shared create/update/delete flow, and the [API reference](../integration/api-reference.md) for every field.

## See also

- [Identity providers](identity-providers.md) — the broker model, linking, mappers, SLO
- [SAML broker](saml.md) · [LDAP / Active Directory](ldap.md)
- [Users & credentials](../manage/users.md) — JIT-provisioned users
- [Authentication flows](../authentication/flows.md)
