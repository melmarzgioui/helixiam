# SAML Broker

Broker authentication to an external SAML 2.0 identity provider, with Helix IAM acting as the service provider and owning the resulting user.

## What it is

When you broker to a **SAML 2.0** IdP, Helix IAM acts as the **service provider (SP)**. Helix issues the authentication request, consumes the upstream assertion, and maps the asserted identity into the realm. This is the path for federating with enterprise IdPs, government identity hubs, and partner organisations that speak SAML.

- **Metadata-driven trust** — import the upstream IdP's metadata to configure endpoints and signing certificates in one step.
- **Signing & encryption** — configure request signing, assertion signature verification, and assertion encryption to meet the upstream's security profile.
- **Attribute mappers** — map SAML assertion attributes to Helix user attributes, roles, and groups.
- **JIT provision + link** — new users are created on first login; returning users can be linked to an existing [account](../manage/users.md).

A SAML broker is an [identity provider](identity-providers.md) with `protocol: "saml"`. Its `config` names the IdP's SSO endpoint and entity id, Helix's own SP entity id and ACS URL, and the IdP signing certificate used to verify assertions.

## In the console

1. Open **Federation & eIDs → Identity providers** and click **Add identity provider**.
2. Choose **SAML**, then **import the upstream IdP metadata** (by URL or file) so endpoints and certificates are populated for you — or enter them manually.
3. Configure the **security profile** — request signing, assertion signature verification, and encryption — to match what the upstream IdP expects.
4. Provide Helix's **SP metadata** to the upstream operator so they can register Helix as a relying SP.
5. Define **attribute mappers** from assertion attributes to Helix user attributes, roles, and groups.
6. Set **account linking** and confirm **JIT provisioning**, then save.

!!! tip "Keep certificates current"
    Re-import the upstream metadata when the IdP rotates its signing certificate, so signature verification keeps working without manual certificate edits.

## Over the API

A SAML broker is created like any [identity provider](identity-providers.md), with `protocol: "saml"`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List SAML brokers

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/identity-providers"
```
```json
[
  { "realmId": "acme", "alias": "partner-saml", "protocol": "saml", "displayName": "Partner Corp", "enabled": true }
]
```

### Create a SAML broker

The `config` map carries the SAML trust and endpoints. You can supply them explicitly, or pass upstream metadata via `metadataUrl` / `metadataXml` to have Helix populate them.

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/identity-providers" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "alias": "partner-saml",
        "protocol": "saml",
        "displayName": "Partner Corp",
        "enabled": true,
        "config": {
          "ssoUrl": "https://idp.partner.example/sso",
          "idpEntityId": "https://idp.partner.example/",
          "spEntityId": "https://auth.example.com/realms/acme",
          "assertionConsumerServiceUrl": "https://auth.example.com/broker/partner-saml/acs",
          "idpSigningCertificate": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----",
          "emailAttribute": "email",
          "firstNameAttribute": "givenName",
          "lastNameAttribute": "surname"
        }
      }' \
  "$HELIX_URL/admin/realms/$REALM/identity-providers"
```
```json
{
  "realmId": "acme",
  "alias": "partner-saml",
  "protocol": "saml",
  "displayName": "Partner Corp",
  "enabled": true,
  "config": {
    "ssoUrl": "https://idp.partner.example/sso",
    "idpEntityId": "https://idp.partner.example/",
    "spEntityId": "https://auth.example.com/realms/acme",
    "assertionConsumerServiceUrl": "https://auth.example.com/broker/partner-saml/acs",
    "idpSigningCertificate": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----",
    "emailAttribute": "email",
    "firstNameAttribute": "givenName",
    "lastNameAttribute": "surname"
  }
}
```

!!! note "Config keys"
    `ssoUrl`, `idpEntityId`, `spEntityId`, `assertionConsumerServiceUrl`, `idpSigningCertificate`, the assertion-attribute names `emailAttribute` (defaults to `email`) / `firstNameAttribute` / `lastNameAttribute`, and an optional `singleLogoutServiceUrl` for federated SLO. Metadata import accepts `metadataUrl` or `metadataXml`.

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /identity-providers` · `POST /identity-providers` | List / create providers |
| `GET` · `PUT` · `DELETE /identity-providers/{alias}` | Read / update / delete a provider |
| `GET /saml/idp/metadata` | Helix's own SAML metadata (share with the upstream operator) |

See [Identity providers](identity-providers.md) for the shared flow, and the [API reference](../integration/api-reference.md) for every field.

## See also

- [Identity providers](identity-providers.md) — broker model, JIT, linking, SLO
- [OIDC & social brokers](oidc-social.md) · [LDAP / Active Directory](ldap.md)
- EU eIDs over SAML: [DigiD](digid.md) · [eHerkenning](eherkenning.md) · [eIDAS](eidas.md)
- [Users & credentials](../manage/users.md) · [Authentication flows](../authentication/flows.md)
