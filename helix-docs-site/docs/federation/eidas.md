# eIDAS (EU Cross-Border)

Sign in EU citizens from across the Union with **eIDAS** cross-border login — available out of the box.

## What it is

eIDAS is the European framework for **cross-border** electronic identification: a citizen authenticates with their own national eID and is recognised by services in another member state through the eIDAS network. With Helix IAM the eIDAS connector is **built in**: you add it from the identity-provider wizard, and the realm can authenticate citizens from across the EU, [provisioning the user just-in-time](identity-providers.md) and mapping the cross-border identity into your realm.

Out-of-the-box pan-European citizen login is one of Helix IAM's flagship differentiators — reach into every member state without building bespoke integrations.

eIDAS is an [identity provider](identity-providers.md) with `protocol: "eidas"`. It builds on the SAML 2.0 SP profile (signed AuthnRequest, encrypted assertion) and reads the **eIDAS minimum dataset** — the `PersonIdentifier` and name attributes — from the assertion returned by your national eIDAS node.

## In the console

1. Open **Federation & eIDs → Identity providers** and click **Add identity provider**.
2. Choose **eIDAS**. This applies **facilitated defaults** for the scheme, so you supply only your environment-specific details.
3. Supply your environment-specific trust material and service details.
4. Configure **attribute mappers** for the eIDAS minimum dataset (`PersonIdentifier` and names) and any attributes you consume.
5. Save; the provider loads at runtime and appears as an eIDAS sign-in option.

!!! note "Operational note — production accreditation"
    The eIDAS connector is **built in and configurable now**. Connecting to **production** is a formal process: you connect through your **national eIDAS node**, which carries its own admission and accreditation requirements. Plan that accreditation track separately from the technical configuration, which you can complete immediately.

## Over the API

eIDAS is created like any [identity provider](identity-providers.md), with `protocol: "eidas"`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### Create an eIDAS connector

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/identity-providers" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "alias": "eidas",
        "protocol": "eidas",
        "displayName": "eIDAS",
        "enabled": true,
        "config": {
          "ssoUrl": "https://eidas-node.example/EidasNode/ServiceProvider",
          "idpEntityId": "https://eidas-node.example/EidasNode/ConnectorMetadata",
          "spEntityId": "https://auth.example.com/realms/acme/eidas",
          "assertionConsumerServiceUrl": "https://auth.example.com/broker/eidas/acs",
          "idpSigningCertificate": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----",
          "spDecryptionPrivateKey": "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----",
          "spSigningPrivateKey": "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----",
          "spSigningCertificate": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----",
          "minimumLoa": "http://eidas.europa.eu/LoA/substantial",
          "subjectAttribute": "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"
        }
      }' \
  "$HELIX_URL/admin/realms/$REALM/identity-providers"
```
```json
{
  "realmId": "acme",
  "alias": "eidas",
  "protocol": "eidas",
  "displayName": "eIDAS",
  "enabled": true,
  "config": {
    "ssoUrl": "https://eidas-node.example/EidasNode/ServiceProvider",
    "idpEntityId": "https://eidas-node.example/EidasNode/ConnectorMetadata",
    "spEntityId": "https://auth.example.com/realms/acme/eidas",
    "assertionConsumerServiceUrl": "https://auth.example.com/broker/eidas/acs",
    "minimumLoa": "http://eidas.europa.eu/LoA/substantial",
    "subjectAttribute": "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"
  }
}
```

!!! note "Config keys"
    SAML-SP endpoints (`ssoUrl`, `idpEntityId`, `spEntityId`, `assertionConsumerServiceUrl`, `idpSigningCertificate`) plus the eID material: `spDecryptionPrivateKey`, `spSigningPrivateKey`, `spSigningCertificate`, `minimumLoa` (an eIDAS LoA URN — `low`/`substantial`/`high`), `subjectAttribute` (the `PersonIdentifier`), and `authnRequestBinding` / `responseBinding`.

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /identity-providers` · `POST /identity-providers` | List / create providers |
| `GET` · `PUT` · `DELETE /identity-providers/{alias}` | Read / update / delete a provider |

See [Identity providers](identity-providers.md) for the shared flow, and the [API reference](../integration/api-reference.md) for every field.

## See also

- [Identity providers](identity-providers.md) — broker model, JIT provisioning, SLO
- [DigiD (NL citizen)](digid.md) · [eHerkenning (NL business)](eherkenning.md)
- [SAML broker](saml.md) — the underlying SAML 2.0 profile
- [Users & credentials](../manage/users.md) · [Authentication flows](../authentication/flows.md)
