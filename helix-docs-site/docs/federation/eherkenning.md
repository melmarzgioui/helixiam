# eHerkenning (NL Business eID)

Sign in Dutch businesses and their employees with **eHerkenning** — the national business eID — available out of the box.

## What it is

eHerkenning is the Netherlands' standardised business electronic identity, used by organisations and their authorised representatives to access services securely. With Helix IAM the eHerkenning connector is **built in**: you add it from the identity-provider wizard, and the realm can authenticate business users with their eHerkenning identity, [provisioning the user just-in-time](identity-providers.md) and mapping it into your realm.

Out-of-the-box business-eID coverage is one of Helix IAM's flagship differentiators — capability you would otherwise have to build and maintain yourself.

eHerkenning is an [identity provider](identity-providers.md) with `protocol: "eherkenning"`. It builds on the SAML 2.0 SP profile (signed AuthnRequest, encrypted assertion) and asserts the organisation and its acting representative. Optional **representation (mandate)** support lets a request ask for a mandated `serviceId` and read the acting subject from the assertion.

## In the console

1. Open **Federation & eIDs → Identity providers** and click **Add identity provider**.
2. Choose **eHerkenning**. This applies **facilitated defaults** for the scheme, so you supply only your environment-specific details.
3. Supply your environment-specific trust material and service details.
4. Configure **attribute mappers** for the organisation / representative identifiers and any attributes you consume.
5. Save; the provider loads at runtime and appears as an eHerkenning sign-in option.

!!! note "Operational note — production accreditation"
    The eHerkenning connector is **built in and configurable now**. Connecting to **production** is a formal scheme process: admission and accreditation are arranged through the **Afsprakenstelsel eToegang** scheme. Plan that accreditation track separately from the technical configuration, which you can complete immediately.

## Over the API

eHerkenning is created like any [identity provider](identity-providers.md), with `protocol: "eherkenning"`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### Create an eHerkenning connector

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/identity-providers" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "alias": "eherkenning",
        "protocol": "eherkenning",
        "displayName": "eHerkenning",
        "enabled": true,
        "config": {
          "ssoUrl": "https://eherkenning.example/sso",
          "idpEntityId": "urn:etoegang:HM:00000000000000000000:entities:0000",
          "spEntityId": "urn:etoegang:DV:00000000000000000000:entities:0001",
          "assertionConsumerServiceUrl": "https://auth.example.com/broker/eherkenning/acs",
          "idpSigningCertificate": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----",
          "spDecryptionPrivateKey": "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----",
          "spSigningPrivateKey": "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----",
          "spSigningCertificate": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----",
          "minimumLoa": "urn:etoegang:core:assurance-class:loa3",
          "subjectAttribute": "urn:etoegang:core:LegalSubjectID"
        }
      }' \
  "$HELIX_URL/admin/realms/$REALM/identity-providers"
```
```json
{
  "realmId": "acme",
  "alias": "eherkenning",
  "protocol": "eherkenning",
  "displayName": "eHerkenning",
  "enabled": true,
  "config": {
    "ssoUrl": "https://eherkenning.example/sso",
    "idpEntityId": "urn:etoegang:HM:00000000000000000000:entities:0000",
    "spEntityId": "urn:etoegang:DV:00000000000000000000:entities:0001",
    "assertionConsumerServiceUrl": "https://auth.example.com/broker/eherkenning/acs",
    "minimumLoa": "urn:etoegang:core:assurance-class:loa3",
    "subjectAttribute": "urn:etoegang:core:LegalSubjectID"
  }
}
```

!!! note "Config keys"
    SAML-SP endpoints (`ssoUrl`, `idpEntityId`, `spEntityId`, `assertionConsumerServiceUrl`, `idpSigningCertificate`) plus the eID material: `spDecryptionPrivateKey`, `spSigningPrivateKey`, `spSigningCertificate`, `minimumLoa`, `subjectAttribute` (the entity-concerned/legal-subject id), and `authnRequestBinding` / `responseBinding`. Representation (mandate) is opt-in; its exact attribute identifiers are supplied from your eHerkenning onboarding.

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /identity-providers` · `POST /identity-providers` | List / create providers |
| `GET` · `PUT` · `DELETE /identity-providers/{alias}` | Read / update / delete a provider |

See [Identity providers](identity-providers.md) for the shared flow, and the [API reference](../integration/api-reference.md) for every field.

## See also

- [Identity providers](identity-providers.md) — broker model, JIT provisioning, SLO
- [DigiD (NL citizen)](digid.md) · [eIDAS (EU cross-border)](eidas.md)
- [SAML broker](saml.md) — the underlying SAML 2.0 profile
- [Users & credentials](../manage/users.md) · [Authentication flows](../authentication/flows.md)
