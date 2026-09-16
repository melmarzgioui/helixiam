# DigiD (NL Citizen eID)

Sign in Dutch citizens with **DigiD** — the national citizen eID — available out of the box and configurable from the console.

## What it is

DigiD is the Netherlands' citizen electronic identity. With Helix IAM the DigiD connector is **built in**: there is no add-on to install and no integration to build. You add it like any other identity provider, and the realm can authenticate citizens with their DigiD identity, with the resulting user [provisioned just-in-time](identity-providers.md) and mapped into your realm.

DigiD is one of Helix IAM's flagship differentiators — out-of-the-box EU eID coverage that most identity products leave you to build yourself.

DigiD is an [identity provider](identity-providers.md) with `protocol: "digid"`. It builds on the SAML 2.0 SP profile but adds the eID-specific material: an SP decryption key (the assertion — and thus the **BSN** — is encrypted to the SP), an SP signing key (the AuthnRequest must be XML-signed), and a minimum level of assurance.

**Binding support.** Helix supports the classic SAML2 **HTTP-Artifact** binding — back-channel **ArtifactResolve** over mutual-TLS SOAP — as well as **HTTP-POST**, selectable per connection so you can match the profile your environment requires.

## In the console

1. Open **Federation & eIDs → Identity providers** and click **Add identity provider**.
2. Choose **DigiD**. This applies **facilitated defaults** for the scheme, so most of the connection is pre-shaped and you supply only your environment-specific details.
3. Supply your environment-specific trust material and service details.
4. Select the **binding** — HTTP-Artifact (with the ArtifactResolve back-channel over mutual TLS) or HTTP-POST — to match your connection profile.
5. Configure **attribute mappers** for the citizen identifier (BSN) and any attributes you consume.
6. Save; the provider loads at runtime and appears as a DigiD sign-in option.

!!! note "Operational note — production accreditation"
    The DigiD connector is **built in and configurable now**. Connecting to **production**, however, is a formal scheme process: admission and accreditation are arranged through **Logius**, and include a **mandatory annual security assessment**. Plan that accreditation track separately from the technical configuration, which you can complete immediately.

## Over the API

DigiD is created like any [identity provider](identity-providers.md), with `protocol: "digid"`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### Create a DigiD connector

The `config` map carries the SAML-SP endpoints and the eID trust material. Set `responseBinding` to `artifact` for the classic DigiD "Koppelvlak SAML" back-channel resolve, or `post` for the modern front-channel profile.

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/identity-providers" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "alias": "digid",
        "protocol": "digid",
        "displayName": "DigiD",
        "enabled": true,
        "config": {
          "ssoUrl": "https://digid.example/saml/idp/request_authentication",
          "idpEntityId": "https://digid.example/saml/idp/metadata",
          "spEntityId": "https://auth.example.com/realms/acme/digid",
          "assertionConsumerServiceUrl": "https://auth.example.com/broker/digid/acs",
          "idpSigningCertificate": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----",
          "spDecryptionPrivateKey": "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----",
          "spSigningPrivateKey": "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----",
          "spSigningCertificate": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----",
          "minimumLoa": "loa3",
          "subjectAttribute": "bsn",
          "responseBinding": "artifact",
          "artifactResolutionServiceUrl": "https://digid.example/saml/idp/resolve_artifact"
        }
      }' \
  "$HELIX_URL/admin/realms/$REALM/identity-providers"
```
```json
{
  "realmId": "acme",
  "alias": "digid",
  "protocol": "digid",
  "displayName": "DigiD",
  "enabled": true,
  "config": {
    "ssoUrl": "https://digid.example/saml/idp/request_authentication",
    "idpEntityId": "https://digid.example/saml/idp/metadata",
    "spEntityId": "https://auth.example.com/realms/acme/digid",
    "assertionConsumerServiceUrl": "https://auth.example.com/broker/digid/acs",
    "minimumLoa": "loa3",
    "subjectAttribute": "bsn",
    "responseBinding": "artifact",
    "artifactResolutionServiceUrl": "https://digid.example/saml/idp/resolve_artifact"
  }
}
```

!!! note "Config keys"
    SAML-SP endpoints (`ssoUrl`, `idpEntityId`, `spEntityId`, `assertionConsumerServiceUrl`, `idpSigningCertificate`) plus the eID material: `spDecryptionPrivateKey`, `spSigningPrivateKey`, `spSigningCertificate`, `minimumLoa` (e.g. `loa3`), `subjectAttribute` (the BSN), `authnRequestBinding` (`post`/`redirect`), `responseBinding` (`post`/`artifact`), and `artifactResolutionServiceUrl` when the response binding is `artifact`. A wizard connection may instead carry `metadataUrl` / `metadataXml`.

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /identity-providers` · `POST /identity-providers` | List / create providers |
| `GET` · `PUT` · `DELETE /identity-providers/{alias}` | Read / update / delete a provider |

See [Identity providers](identity-providers.md) for the shared flow, and the [API reference](../integration/api-reference.md) for every field.

## See also

- [Identity providers](identity-providers.md) — broker model, JIT provisioning, SLO
- [eHerkenning (NL business)](eherkenning.md) · [eIDAS (EU cross-border)](eidas.md)
- [SAML broker](saml.md) — the underlying SAML 2.0 profile
- [Users & credentials](../manage/users.md) · [Authentication flows](../authentication/flows.md)
