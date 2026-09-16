# SAML clients

A SAML relying party (service provider) is the SAML 2.0 face of an [application](applications.md) — Helix IAM acts as the SAML Identity Provider issuing assertions to it.

## What it is

SAML clients let Helix IAM federate to SAML 2.0 service providers (SPs). The IdP issues signed SAML assertions in response to SP authentication requests. Each relying party is configured per-SP with WSO2-class options:

- **Sign assertion / sign response** — independently control what gets signed.
- **Encrypt assertion** — encrypt the assertion to the SP's certificate.
- **AuthnRequest signature verification** — require and verify signed requests from the SP (POST and redirect-querystring bindings).
- **NameID format** — choose the subject identifier format (e.g. persistent, transient, email).
- **SubjectConfirmation** — Bearer subject confirmation data.
- **Multiple ACS URLs** — several Assertion Consumer Service endpoints per SP.
- **ForceAuthn / IsPassive** — force re-authentication or require silent SSO.
- **RequestedAuthnContext** — honor the requested authentication context.
- **Back-channel SLO** — Single Logout over the back channel.
- **IdP-initiated SSO** — start SSO from the IdP side.

### Metadata

You can import an SP by uploading its metadata XML or by pointing at its metadata URL, and you can export this realm's IdP metadata (and per-SP descriptors) for the SP to consume.

!!! tip
    Importing SP metadata is the fastest path to a correct configuration — it populates entityID, ACS URLs, NameID format, and signing certificates in one step.

### IdP signing certificate

Helix IAM signs each realm's SAML assertions with a certificate **derived from that realm's own signing key** — the same key it uses for OIDC. Every realm is therefore a distinct SAML Identity Provider with its own certificate; no shared, deployment-wide SAML key exists.

Give service providers the realm's **IdP metadata URL** — `/<realm>/saml/idp/metadata` — rather than a static copy of the certificate. The certificate is embedded there in the `<KeyDescriptor use="signing">` element, and it changes when you rotate the realm key.

!!! warning "Don't pin the certificate"
    Because the signing certificate rotates with the [realm key](../operations/realm-keys.md), an SP that hard-codes a copy of it will reject newly signed assertions after a rotation. Configure SPs to re-read the metadata URL. Full details are in [Realm keys → SAML assertion signing](../operations/realm-keys.md#saml-assertion-signing).

## In the console

SAML clients live under **Manage → Applications & clients → OIDC/SAML clients**, either via the parent [application](applications.md) or the SAML clients list, keyed by the SP **entityID** and shown by display name.

1. Open **Manage → Applications & clients → OIDC/SAML clients**, then **Create** a SAML client (or import metadata).
2. **Import metadata** — provide the SP's metadata XML (file) or a metadata URL to auto-fill the configuration.
3. **Configure signing & encryption** — choose whether to sign the assertion, sign the response, and/or encrypt the assertion.
4. **Set NameID & SubjectConfirmation** — pick the NameID format and confirm Bearer subject confirmation suits the SP.
5. **Add ACS URLs** — register one or more Assertion Consumer Service endpoints.
6. **Enable SLO** — configure back-channel Single Logout so logout propagates (see [Sessions](sessions.md)).
7. **Export IdP metadata** — give the SP this realm's IdP descriptor.

!!! warning
    If the SP requires signed AuthnRequests, enable AuthnRequest signature verification and register the SP's signing certificate — otherwise valid requests may be rejected or spoofed ones accepted.

## Over the API

SAML relying parties live under `/admin/realms/{realm}/saml-clients`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List relying parties

Each relying party is keyed by its `entityId`. The per-SP WSO2-class settings live in the nested `options` object (a `null` field means "inherit the realm/IdP default").

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/saml-clients"
```
```json
[
  {
    "realmId": "acme",
    "entityId": "helix-sandbox-sp",
    "assertionConsumerServiceUrl": "http://localhost:9090/saml/acs",
    "defaultAuthnContextClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    "singleLogoutServiceUrl": "http://localhost:9090/saml/slo",
    "signingCertificate": null,
    "enabled": true,
    "applicationId": "acme|helix-sandbox-sp",
    "options": {
      "signAssertion": null,
      "signResponse": null,
      "wantAuthnRequestsSigned": null,
      "encryptAssertion": null,
      "nameIdFormat": null,
      "includeAttributes": true,
      "additionalAcsUrls": [],
      "backChannelSloEnabled": null,
      "idpInitiatedSsoEnabled": null,
      "assertionLifetimeSeconds": null
    }
  }
]
```

### Register a relying party

`entityId` and `assertionConsumerServiceUrl` are required; everything else is optional and defaults are inherited when omitted.

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/saml-clients" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "entityId": "https://sp.example.com/saml/metadata",
        "assertionConsumerServiceUrl": "https://sp.example.com/saml/acs",
        "singleLogoutServiceUrl": "https://sp.example.com/saml/slo",
        "enabled": true,
        "options": { "signAssertion": true, "signResponse": false, "wantAuthnRequestsSigned": true }
      }' \
  "$HELIX_URL/admin/realms/$REALM/saml-clients"
```
```json
{
  "realmId": "acme",
  "entityId": "https://sp.example.com/saml/metadata",
  "assertionConsumerServiceUrl": "https://sp.example.com/saml/acs",
  "singleLogoutServiceUrl": "https://sp.example.com/saml/slo",
  "signingCertificate": null,
  "enabled": true,
  "applicationId": null,
  "options": { "signAssertion": true, "signResponse": false, "wantAuthnRequestsSigned": true, "includeAttributes": true }
}
```

### Import from metadata, update, or delete

```bash
# Import an SP by metadata URL (or POST the XML to /saml-clients/import)
curl -s -b cookies.txt -X POST -H "X-XSRF-TOKEN: $CSRF" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://sp.example.com/saml/metadata"}' \
  "$HELIX_URL/admin/realms/$REALM/saml-clients/import-url"

# Delete a relying party by its entityId — returns 204 No Content
curl -s -b cookies.txt -X DELETE -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/saml-clients/https%3A%2F%2Fsp.example.com%2Fsaml%2Fmetadata"
```

!!! tip "URL-encode the entityId"
    Relying parties are addressed by `entityId`, which is often a URL. URL-encode it in the path (`https://…` → `https%3A%2F%2F…`).

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /saml-clients` · `POST /saml-clients` | List / create relying parties |
| `GET` · `PUT` · `DELETE /saml-clients/{entityId}` | Read / update / delete a relying party |
| `POST /saml-clients/import` | Import SP metadata (XML) |
| `POST /saml-clients/import-url` | Import SP metadata from a URL |

See the [API reference](../integration/api-reference.md).

## See also

- [Applications](applications.md)
- [OIDC clients](oidc-clients.md)
- [Sessions](sessions.md)
- [Realm keys — SAML assertion signing](../operations/realm-keys.md#saml-assertion-signing)
- [Identity providers / federation](../federation/identity-providers.md)
