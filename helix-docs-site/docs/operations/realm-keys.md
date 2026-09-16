# Realm keys

Every realm signs its tokens **and its SAML assertions** with its own keys, rotates them without downtime, and can anchor key material in your KMS or HSM.

## What it is

Each realm owns an independent set of RSA signing keys and publishes the public half in its **JWKS**. Relying parties fetch that JWKS to verify the tokens Helix IAM issues, so key isolation between realms is absolute — one tenant can never verify another's tokens.

Helix IAM supports:

- **Zero-downtime rotation.** When you rotate, a fresh key becomes the active signer while the previous key stays published for verification. Tokens minted before the rotation keep validating until they expire — no failed verifications, no forced re-login.
- **One key per realm, both protocols.** The realm's active signing key backs **both** OIDC/OAuth2 token signing **and** SAML 2.0 assertion signing — so each realm is a fully isolated Identity Provider on every protocol, and a single rotation covers both. See [SAML assertion signing](#saml-assertion-signing).
- **External key material.** Signing keys can live in a KMS or HSM over **PKCS#11**, so the private key never leaves your hardware boundary.

## SAML assertion signing

When a realm acts as a **SAML 2.0 Identity Provider**, it signs assertions with a certificate derived from that realm's **active signing key** — the same key it publishes in JWKS for OIDC. This means:

- **Per-realm IdP identity.** Every realm signs SAML as itself, never with a shared, deployment-wide certificate. A relying party that trusts one realm's certificate cannot verify another realm's assertions.
- **Rotation is unified.** Rotating the realm key (below) rotates the SAML signing certificate too — there is no separate SAML key to manage, generate, or expire.
- **Published in metadata.** The realm's SAML certificate is embedded in its **IdP metadata** at `/<realm>/saml/idp/metadata` (the `<KeyDescriptor use="signing">` element). Service providers discover it from there.

!!! warning "Service providers must read live metadata — never pin the certificate"
    A SAML service provider should consume the realm's IdP **metadata URL** and re-read it, rather than hard-coding a copy of the signing certificate. When you rotate the realm key, the certificate in the metadata changes; an SP that pinned the old certificate will reject newly signed assertions. This mirrors the OIDC rule that verifiers must read the live JWKS, not a cached key.

    When onboarding an SP, prefer exchanging **metadata URLs** over static certificates — see [SAML clients](../manage/saml-clients.md).

## In the console

Open **Manage → Realms → Realm keys** to view the active key, any retained verification keys, and each key's ID and status. From here you can trigger a rotation and retire superseded keys once all tokens signed by them have expired.

!!! warning "Persist your signing keypair"
    A realm's keys must survive restarts. If the keypair lives on an ephemeral volume it will be regenerated on the next boot, instantly invalidating every issued token and every cached JWKS. Mount durable storage for the keystore, or source the key from a KMS/HSM. See the [security checklist](security.md) and [backup guide](backup.md).

## How to rotate

1. Open **Realm keys** and confirm the current active key.
2. **Rotate** — a new active key is generated and published alongside the outgoing key. The realm's SAML signing certificate changes at the same time.
3. Leave the previous key in place until the longest-lived token signed by it has expired.
4. Retire the old key.

Rotation is safe to run on a schedule as part of routine key hygiene.

!!! note "SAML consumers after a rotation"
    OIDC relying parties pick up the new key automatically from the live JWKS. SAML service providers that re-read the IdP metadata URL do too; any SP configured with a static, pinned certificate must be updated with the realm's new certificate before the old key is retired.

## Over the API

Keys live under `/admin/realms/{realm}/keys`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List the realm's keys

The `ACTIVE` key is the current signer; keys with a `rotatedAt` timestamp are retained for verification only. `publicKey` is the base64 DER of the RSA public key that also appears in the realm's JWKS.

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/keys"
```
```json
[
  {
    "keyId": "18bdfe78-5b98-4675-a4e2-19b4f18b8ca4",
    "algorithm": "RSA",
    "status": "ACTIVE",
    "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2in3SfWJTdlQ+8uqGArD…AB",
    "createdAt": 1783020171129,
    "rotatedAt": null
  }
]
```

### Rotate to a new key

Rotation mints a fresh `ACTIVE` key and marks the outgoing key retained (it keeps a `rotatedAt`). The realm's SAML signing certificate rotates at the same moment.

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/keys" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt -X POST -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/keys/rotate"
```
```json
{
  "keyId": "a1c93e40-7f22-4c8e-9b0d-2b5f6e1d4a77",
  "algorithm": "RSA",
  "status": "ACTIVE",
  "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9pQ2r0e…AB",
  "createdAt": 1783106571000,
  "rotatedAt": null
}
```

### Retire an old key

Once the longest-lived token signed by a retained key has expired, delete it by `keyId`:

```bash
# Delete — returns 204 No Content; refuse to delete the ACTIVE key
curl -s -b cookies.txt -X DELETE -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/keys/18bdfe78-5b98-4675-a4e2-19b4f18b8ca4"
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /keys` | List active + retained keys |
| `POST /keys/rotate` | Rotate to a new active key (also rotates SAML cert) |
| `DELETE /keys/{keyId}` | Retire a superseded key |

## See also

- [Backup & disaster recovery](backup.md)
- [Security hardening](security.md)
- [Realm settings](realm-settings.md)
- [Configuration](../getting-started/configuration.md)
