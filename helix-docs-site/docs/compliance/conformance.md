# OpenID / FAPI conformance (PROD-12)

Certification is an **external process** run against the OpenID Foundation's conformance suite. This
document captures what to run and the readiness state so the certification can be kicked off; the
formal mark is awarded by the OpenID Foundation, not by this repository.

## What we certify

| Profile | Helix capability | Status |
|---------|------------------|--------|
| OpenID Connect — Basic / Config / Dynamic | authorization_code, discovery, dynamic client registration | implemented |
| OIDC RP-initiated Logout / Back-channel / Front-channel | `/connect/logout`, logout tokens, SLO | implemented |
| FAPI 2.0 Security Profile | mTLS-bound tokens (RFC 8705), PAR (RFC 9126), `iss` in response | implemented |
| FAPI — Request Object / JARM | signed request objects (RFC 9101), JWT-secured response mode | implemented |
| OAuth 2.0 DPoP | sender-constrained tokens (RFC 9449) | implemented |
| CIBA | backchannel authentication (pairs with device push) | implemented |

## Running the conformance suite

1. Deploy a dedicated conformance realm (isolated; throwaway clients).
2. Use the hosted suite at <https://www.certification.openid.net/> (or self-host
   `openid-certification/conformance-suite` via its docker-compose).
3. Configure the test plan with the realm's discovery URL:
   `https://<host>/realms/<realm>/.well-known/openid-configuration`.
4. Provide a confidential test client (and, for FAPI, an mTLS client cert + a signing key for request
   objects). Register them via the admin API / console.
5. Run the plan, export the results, and submit them with the certification form + fee.

## Inspect what the issuer advertises

The discovery document is the ground truth the conformance suite reads. It is **anonymous** — no session or token — so you can inspect any realm's advertised capabilities directly. See [Authenticating to the API](../getting-started/api-authentication.md) for `$HELIX_URL` / `$REALM`.

```bash
curl -s "$HELIX_URL/realms/$REALM/.well-known/openid-configuration" | jq '{
  grant_types_supported,
  response_types_supported,
  code_challenge_methods_supported,
  token_endpoint_auth_methods_supported,
  tls_client_certificate_bound_access_tokens,
  dpop_signing_alg_values_supported,
  pushed_authorization_request_endpoint
}'
```
```json
{
  "grant_types_supported": [
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "response_types_supported": ["code"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic", "client_secret_post", "client_secret_jwt",
    "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"
  ],
  "tls_client_certificate_bound_access_tokens": true,
  "dpop_signing_alg_values_supported": [
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512"
  ],
  "pushed_authorization_request_endpoint": "http://localhost:8083/realms/master/oauth2/par"
}
```

These live values map straight onto the certified profiles: `token-exchange` and `device_code` grants, **S256-only** PKCE, FAPI's `private_key_jwt` / `tls_client_auth` and `tls_client_certificate_bound_access_tokens: true` (RFC 8705), DPoP signing algorithms (RFC 9449), and the PAR endpoint (RFC 9126). Point the conformance test plan at the same URL.

## Readiness checklist

- [x] Discovery document advertises the supported grant types, response modes, PKCE methods, and the
      `tls_client_certificate_bound_access_tokens` / DPoP / PAR metadata.
- [x] JWKS endpoint serves per-realm signing keys; rotation supported.
- [x] FAPI client policies enforce PAR + mTLS/`private_key_jwt` for high-assurance clients.
- [ ] Conformance realm + test clients provisioned in the target environment (per-run).
- [ ] Test plan executed and results exported (per-run).
- [ ] Certification submitted to the OpenID Foundation (external; fee + review).

The implementation is conformance-ready; the remaining items are operational (provision + run + submit).
