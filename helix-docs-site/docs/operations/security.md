# Security hardening

A production checklist to lock down a Helix IAM deployment, plus the high-assurance protocol profiles it supports.

## Production checklist

Work through this before you serve real traffic.

### Secrets & keys

!!! danger "DB_ENCRYPTION is immutable after first boot"
    Keep `DB_ENCRYPTION` strong, store it securely, back it up, and **never change it** once the system has booted. Rotating or losing it makes every encrypted column — and every database backup — unrecoverable. See [Backup & disaster recovery](backup.md).

!!! warning "Persist the signing keypair"
    Mount the signing keystore on durable storage (or source it from a KMS/HSM). An ephemeral volume regenerates keys on restart and invalidates every issued token. See [Realm keys](realm-keys.md).

### Accounts & access

- **Change the admin password** from any bootstrap default, and rotate it on a schedule.
- Keep the **`dev-open` admin bypass OFF** — it is off by default and must stay off in production.
- Apply least-privilege [admin RBAC](admin-roles.md) so each administrator holds only the permissions they need.

### Network & endpoints

- Use real **HTTPS hostnames** for `IDP_BASE_URL` and `SP_BASE_URL` so issuer, redirect and metadata URLs are correct and trusted.

```bash
IDP_BASE_URL=https://login.example.com
SP_BASE_URL=https://login.example.com
```

- **Change database and Redis credentials** from their defaults, and **do not expose PostgreSQL or Redis** to untrusted networks.
- Forward the [audit log to your SIEM](observability.md) for monitoring and incident response.

## Verify the hardening

Don't take the checklist on trust — probe the running server. These checks use anonymous endpoints (no cookie, no token); see [Authenticating to the API](../getting-started/api-authentication.md) for `$HELIX_URL` / `$REALM`.

### The admin API rejects anonymous callers

An unauthenticated call to any `/admin/**` route must return **401**, never data:

```bash
curl -s -o /dev/null -w '%{http_code}\n' "$HELIX_URL/admin/realms/$REALM/users"
```
```
401
```

Anything other than `401`/`403` here means the admin surface is reachable without a session — stop and fix your reverse proxy / network policy before serving traffic.

### Discovery advertises the expected profile

The realm's discovery document is the authoritative statement of what the issuer supports. Confirm the high-assurance building blocks are present — S256 PKCE, sender-constraint auth methods, mTLS-bound tokens, and a PAR endpoint:

```bash
curl -s "$HELIX_URL/realms/$REALM/.well-known/openid-configuration" | jq '{
  issuer,
  code_challenge_methods_supported,
  token_endpoint_auth_methods_supported,
  tls_client_certificate_bound_access_tokens,
  pushed_authorization_request_endpoint
}'
```
```json
{
  "issuer": "http://localhost:8083/realms/master",
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic", "client_secret_post", "client_secret_jwt",
    "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"
  ],
  "tls_client_certificate_bound_access_tokens": true,
  "pushed_authorization_request_endpoint": "http://localhost:8083/realms/master/oauth2/par"
}
```

Check the `issuer` is your real HTTPS hostname (from `IDP_BASE_URL`), that `code_challenge_methods_supported` is `["S256"]` (never `plain`), and that `private_key_jwt` / `tls_client_auth` are offered for high-assurance clients. See [OpenID / FAPI conformance](../compliance/conformance.md) for the full advertised feature set.

## High-assurance protocol profiles

For regulated and high-value clients, Helix IAM supports advanced, sender-constrained and bank-grade OAuth/OIDC profiles:

- **FAPI** — mutual-TLS-bound tokens, signed request objects, and JWT-secured response mode (**JARM**).
- **DPoP** — sender-constrained tokens bound to a client-held key.
- **PAR** — pushed authorization requests, so request parameters never travel through the browser.
- **CIBA** — decoupled, backchannel authentication for out-of-band approval flows.

Enable these per client when the relying party requires a high-assurance profile.

## See also

- [Realm keys](realm-keys.md)
- [Admin roles (RBAC)](admin-roles.md)
- [Backup & disaster recovery](backup.md)
- [Observability & health](observability.md)
- [Multi-factor authentication](../authentication/mfa.md)
- [Configuration](../getting-started/configuration.md)
