# Helix IAM — Sandbox Relying Party

A small OIDC relying-party app to exercise **Helix IAM** end to end: login, OTP/MFA
step-up, claims inspection, token refresh, silent SSO, and single logout. It's a
transparent test harness — every token is shown decoded so you can see exactly what the
IdP issues.

Built with **Node + Express + [openid-client](https://github.com/panva/node-openid-client)**
(certified OIDC RP) + **otplib** (for generating TOTP codes in the automated test).

```
GET  /          home — signed-in state + flow steps + actions
GET  /login     authorization_code + PKCE (password → OTP → resume)
GET  /callback  code → token exchange; stores tokens in the session
GET  /claims    decoded id_token (standard vs custom) + live /userinfo + access token
GET  /refresh   refresh_token grant → fresh tokens
GET  /silent    prompt=none — silent SSO probe (login_required if no session)
GET  /stepup    prompt=login — force re-authentication
GET  /logout    RP-initiated end_session (single logout)
```

## Run

```bash
npm install
npm start            # listens on http://localhost:9090
npm test             # unit tests for the JWT/claims helpers
```

Config is env-overridable (defaults match the provisioned e2e sandbox):

| env | default | meaning |
|---|---|---|
| `HELIX_ISSUER` | `http://localhost:8083/realms/master` | IdP issuer (OIDC discovery) |
| `HELIX_CLIENT_ID` | `helix-sandbox` | registered client id |
| `HELIX_CLIENT_SECRET` | *(the e2e secret)* | confidential client secret |
| `HELIX_REDIRECT_URI` | `http://localhost:9090/callback` | must match the registered redirect |
| `HELIX_POST_LOGOUT` | `http://localhost:9090/` | post-logout redirect |
| `HELIX_SCOPE` | `openid profile email` | requested scopes |
| `PORT` | `9090` | |

## How the IdP side was provisioned (e2e `master` realm)

The admin API is open in dev (`HELIX_ADMIN_DEV_OPEN=true`), reachable at
`http://localhost:8083/admin/realms/master/**`:

1. **Client** — `POST /admin/realms/master/clients` → confidential `helix-sandbox`
   (`client_secret_basic`, redirect `:9090/callback`, scopes `openid profile email`).
2. **OTP scoping** — created an auth flow `sandbox-otp` (one unconditional `otp` REQUIRED
   step) and bound it to **only** the `helix-sandbox` client via `authFlowAlias`, so OTP
   applies to this client alone — `admin`/the dashboard stay password-only.
3. **Test user** — `POST /admin/realms/master/users` → `sandbox-user` / `Sandbox123!`.
4. **TOTP secret** — the j256 verifier uses SHA1/6-digit/30s base32 (matches
   `otplib.authenticator`). The secret is encrypted at rest (AES-256-GCM via the
   subscriber's `AttributeEncryption`, key = `DB_ENCRYPTION`), so it was provisioned by
   generating a base32 secret, GCM-encrypting it the same way (`base64(iv‖ct‖tag)`), and
   writing it to `user_credentials.mfa_secret` + `mfa_enabled=true`.

## What the live run proved

Driven via Playwright against the e2e stack:

- **Login** — authorization_code + PKCE, password step.
- **OTP step-up** — TOTP challenge, code accepted, session promoted.
- **Resume** — login resumed the originating `/oauth2/authorize` back to the RP.
- **Claims** — id_token (`iss/sub/aud/azp/email/preferred_username/nonce/jti`), the custom
  `realm_access` claim, and a live `/userinfo` response.
- **Refresh** — refresh_token grant rotated the access token.
- **Silent SSO** — `prompt=none` returned a code with no prompt while the session was live.
- **Single logout** — `end_session` destroyed the IdP session; a subsequent `prompt=none`
  returned `login_required`.

## Bug this harness surfaced (and the fix shipped)

Under realm-path routing (`/realms/{realm}/...`), the flow-engine challenge templates
(`flow/otp-form.html` et al.) hardcoded `action="/flow"` and `FlowController` issued
`redirect:/flow` / `redirect:/login` — all **root-absolute**, dropping the `/realms/{realm}`
prefix, so submitting any post-password factor (OTP, WebAuthn, push, recovery-code, …)
404'd. Fixed in the publisher by adding `security/realm/RealmPaths` (TDD) and realm-prefixing
both the `FlowController` redirects and the rendered form action (`${flowAction}`).

## SAML2 (same IdP, second protocol)

The sandbox is also a **SAML 2.0 Service Provider** against Helix's SAML IdP role.

```
GET  /saml/login     AuthnRequest → IdP SSO (HTTP-Redirect binding)
POST /saml/acs       Assertion Consumer Service — validates the signed assertion
GET  /saml/metadata  SP metadata (for import)
GET  /saml/logout    RP-initiated SAML Single Logout
GET|POST /saml/slo    receives the IdP LogoutResponse
```

The SP consumes the IdP metadata (`HELIX_SAML_IDP_METADATA`) to discover the entityID, SSO/SLO
endpoints and signing certificate, then validates the assertion signature against it. SAML config is
env-overridable: `HELIX_SAML_SP_ENTITY_ID`, `HELIX_SAML_ACS`, `HELIX_SAML_SLO`, `HELIX_SAML_IDP_METADATA`.

**Relying-party registration is dynamic** — the SP is registered with the IdP via the admin API or the
console's **SAML clients** screen (`POST /admin/realms/{realm}/saml-clients`), persisted per realm and
loaded by the IdP at request time. Nothing in a properties file; no rebuild to onboard an SP.

Live-verified (Playwright): `/saml/login` → IdP AuthnRequest → password → **OTP** (the realm browser
flow applies MFA to this user) → signed assertion auto-POSTed to `/saml/acs` → validated → NameID +
`mail` attribute shown; then RP-initiated SLO clears the session at the IdP.

## Notes / follow-ups

- The id_token for this flow carried no `auth_time` / `amr` / `sid` — worth wiring the
  flow-engine completion to stamp them (the password/MFA choke points already compute
  `auth_time` for SSO P2).
- The async-poll factors (QR login, push) still fetch their status endpoints with
  root-absolute paths in the page JS; only the OTP/form path was needed here, so those
  weren't touched — same `RealmPaths` fix applies if those factors are exercised under a
  realm path.
