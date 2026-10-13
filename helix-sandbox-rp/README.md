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
| `COOKIE_SECURE` | `true` when `NODE_ENV=production`, else `false` | `Secure` flag on the session cookie (`false` for plain-http local runs) |
| `TRUST_PROXY` | `false` | `true` behind a TLS-terminating proxy (needed for the `Secure` cookie) |
| `SESSION_SECRET` | *(random per process)* | session signing secret |
| `RATE_LIMIT` | `300` | requests per client IP per 15 minutes |

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

## EUDI Wallet (OpenID4VP) — experimental

The sandbox's "Sign in with EUDI Wallet" button runs the real OpenID4VP verifier flow (request
object, DCQL query, encrypted `direct_post.jwt` response, SD-JWT VC and mdoc presentation
verification) against the IdP's wallet broker. Standing in for a phone, there's a small test-wallet
CLI (`TestWalletCli`, `helix-iam-server/src/test/java`) that fetches the request object, mints a PID
and posts the presentation — **test/dev tooling only, never built into the server image or the main
jar** (it lives under `src/test/java` and runs on the test classpath).

> **DEV/TEST ONLY.** The test wallet, its CA and every key `TestWalletCli ca` writes are throwaway
> material generated for this sandbox. They prove nothing about identity in the real world and must
> never be trusted, imported, or referenced by a production deployment.

### 1. Start the server and the sandbox

```bash
# Postgres for the dev profile (matches application-dev.properties' defaults)
docker run -d --name hlx-pg -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=helixiam -p 5432:5432 postgres:16-alpine

cd helix-iam-server
mvn -q clean package -DskipTests
# HELIX_ADMIN_DEV_OPEN=true: local-dev-only, opens the admin API with no auth so the seed script
# below can provision the demo realm with a single curl pipeline — same shortcut
# helix-sandbox-rp's own OIDC provisioning uses (see above). HELIX_FEDERATION_STORE_ENABLED=true:
# admin-API-managed identity providers (this wallet connection) are off by default — turn the
# refresher on so a console/admin-API write takes effect in the running server.
SPRING_PROFILES_ACTIVE=dev HELIX_ADMIN_DEV_OPEN=true HELIX_FEDERATION_STORE_ENABLED=true \
  java -jar target/helix-iam-server-1.0.0-SNAPSHOT.jar &

cd ../helix-sandbox-rp
npm install
```

### 2. Seed the demo realm

```bash
cd ..   # repo root
e2e/wallet-demo/seed.sh
```

Idempotent — creates (or updates) a `wallet-demo` realm, imports a throwaway verifier access key,
creates the `eudi-wallet` identity provider (trust anchor = the test wallet's own PID-issuer CA,
response mode `direct_post.jwt`, encrypted, with `DB_ENCRYPTION` set — the dev profile's default
encryption key, the same posture the e2e base uses; plaintext `direct_post` is a dev-only allowance
this script does not use), and registers `helix-sandbox` as an OIDC client in that realm. It writes
`e2e/wallet-demo/out/sandbox.env` with the client credentials for step 3. See
`e2e/wallet-demo/seed.sh` for every option and why it lives under `e2e/` rather than here.

### 3. Point the sandbox at the demo realm

```bash
cd helix-sandbox-rp
source ../e2e/wallet-demo/out/sandbox.env
npm start
```

Open <http://localhost:9090/login> — the IdP's login page now offers **"Sign in with EU Digital
Identity Wallet"** below the password form.

### 4. Cross-device: scan the QR, respond with the CLI

Click the wallet button. The wallet page shows a QR code (and an "Open wallet" link — see step 5) that
really does encode the cross-device invocation URL — point a phone camera or any QR-reader app at the
screen to read it out (it is a plain inline SVG, nothing fancy). Without a phone handy, scan it from a
screenshot with any QR-decoding tool. Either way, hand the decoded URL to the CLI:

```bash
cd ../helix-iam-server
mvn -q exec:java -Dexec.classpathScope=test -Dexec.mainClass=io.helixiam.testwallet.TestWalletCli \
  -Dexec.args="respond '<invocation-url>' --format sd-jwt --dir ../e2e/wallet-demo/out/wallet-demo-ca"
```

Switch back to the browser tab — it polls `/broker/eudi-wallet/wallet/status` automatically and
signs in within a couple of seconds, landing back on the sandbox at `/claims`.

### 5. Same-device: follow the "Open wallet" link

On the same wallet page, right-click **"Open wallet"** and copy its link (a `haip-vp://` URL) instead
of scanning the QR — this is what a phone's OS would hand to the installed wallet app. Give it to the
same CLI:

```bash
mvn -q exec:java -Dexec.classpathScope=test -Dexec.mainClass=io.helixiam.testwallet.TestWalletCli \
  -Dexec.args="respond '<open-wallet-url>' --format mdoc --dir ../e2e/wallet-demo/out/wallet-demo-ca"
```

(`--format` is independent of cross- vs same-device; either flow accepts SD-JWT VC or mdoc, since the
demo realm's connection was seeded to accept both.) The CLI posts the response and prints the
`redirect_uri` the verifier returned — open that URL (same browser) to complete the sign-in, since
there's no real wallet app here to follow it for you.

### What the RP receives

Live-verified against a real running server (same-device, `--format sd-jwt`, the CLI's default
persona): the sandbox's `/claims` page shows the decoded id_token with `acr:
http://eidas.europa.eu/LoA/high` (the eIDAS-high LoA the wallet broker always asserts),
`given_name: Erika` / `family_name: Mustermann`, a fresh `sub` (one account was created on first
sign-in), and the usual `iss`/`aud`/`nonce`/`jti`/`auth_time`. `--format mdoc` was separately verified
to post and verify successfully against the same running server. A repeat sign-in with the *same*
`--administrative-number` resolves to the same account rather than creating a new one — covered by
`WalletFlowE2eTest#sameDevice_openWallet_redirectUriBringsTheBrowserBackSignedIn` and not retested by
hand here (each manual run above used a fresh random administrative number, by the CLI's default, to
avoid colliding with a previous run's account).

### Account linking

A PID's `personal_administrative_number` is what lets the wallet create an account on first sign-in
(maintainer decision: without one, the wallet cannot create an account by itself). To link a wallet to
an **already-signed-in** account instead: sign in normally (password), open the account console
(`/realms/wallet-demo/account`), find "EU Digital Identity Wallet" under its wallets section and click
**Link wallet** — this starts the same wallet page/CLI flow (`respond` works identically), except the
callback is `/account/wallet/eudi-wallet/callback` and it binds the wallet to *that* account rather
than signing in. The console then shows the provider as **Linked**.

## Notes / follow-ups

- The id_token for this flow carried no `auth_time` / `amr` / `sid` — worth wiring the
  flow-engine completion to stamp them (the password/MFA choke points already compute
  `auth_time` for SSO P2).
- The async-poll factors (QR login, push) still fetch their status endpoints with
  root-absolute paths in the page JS; only the OTP/form path was needed here, so those
  weren't touched — same `RealmPaths` fix applies if those factors are exercised under a
  realm path.
