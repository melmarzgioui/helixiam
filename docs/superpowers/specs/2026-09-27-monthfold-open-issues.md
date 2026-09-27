# HelixIAM: open issues after the Monthfold production switch (next release after v1.0.0-rc.4)

> **Status after the rc.5 review (2026-09-27):** A1–A9, C1–C6 and D1–D2 are fixed and verified live;
> B1 is built. Custom domains (E1) are out of scope. Still open for rc.6:
>
> 1. **Medium. The account console signs the user out on the `queue` (PostgreSQL) session store.**
>    - Any console form that redirects ends at `/login` (for example a password change, or a wrong
>      recovery code). The same flow works on Redis.
>    - Likely cause: flash attributes contain `org.springframework.util.LinkedMultiValueMap`, which the
>      store's safe-deserialisation allowlist rejects. The failure is swallowed, so the session comes
>      back empty.
>    - Fix: allow the class, log rejected sessions, and run the console browser tests on the `queue`
>      store.
> 2. **Ship master's CodeQL fixes (`386f348`) in rc.6**, especially `79b5bf4`: the email-change link in
>    rc.5 confirms on GET, so mail scanners that prefetch links can confirm it.
> 3. **The verification email's plain-text part has no link.** It says only "Open this email in an email
>    app that shows HTML". Include the link.
> 4. **The verify-email subject uses the realm id** ("for monthfold"). Use the display name.
> 5. **The Helm chart still requires `redis.host` with `sessionStore: queue`.**
> 6. **Protocol error pages are unthemed:** an unknown `client_id`, or a bare `GET /connect/logout`,
>    shows Spring's plain error page.
> 7. **Minor:** the `inkMuted` contrast isn't checked, and the console's session list shows only the
>    current browser.

You are working in the HelixIAM repository (github.com/melmarzgioui/helixiam), a Java 21 / Spring Boot
OAuth2 / OIDC / SAML identity provider with Thymeleaf pages, PostgreSQL (Flyway), an admin REST API and
a Helm chart. Monthfold, a white-label SaaS for bookkeepers, now runs its production sign-in on rc.4.
That works only because of workarounds on Monthfold's side. This document lists everything still open,
most important first.

## How to work

- For every item:
  - write a failing test first;
  - use a **real browser** (Playwright or Selenium with Chromium in CI) for anything involving
    redirects, CSP or sign-in pages. HTTP-client tests ignore CSP and missed item 1;
  - then fix, with one commit per item.
- Keep the full suite green (including the Flyway fresh-boot and `schema.sql` paths), and check that the
  Helm chart's defaults boot on a fresh database.
- Update `CHANGES-1.0.md` (or the next changelog), marking security fixes as such.
- Don't tag a release. Report per item: cause, fix, files, tests, anything deferred.

## Reference setup (what Monthfold runs)

- Realm `monthfold`:
  - `requireMfa=true`, skip grace 0
  - access token 300 s
  - self-registration on
  - HTTP email driver
- Confidential client `web`:
  - authorization code + PKCE (S256), `client_secret_basic`
  - redirect `https://app.monthfold.com/auth/callback`
  - post-logout `https://app.monthfold.com/`
  - back-channel logout `https://app.monthfold.com/auth/backchannel-logout`
  - scopes `openid profile email`
- Service-account client `monthfold-identity`, with only `view-users` and `manage-users`.
- The relying party runs on another origin than HelixIAM (app.monthfold.com versus auth.monthfold.com).
- Build a two-origin browser test harness that mirrors this setup, and use it for the items below.

---

## A. Sign-in flow bugs (confirmed live on rc.4; Monthfold has workarounds)

### A1. CRITICAL: sign-in never returns to the app after the two-step code
**Cause:**
- Every auth page sends `Content-Security-Policy: … form-action 'self'`.
- Browsers apply `form-action` to the whole redirect chain after a form POST. So `POST /mfa/totp` →
  `302 /oauth2/authorize` → `302 https://app…/auth/callback` is blocked by Chrome.
- The user stays on the code page, and a second submit lands on `/` (404: "Endpoints are served under
  /realms/{realm}/").

**Monthfold's workaround:** Traefik replaces the CSP header, adding the app's origin to `form-action`.

**Fix:** build `form-action` per request: `'self'` plus the origins of the redirect URIs registered for
the client in the pending authorization request (and post-logout URIs on logout pages).

**Done when:** a browser test signs in with password + TOTP to a relying party on another origin, and
lands on its callback with a code.

### A2. `prompt=login` loops forever
**Cause:** `PromptAndMaxAgeAuthorizeFilter` clears the session for every `/oauth2/authorize` with
`prompt=login`, including the saved request it resumes right after a successful sign-in. The user is
sent back to `/login` endlessly.

**Monthfold's workaround:** uses `max_age=120` instead, which works.

**Fix:** once the user has re-authenticated for this request, don't force again. For example, strip
`prompt` from the saved request after the interactive login, or compare the fresh `auth_time` with when
the request was first seen.

**Done when:** a browser test with `prompt=login` shows the login once and completes to the callback.

### A3. ID tokens have no `auth_time` and no `sid`
**Why it matters:**
- OpenID Connect Core requires `auth_time` when `max_age` is requested, or when the client registers
  `require_auth_time`. Relying parties use it to verify a fresh re-authentication before destructive
  actions.
- `sid` is needed to match back-channel logout tokens to sessions.

**Monthfold's workaround:** trusts the missing `auth_time` behind an explicit flag.

**Fix:** add `auth_time` to every ID token, and include it on refresh. It must be the time of the last
interactive authentication (from `AuthTimeStamper`), not the last request. Add `sid` for the SSO session,
consistent with the logout tokens.

### A4. RP-initiated logout doesn't send back-channel logout
**Cause:** the end-session handler looks up the SSO session by `sub` instead of `sid`, so the client's
`backchannelLogoutUri` is never called.

**Fix:** look up by `sid` (from `id_token_hint`), then notify every client that took part in that
session.

### A5. Logout tokens from an admin session revoke are signed with the master realm's key
**Symptom:** relying parties that validate against the user's realm JWKS reject them.

**Fix:** sign with the key of the session's realm, with `iss` = that realm's issuer.

**Done when (A4 + A5):** a browser test signs in, then:
- signs out from the relying party, and back-channel logout arrives with a token that verifies against
  the realm JWKS (iss, aud, events, sid, iat, jti, no nonce);
- has an admin revoke the session, with the same result.

### A6. The "Create account" link on the login page is `/register` without the realm prefix
**Symptom:** it 404s.

**Fix:** build it realm-relative (`/realms/{r}/register`). Check every link in every template, and add a
test that crawls the rendered pages for non-realm links.

### A7. The registration verification email contains only a bare code, with no page to enter it
**Monthfold's workaround:** built its own page that forwards the code to `/register/verify/{code}`.

**Fix:** email a clickable link to `/realms/{r}/register/verify/{code}` and keep a code-entry page for
those who can't click. Localise the email and apply the realm's branding (see D1).

### A8. After registration or verification the user lands on `spBaseUrl` (the IdP host)
**Fix:** return to the pending authorization request when there is one. Otherwise go to a per-realm
`postRegistrationRedirectUrl`, which must be one of the realm's registered redirect origins.

**Done when:** a browser test starts at the app, registers from the login link, verifies from the
email, and ends back at the app's callback.

### A9. Logout-token replay
**Fix:**
- Set a short `exp` on logout tokens.
- Document that relying parties should reject a repeated `jti`.
- Keep `jti` unique per token.

## B. Account self-service (a gap Monthfold users hit today)

### B1. No account page for a non-master realm
Bookkeepers can't change their password, see or reset their two-step authenticator, regenerate recovery
codes, see their sessions, or change their email from a realm's own account page. Monthfold can't link
anywhere for these.

**Build:** a realm-scoped account console at `/realms/{r}/account`, themed like the other pages (see D1),
covering:
- password change (current password required)
- authenticator: re-enrol or remove, where the realm allows removal
- recovery codes: regenerate, which needs a fresh code
- active sessions: sign out others
- email change: needs re-verification, and the email stays unverified until confirmed
- data export and account deletion, where the realm allows them

Sensitive actions need a fresh authentication (`max_age`-style step-up). Every change is audited.
Support a `referrer` and `referrer_uri` (validated against the client's redirect origins) so users can
return to the app.

**Done when:** browser tests cover each action and the return link, and a user of a non-master realm can
do all of them.

## C. Packaging and administration

### C1. Multi-architecture image
**Today:** the release publishes linux/amd64 only. Monthfold's cluster moves to ARM (Hetzner cax).

**Fix:**
- Build and push `linux/amd64` and `linux/arm64` as one manifest list, keeping the cosign signature
  and SBOM attestation.
- Smoke-test that the arm64 image boots and passes `/actuator/health/readiness`.

### C2. Settable client secret via the admin API and import
**Today:** client create, update and import never accept a secret, so consumers that keep secrets in a
secrets manager must read them back after each run.

**Fix:**
- Add an optional `clientSecret` on create, update and import, with a minimum of 32 characters. Store
  it exactly like generated secrets and never return it.
- Add `POST /admin/realms/{r}/clients/{id}/secret` with `{"secret": "..."}` to set it.
- Audit the change without the value.

### C3. Admin email verification
**Fix:**
- Add an `emailVerified` field on admin user create and update.
- Add `POST /admin/realms/{r}/users/{id}/send-verification-email`.
- Make the `VERIFY_EMAIL` required action actually enforced: no tokens until the email is verified, when
  the realm requires verification.

### C4. `/actuator/health` aggregate shows DOWN without Redis (dev, and `sessionStore: queue`)
**Cause:** the reactive Redis health indicator stays active. Readiness and liveness are UP, so this is
low impact, but monitoring on the aggregate misreports.

**Fix:**
- Disable both the imperative and the reactive Redis indicators when Redis isn't the session or token
  store.
- Add a boot test that calls `/actuator/health`. The current test only checks a property in a
  MockEnvironment.

### C5. Bootstrap admin and global MFA switch
**Today:** operators must set `MFA_ENABLED=false` globally so the provisioning service can sign in as the
bootstrap admin. Per-realm `requireMfa` still works, but the global switch is confusing.

**Fix:** document the interaction. Better, provide a provisioning path that doesn't depend on disabling
MFA globally, for example a bootstrap service account with client credentials created from environment
variables on first boot.

### C6. Private-address egress guard
**Today:** delivering email through an in-cluster HTTP endpoint requires `HELIX_EGRESS_ALLOW_PRIVATE=true`
for the whole server.

**Fix:** allow an explicit allowlist of private hosts (per driver or per realm) instead of an all-or-
nothing switch.

## D. Theming (styled sign-in stops at the first page after login)

### D1. Realm and organization theming on every user-facing page and email
**Today:** `customCss` and `welcomeText` reach only `login.html` and `register/register.html`. The two-step
enrolment and code pages, recovery codes, reset, consent, required actions, magic link, flow pages and
the account console show HelixIAM's default look.

**Fix:** apply the realm or organization theme through one shared head fragment on every user-facing
template and every email. Add a test that renders every template for a themed realm, so no page can
forget the theme.

The full design is in the companion prompt `helixiam-theming-redesign-prompt.md`:
- structured, validated theme settings instead of free CSS, rendered to a cacheable `theme.css` with a
  documented variable contract
- uploaded fonts and assets
- custom CSS kept only as a locked-down escape hatch
- file-based themes
- a CSP without `'unsafe-inline'`

At minimum, fix coverage (D1) and harden the current `customCss` in this release. It's inserted raw with
`th:utext`, so:
- reject `<`, `@import`, `expression(`, `javascript:` and non-allowlisted `url(`;
- cap it at 32 KB.

### D2. Brand-panel text, favicon and languages per realm
**Today:** the login brand panel always shows HelixIAM's marketing copy, badges and "A HelixIAM
product"; the favicon is HelixIAM's; the EN/NL switcher is always shown.

**Fix:** add per-realm (and per-organization) `brandHeadline`, `brandSubhead`, `brandByline`,
`brandBadges`, `faviconUrl` and `supportedLocales`. With a single locale, hide the switcher.

## E. Features Monthfold will need next (lower priority)

1. **Custom domains per realm and organization**, deferred in 1.0: a host-to-realm/organization
   resolver, DNS TXT ownership proof, an issuer per host (or a documented issuer strategy), and a
   certificate story. Needed before Monthfold can move its white-label client portal onto HelixIAM.
2. **MFA policy per role, client or organization**, not only per realm: for example, clients using
   magic link without TOTP, and staff with TOTP.
3. **`login_hint`** on `/oauth2/authorize` to pre-fill the email.
4. **Organization hint enforcement**: an option to require membership of the hinted organization, not
   just branding.
5. **Changing an organization member's role in place**: `PUT` on the membership instead of delete and
   re-add, which returns 409 today.
6. **Webhook delivery with retries and backoff**, plus a dead-letter view, instead of best-effort.
7. **Revoke all sessions of a user** in one admin call.
8. **Realm role names in tokens**: document or make configurable the realm suffix (for example
   `user_monthfold` versus `user`).
9. **Rate limits shared across replicas** (Redis or the database), with a per-client token-endpoint
   limit for service accounts, and correct client IPs through trusted proxies.
10. **An external penetration test before 1.0 GA**, as `SECURITY-REVIEW.md` recommends.

---

## Final check

A two-origin browser end-to-end suite passes against a fresh deployment on the Helm defaults, covering:
- registration from the login link, then the email verification link, then back at the app
- sign-in with password + TOTP, landing at the app
- `prompt=login` and `max_age` re-authentication, with `auth_time` present
- RP-initiated logout and admin revoke, each with verified back-channel logout
- account console actions
- a themed realm, styled on every page and email

Both amd64 and arm64 images boot. Report per item as described at the top.
