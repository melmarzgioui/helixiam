# CHANGES — road to a credible 1.0

Running log for branch **`overhaul/1.0-gaps`**. Every finding, fix, commit, deferred item and open
question. Newest first within each phase.

## Next release (after `v1.0.0-rc.4`)

Open issues found when Monthfold moved its production sign-in to rc.4
(`docs/superpowers/specs/2026-09-27-monthfold-open-issues.md`).

> **SECURITY ADVISORY — second factor bypassed (HIGH, fixed in `cf06160` and `3e5275e`).** In a realm that requires a
> second factor (`requireMfa`), rc.1–rc.4 issued authorization codes **and SAML assertions** to browser sessions that
> had not completed one: a federated (identity-provider) sign-in, and a session that signed in with a password before
> the realm required a second factor (OIDC also with `prompt=none`; SAML SP-initiated, IdP-initiated and `IsPassive`).
> The gate in front of `/oauth2/authorize` read the sign-in from a place that is still empty at its position, so it
> never fired, and the SAML IdP had no gate at all. Both now send such sessions to enrolment or the code page and
> resume afterwards; `prompt=none` gets `interaction_required` and SAML `IsPassive` a `NoPassive` status at the SP's
> ACS. Browser tests cover every sign-in path. Password, magic-link, `prompt=login` and SAML `ForceAuthn` sign-ins were
> not affected: they are gated when the first factor completes.
>
> **SECURITY — consent Cancel approved (fixed in `5030623`).** The consent page's Cancel button submitted the approval
> form with every scope checked, so consent was recorded and tokens issued (code and device flows). Cancel now denies.

- **A2** — `296aa4e` `prompt=login` no longer loops. The prompt filter used to clear the session again on the saved
  authorize request that the login resumes, so the user was sent back to `/login` forever. It now notes when the
  prompt was first seen and lets the resumed request through once the session's `auth_time` is at or after that moment.
- **A3** — `2b2d99a` ID tokens carry `auth_time` (time of the last interactive sign-in, epoch seconds) and `sid` (the
  browser SSO session), on the code exchange and on every refresh. The code is bound to the session when it is issued,
  so refresh and silent SSO don't move `auth_time`, and `sid` is the same for every client of one sign-in.
- **A4** — `6792b05` RP-initiated logout ends the SSO session named by the `id_token_hint`'s `sid` (it looked it up by
  `sub`, found nothing, and sent no back-channel logout) and notifies every client of that session. It no longer
  touches the user's other browser sessions. All authorizations of the session are removed, including older ones of a
  client that signed in twice in it.
- **A5 — security** — `4ef14f2` Back-channel logout tokens are signed with the key of the session's realm and carry
  its issuer. A session revoked by an admin (an `/admin/**` request) used to be announced with tokens signed by the
  master realm's key, which every relying party validating against its realm JWKS rejected, so the RP never logged out.
- **A9 — security** — `2414be0` Logout tokens expire after 120 s (`HELIX_LOGOUT_TOKEN_TTL_SECONDS`, 1–600) and every
  token has its own `jti`. `docs/oidc-sessions-and-logout.md` tells relying parties how to validate a logout token,
  including rejecting a `jti` they have already seen until its `exp`.
- **security** — `6b22406` Ending an SSO session (RP logout, admin revoke, account self-service) ends only that
  session's browser login, found through the HTTP session recorded when its codes were issued, in whichever session
  store is active. Before, the Redis default ended no browser session at all, so a revoked user's browser silently
  got new codes. The queue store ended every browser session of the user. The by-user deletion remains only for
  sessions from before `sid` existed.
- `98adc78` Discovery lists `claims_supported` (including `auth_time` and `sid`) and advertises
  `backchannel_logout_supported` and `backchannel_logout_session_supported`.

- **C2** — A client secret can be set by the caller: optional `clientSecret` on client create, update and realm import (`clientSecret` or `secret`, `${ENV}` placeholders resolved), and `POST /admin/realms/{r}/clients/{id}/secret` with `{"secret": "..."}` (204; without a secret it still rotates and returns the generated one once). 32–120 printable ASCII characters; stored exactly like a generated secret (AES-GCM at rest); never returned, logged or exported; audited as `CLIENT_SECRET_ROTATE` without the value. A secret containing the letters `noop` is no longer mistaken for an already-prefixed one (it failed client authentication).
- **C3 — security** — Email verification is enforced. Admin user create/update accept `emailVerified` (and the user DTO returns it); `POST /admin/realms/{r}/users/{id}/send-verification-email` emails a single-use link (`/realms/{r}/verify-email?token=…`, 24 h, stored as SHA-256 with the address it was sent to, rate limited per user; host from `idp.base.url`), through the realm's email provider (SMTP or HTTP driver, editable `verify-email` template) or the global SMTP fallback. New realm setting `PUT /admin/realms/{r}/settings/verify-email {"enabled": true}` (Flyway V40): a user with an unverified address gets no tokens (`access_denied` on every grant, including refresh) and a password sign-in is held on a "verify your email" page (auto-send, resend, continue) until the link is opened. The `VERIFY_EMAIL` required action can no longer be acknowledged away; it is cleared only by verifying. Realms seeded before a message template existed now get the missing default templates.
- **C4** — `/actuator/health` is UP without Redis when Redis is not used (dev profile, `sessionStore: queue`). Cause: the environment post-processor that switches the Redis health indicators off was registered in `META-INF/spring/…EnvironmentPostProcessor.imports`, which Spring Boot 3 never reads, so it never ran (rc.3 #6 only tested it on a mock environment). It is now registered in `META-INF/spring.factories`, turns off both the imperative and the reactive Redis indicator (`management.health.redis.enabled=false`) whenever Redis is neither the session store nor the token store (`HELIX_TOKEN_STORE=redis` keeps it), and never overrides an explicit setting. Real boot tests call `/actuator/health` with Redis unreachable, for `HELIX_SESSION_STORE=queue` and for the dev profile.
- **C5** — Provisioning no longer needs MFA switched off globally. `HELIX_BOOTSTRAP_CLIENT_ID` plus `HELIX_BOOTSTRAP_CLIENT_SECRET_FILE` (or `HELIX_BOOTSTRAP_CLIENT_SECRET`; 32–120 characters) create, on first boot and only once, a master-realm `client_credentials` service account with the master `admin` role; it administers every realm through the admin API with a bearer token while `MFA_ENABLED` stays on. Helm: `secrets.bootstrapClientId` + `secrets.bootstrapClientSecretKey` (mounted as a file, `0440`), and `config.mfaEnabled` (`MFA_ENABLED`, default `true`). README and chart README document how the global switch and per-realm `requireMfa` interact.
- **C6 — security** — Private-address egress is an explicit allowlist instead of all-or-nothing. `helix.egress.allowed-private-hosts` (`HELIX_EGRESS_ALLOWED_PRIVATE_HOSTS`; Helm `config.egressAllowedPrivateHosts`) lists exact host names or IP literals, optionally with a port (`mailer.mail.svc.cluster.local`, `sms-gateway.internal:8080`). Only a URL whose host is a listed *name* (on the listed port, 80/443 by default) may reach private, site-local, unique-local, CGNAT or loopback addresses; another name resolving to the same private address, or the address itself, is still refused; link-local/cloud-metadata, multicast and wildcard addresses stay blocked even for listed hosts. It applies to every outbound call through the SSRF guard, including the email/SMS HTTP drivers, and is global rather than per realm because realm admins configure those URLs. `HELIX_EGRESS_ALLOW_PRIVATE=true` still works but is deprecated (startup warning; flagged by the production-readiness check).
- **Structured theming — security** — `ded6b34`, `7072132`, `e78bff3`, `7d6c83b` Realms are themed through a
  validated theme model instead of raw CSS: colours (14 roles, light and dark, dark derived when omitted, WCAG AA
  contrast enforced), built-in or uploaded fonts, shape, logo/favicon/brand image, split or centered layout, localised
  texts, legal links and supported locales, with an optional organization layer on top (`GET/PUT
  /admin/realms/{r}/theme`, `…/organizations/{id}/theme`, `POST …/theme/preview`, `…/theme/assets` for woff2, svg,
  png and webp uploads; `manage-realm` / `manage-organizations`, audited, strict input). Every user-facing page and
  email uses it through one shared fragment and `/realms/{r}/theme.css`, which carries the versioned `--hx-*` variables
  contract (v1, stable across minor versions). **Security:** realm-admin CSS can no longer be injected into pages:
  the old `customCss` was inserted raw with `th:utext` (script and input-exfiltration risk); it is now a restricted
  escape hatch served inside `theme.css` (no `<`, escapes, comments, `@import` or foreign `url()`), and stored CSS that
  fails the rules is not served. The page CSP drops `style-src 'unsafe-inline'`, and `img-src` is limited to `'self'
  data:` plus per-realm allowed origins instead of any `https:` host. Legacy branding is migrated (Flyway V19–V22,
  V70); invalid legacy CSS is dropped with a log; the realm-settings and organization-branding fields keep working,
  deprecated. Rollback to 1.0 shows no branding (the legacy columns are cleared). `supportedLocales` now decides the
  page language. See `docs/THEMING.md`.
- **File themes (structured theming, spec §5)** — Operators can keep themes in version control: set
  `helix.theme.directory` (`HELIX_THEME_DIRECTORY`; Helm `themes.enabled` with a ConfigMap or an existing volume) to a
  directory of `{name}/theme.json` (same schema and validation as `PUT /admin/realms/{r}/theme`), an optional
  `fonts.json` and `assets/` (fonts and images checked with the same type, size, count and SVG rules as uploads;
  referenced as `assets/<file>`). A realm selects one with `PUT /admin/realms/{r}/theme/base {"themeName": ...}`
  (`manage-realm`, audited as `THEME_UPDATE`); it becomes the layer between the default and the realm's database theme,
  so database fields override file values. Themes are validated at startup and whenever the files change (polled
  every `helix.theme.reload-interval-seconds`, default 30); an invalid theme is refused with an error log listing
  every problem, and realms that select it fall back to their database theme or the default. File assets are served
  under the selecting realm's own `/realms/{r}/theme/assets/` path with the same headers as uploads. Deleting an
  uploaded asset now also checks base layers, and a font family the file theme provides keeps resolving. Schema:
  `realm_theme.theme_name` (Flyway `V70`, and `schema.sql`).
- **E5** — `PUT /admin/realms/{r}/organizations/{org}/members/{user}` changes a member's role in place: 201 with the
  membership when it adds the member, 200 when it changes (or keeps) the role; a body without `role` keeps the current
  role instead of resetting it to `member`. An organization or user outside the path realm is now a 404 (it was a 409,
  which read as "already a member"). Roles are validated (at most 64 characters: letters, digits, `.`, `_`, `:`, `-`;
  400 `fieldErrors.role`). Audited as `ORGANIZATION_MEMBER_PUT` (detail: added or role change) and
  `ORGANIZATION_MEMBER_REMOVE`.
- **E7** — `DELETE /admin/realms/{r}/users/{userId}/sessions` revokes every session of a user in one call: browser
  sessions, every SSO session (back-channel logout with the session's `sid`, realm-signed, to each of its clients),
  and every remaining authorization with its refresh token (those clients get a `sub`-only logout token). Answers the
  counts; 404 for a user outside the path realm; needs `manage-users`; audited as `USER_SESSIONS_REVOKE`.
  See `docs/oidc-sessions-and-logout.md`.
- **E8** — Documented how role names appear in tokens (`docs/role-names-in-tokens.md`): a user's realm roles are
  `<role>_<realm>` in `realm_access.roles` (for example `user_monthfold`), service-account and agent roles are plain.
  The suffix is not made configurable per realm in this release; the page gives the reasons (delegation and mapper
  consumers depend on today's strings, the realm-settings change is cross-cutting, and RPs need a migration path) and
  the recommended follow-up. `RealmRoleNamesInTokensE2eTest` pins the documented behaviour.
- **Delegation roles — security/correctness fix** — The RFC 8693 on-behalf-of exchange
  (`/realms/{r}/agent/delegation/token`) intersected the user token's realm roles (`<role>_<realm>`) with the agent's
  roles (plain names, as the console and admin API configure them), so the delegated token never carried a realm
  role outside setups that configured agent roles in the token form. It failed closed (no extra rights), but agents
  acting for users could not use their granted roles. Both sides are now compared on the plain role name; only tokens
  issued for a user are un-suffixed, so a plain role ending in `_<realm>` is never read as another role. The token
  output is unchanged (`<role>_<realm>`), and a requested `scope` may name a role in either form. Agents configured
  with the token form as a workaround (`accountant_monthfold`) must be changed to the plain name (`accountant`).
  `AgentDelegationRolesE2eTest` reproduces it; `docs/role-names-in-tokens.md` has a Delegation section.
- **A1 — security** — `4379d35` Sign-in returns to the app after the password or two-step code. Every sign-in page sent
  `form-action 'self'`, and browsers apply it to the whole redirect chain after a form POST, so `POST /mfa/totp` →
  `/oauth2/authorize` → the app's callback on another origin was blocked. The page CSP now adds, per request, only the
  origins of the redirect URIs registered for the client of the pending authorization request (or the consent page's
  `client_id`), and the post-logout origins on the end-session endpoint; unsafe schemes and anything that is not a
  source expression are dropped. Workarounds that rewrite the CSP at the proxy can be removed.
- **A6** — `a594bc5` Every link, form, script and poll URL of the sign-in pages is under `/realms/{realm}/` (scripts were
  linked at `/js/…`, and the QR and push pages polled `/qr/…` and `/push/…`, which 404). A template test fails on any URL
  outside the realm; a browser test crawls every page reachable from the login page. The stylesheet's fonts stay at the
  shared `/css/font(s)/` (a relative URL would be cached with the first realm's path by the content-versioning chain).
- **A7** — `ea17fe1` The registration email has a button to `/realms/{r}/register/verify/{code}` (on `IDP_BASE_URL`,
  never the request host), the code, and a link to the new code page `/realms/{r}/register/verify`. It is in the language
  the user registered in and carries the realm (or organization) brand, through the realm's email provider. The reset
  email links to `/reset/password/{code}`. An unknown or used code shows an error (it used to say "verified").
- **A8** — `762bc58` After registration or verification the user goes back to the pending sign-in (the login page says
  the address is verified and is pre-filled); without one, to the realm's new `postRegistrationRedirectUrl`
  (`GET/PUT /admin/realms/{r}/settings/registration`, Flyway V50), which must be on one of the realm's registered
  redirect origins; else to the realm's login page. Never to `SP_BASE_URL`.
- **E3** — `9d5fa0f` `login_hint` on `/oauth2/authorize` pre-fills the email field.
- **E4** — `86fcc7b` An organization can set `requireMembership` (organization API and realm export/import, Flyway
  V51). When it is hinted (`organization=`) and the signed-in user is not a member, the client gets
  `error=access_denied`; the refusal is audited. Relying parties still check the `organizations` claim, since a user can
  drop the hint.
- **Theming, emails** — `e78bff3` Verification, reset, magic-link and code emails use the realm or organization theme:
  logo (an uploaded asset on `IDP_BASE_URL`), light palette, footer text in the user's language and the legal links.
- Sign-in pages: `55c75cf` after a failed sign-in the username is filled in again (kept in the session, not the URL);
  `f55fe32` the register password-mismatch alert is under the title, in view on a phone; `a79a563` the maintenance
  page is a localised card page; `e382287` no key icon on "Save password"; `a5119b9` link buttons keep their text colour.
- **B1** — `feb4c71`…`21fe41c` Every realm has an account console at `/realms/{realm}/account`, themed like the sign-in
  pages (`/me` redirects to it). A user of any realm can change their password (current password required, realm
  policy and history apply), set up or move to a new authenticator app, remove it where the realm allows it and does not
  require two-step verification, get new recovery codes (needs a current code), see where they are signed in and sign
  out everywhere else, change their email address (unverified until the link sent to the new address is opened; the
  old address is told), and, where the realm allows it, download their data or delete their account.
  - Sensitive actions need a sign-in at most `helix.account.step-up-max-age-seconds` (default 300) old, else the
    console asks for the password (and a code, when an authenticator is set up) again; that stamps a new `auth_time`.
  - Every change is an `AUTHN` audit event (`ACCOUNT_*`); attempts are rate limited per user; a wrong password or code
    counts toward the account lockout. Every form post needs the CSRF token.
  - `?referrer=<client_id>&referrer_uri=<url>` shows "Back to &lt;app&gt;" when the URL is on the origin of one of the
    client's redirect URIs; it is only ever a link.
  - "Sign out everywhere else" and account deletion end the other browser sessions in any session store
    (`user_credentials.sessions_revoked_at`) and send back-channel logout to their applications.
  - New realm settings `GET/PUT /admin/realms/{realm}/settings/account-console` (`allowAuthenticatorRemoval` and
    `allowDataExport` default on, `allowAccountDeletion` default off), also in the realm export/import as
    `accountConsole`. Flyway V60–V62.
  - **security** — the account API follows the same rules: removing TOTP or recovery codes and the data export are
    refused where the realm does not allow them; new recovery codes need a code or a fresh sign-in; an email address
    changed through `PUT /account/profile` also gets the confirmation link.

## Code scanning and dependencies (after `v1.0.0-rc.4`)

First CodeQL, Trivy and Dependabot results on `master` (the workflows had been listening on `main`).

> **SECURITY ADVISORY — admin rights through a role name (HIGH, fixed in `f063eac` + `aadb9ef`).** Admin
> authorities are `admin_<realmId>` and realm ids may contain `_`. In rc.1–rc.4 an admin of realm `acme` could create
> a role `admin_prod`, whose authority `admin_prod_acme` is the same string as "admin of realm `prod_acme`", and grant
> it to any user. Role names starting with `admin_` are now refused (API and import), and such a role already in the
> database grants no authority.

- **security** — `b041f65` Workload-identity exchange: the issuer discovery fetch (credential without `jwksUri`) goes through the SSRF guard, like the JWKS fetch already did.
- **security** — `e387510` A generated bootstrap admin password is never logged: it is written 0600 to `helix.admin.password-file` (default `<tmp>/helixiam-admin-password`) and only the path is logged; if the file cannot be written no admin is created and the log says to set `HELIX_ADMIN_PASSWORD`. The SSRF guard logs only `scheme://host[:port]`, never credentials, path or query.
- `dc41bc6` The remembered-device cookie is `Secure` according to `helix.security.cookie-secure` (not the request scheme); `6dc303d` SCIM paging with a huge `count` no longer overflows into a 500; `aadb9ef` the Prometheus endpoint is authenticated unless `helix.actuator.prometheus-anonymous=true` (the in-code default said `true`).
- `9bb64ac` Log injection: user-controlled values in log lines are passed through `LogSafe.sanitize` (line breaks and control characters → `_`), and the console/audit layouts encode CR/LF (`%enc{%m}{CRLF}`).
- Dependencies (no framework major): Spring Security 6.5.11, pgjdbc 42.7.12, BouncyCastle 1.86, OpenSAML 5.2.3, webauthn4j 0.31.10 and the rest of Dependabot's Maven minor/patch group (#13); grpc 1.83.2 and `golang.org/x/*` in the Terraform provider; express 4.22.3 and patched transitive packages in the sandbox RP.
- Images and manifests: the console image runs as the non-root `nginx` user with a HEALTHCHECK, on nginx 1.29 and a Node 22 build stage (Node 20 is end of life); the release-check Postgres/Redis manifest runs non-root with a read-only root filesystem.
- Sandbox RP: rate limiting, session regeneration at login, HttpOnly/SameSite cookies (`Secure` in production or with `COOKIE_SECURE=true`), CSRF tokens on its own forms, session secret from `SESSION_SECRET`. MCP demo: every request's bearer token is verified (RS256, `exp`, `nbf`).
- CI: all pinned actions updated together (CodeQL action v4, checkout v7, sbom-action 0.24.2). Framework majors (Spring Boot 4, Security 7, Flyway 13, React 19, Vite 8, Storybook 10, Express 5, …) are ignored by Dependabot and listed in ROADMAP.md as planned post-1.0 upgrades.
- Release images are multi-arch: `linux/amd64` and `linux/arm64` under one tag, signed per architecture (`cosign sign --recursive`). The Java build stage runs natively (`--platform=$BUILDPLATFORM`) and only the runtime layer is built per architecture; CI builds both architectures on every push.
- Findings not fixed in code, with reasons: `helix-iam-server/CODEQL-TRIAGE.md` (false positives) and `SECURITY-TRIAGE.md`.

## Review of rc.3 (after `v1.0.0-rc.3`)

> **SECURITY ADVISORY — cross-realm admin takeover (HIGH, fixed in `e4dcb9c`).** In rc.1–rc.3 several admin
> operations looked objects up by id without checking the realm in the URL. An admin of one realm could reset
> another realm's user's password, remove her TOTP and sign in as her, and grant the master realm's `admin` role to
> their own user (admin of every realm). Federated login and LDAP sync could also attach to a user of another realm
> by email. Upgrade; Flyway V16 removes any role grant whose user is not a member of the role's realm.

- **#1 — security** — `e4dcb9c` Every by-id admin operation is scoped to the path realm (users, role grants, groups, organizations, client-scope claims, realm keys, webhooks, SCIM targets, workload identities, agents, application references, push tokens); federated/LDAP user matching stays within the realm and JIT users are linked to it; V16 cleans up cross-realm role grants. `2f52bf2` The `organizations` claim only lists the token realm's organizations.
- **#2** — `c295bab` A client without its own token lifetime uses the realm's access/refresh token lifetime.
- **#3** — `e421a80` Per-client sub-resources (mappers, roles, authz, allowed resources, token-exchange policy) accept the internal client id; an unknown client is a 404.
- **#4** — `7055c8b` Duplicate email → 409 (no DB detail); a changed email is unverified; tokens carry `email_verified`.
- **#5** — `792537d` Re-importing a realm's own export succeeds; an import stops when the realm cannot be written; invalid realm ids → 400; plain failure reasons.
- **#6** — `aaa79c0` With PostgreSQL sessions the Redis health indicator is off, so `/actuator/health` is UP without Redis.
- **#7 — security** — `e786c6d` At most 5 wrong second-factor codes per sign-in (then the password is needed again); wrong codes count toward the realm lockout; `/mfa` is rate limited per IP.
- **security** — `757ca11` Usernames and emails are unique per realm (V17 backfills each user's home realm); password sign-in, reset, magic link and federation look users up within the realm, so a user of one realm can no longer sign in at another realm's login page; self-registered users now belong to their realm. V18 adds the missing `notification_code` table (email verification and password reset codes were never stored).
- **security** — `2bb9d07` SAML metadata import by URL goes through the SSRF guard (https, public addresses only, redirects re-checked, 1 MB cap); the guard also blocks 0.0.0.0/8 and 100.64.0.0/10.

## 1.0 release blockers (branch `fix/1.0-blockers`, after `v1.0.0-rc.2`)

> **SECURITY ADVISORY — claim injection (item 1, critical).** In rc.1 and rc.2 a signed-in user could set
> their own profile attributes (`PUT /realms/{realm}/account/profile`) and the token customizer copied the
> whole profile into tokens, so `attributes.sub=<another user's id>` (or `iss`, `aud`, roles) produced
> validly signed tokens, userinfo and introspection for the other user. Fixed in `8b632d2`. Upgrade; review
> `user_attributes` for reserved names (`sub`, `iss`, `aud`, `roles`, …) set by users before the upgrade.

- **1 — security** — `8b632d2` Profile attributes no longer reach tokens wholesale; reserved claims can never come from attributes or mappers (mapper save 400); users may only edit admin-allowlisted attributes (`/admin/realms/{r}/settings/self-editable-attributes`, empty by default).
- **2** — `d1ca907` Admin-created/imported clients are bound to their realm (`realm_id`); `UNIQUE(client_id, realm_id)` on both schema paths; by-id client admin calls can no longer reach another realm's client (secret read/rotate); Flyway boots an empty database (V10 seed) and is the default in the app, image and Helm chart.
- **3** — `d266e34` Permission types parsed case-insensitively into `RESOURCE`/`SCOPE`; unknown types refused on save (400) and import, denied at evaluation; a `scope` permission grants only its scope.
- **4** — `2baaff9` Admin API accepts service-account bearer tokens (client_credentials only, revocation-aware, realm RBAC, no CSRF for bearer); `44644f6` master-realm admins administer every realm, so realms can be provisioned over the API.
- **5** — `448b010` Token exchange honours `audience`/`resource` (`invalid_target` for unknown targets), enforces the target client's exchange allowlist (`/admin/realms/{r}/clients/{id}/token-exchange`), adds `act`, keeps organization claims.
- **6** — `043fcbe` TOTP: secret generated per enrolment and confirmed with a first code; realm-prefixed MFA forms; `requireMfa` enforced before any code is issued (all login paths); skip grace per realm, off by default (`/admin/realms/{r}/settings/mfa`); ±30 s window with replay protection; recovery codes usable at sign-in and regenerable (`POST /account/mfa/recovery-codes`), no broker; otpauth issuer/label = realm name.
- **6 — magic link** — `2f16131` Passwordless sign-in by emailed link, opt-in per realm (`/admin/realms/{r}/settings/magic-link`): hashed single-use links, 15-minute expiry, rate limited per email and IP, identical answer for unknown addresses, confirmation step against link prefetching, TOTP still enforced; `203674b` (security, pre-release) the link's host comes from `idp.base.url`, never from the request (`Host`/`X-Forwarded-Host` injection).
- **email** — `7075efb` Every HTML email uses one branded layout (organization in context, else realm, else HelixIAM; button for links, Outlook/Gmail/phone-safe); template values are now HTML-escaped (a user's name or claims could previously inject markup into emails); the console preview shows exactly what is sent.
- **7 — organization branding** — `b120059` Display name, logo (https) and colour (#RRGGBB) per organization via `/admin/realms/{r}/organizations/{id}/branding`, strictly validated; an `organization` authorize hint brands the login, MFA and consent pages.
- **7 — custom domains: deferred past 1.0** (decision) — verified per-organization hosts (DNS TXT proof, per-host issuer, unknown host 404) need their own design and security review.
- **8** — `3710b0c` KubeDNA/kubeiam names removed (seed client `kubedna-cli` → `helix-cli` via Flyway V13; Terraform module/registry `melmarzgioui/helix`); the demo client `oidc-client`/`secret` is no longer seeded and is disabled on upgrade; `/error` permitted so server errors are `500` with a `correlationId`; realm import reports `failed[]` with reasons and answers `422`.
- **ops** — `591f7db` Dev profile needs no Redis (PostgreSQL sessions); with Redis sessions, startup fails fast with a clear message if Redis is unreachable; rate limits (per IP, shared-egress caveat) and memory (container limit ≥ 1 GiB) documented.
- **session** — `8fca429` An unset realm SSO idle timeout (0) no longer invalidates every session immediately (found by the release gate).
- **release gate** — `14db0d0` `e2e/monthfold/k3d-helm.sh`: Helm defaults on a fresh k3d cluster + scripted Monthfold run + Go jwx validation (38/38 checks, 6/6 tokens).

## Decisions (agreed with maintainer)
- **No-AI scrub scope:** remove AI *as tool/author* only (tooling config, "agent" tester framing);
  **keep** the product's AI-agent identity feature (the Phase-1 differentiator).
- **Sequence:** adoption + honesty first (Ph5 hygiene → Ph3 runnable → Ph6 feature honesty) →
  Ph2 secure defaults → Ph1 delegation hardening → Ph4 CI/release → Ph7 website.
- **Secure defaults (Ph2):** flip to secure defaults, but each with a documented compatibility note
  and an explicit env override to restore prior behavior. New config keys listed here for review.
- **Gates still in force:** stop-and-ask before changing token formats/claims, public endpoint paths,
  DB schema, config key *names*, or defaults that break existing deployments, and before large
  renames of public classes.

## Do-not-reintroduce (already fixed — verified via SECURITY-REVIEW + internal test reports)
C1 anon `/admin/**`; C1-residual admin-escalation; H1 shipped default enc-key; H2 silent
plaintext-fallback (now fails closed); H3 error-detail leak; M1–M7 (method-security, CORS `*`, CSP,
cookie/CSRF `Secure`, SSRF `OutboundUrlGuard`, OpenSAML 5.1.4); L1–L4; P1/P2 cross-tenant; SAML
S-H1/S-H2/S-M3 + InResponseTo binding; deep-SAML XSW2–8 rejected; DEEP-1 eID status check.
Do not weaken any of these; every change here keeps a regression test.

---

## Phase 5 — Repo hygiene & honesty  *(in progress)*
- **`1c020e0`** — **Auth pages de-branded + re-themed.** The login/2FA/reset/register/consent/flow
  pages still shipped a KubeDNA logo (a `theme.css` background + a hard-coded `<img>` in 21 templates)
  and KubeDNA strings, and per-realm branding stopped at the login page. Replaced the logo with a
  branding-aware **HelixIAM wordmark** in every template (shows the realm's `brandingLogo` when set,
  else the built-in lockup) and re-themed `theme.css` + `login.css` to the helixiam.com warm-humanist
  look (cream/sage/coral, Bricolage + Hanken, sage buttons). Scrubbed the remaining KubeDNA references
  incl. the WebAuthn RP name shown in the passkey prompt, the seed tenant name, page titles and the
  register terms link; byline → "Self-hosted identity". Build green (1139 tests); login + 2FA
  render-verified. (Left: `brand.css` vendored-token comments still say KubeDNA — not user-facing.)
- **`e8dc92a`** — Relabelled the internal security-test reports and moved them to `docs/security/`.
  Titles now say "Internal … Penetration Test Report" with a disclaimer that they are internal
  automated tests on our own code, **not** an independent third-party pentest (still required before
  1.0). Dropped the "offensive-security agent" tester framing. `SECURITY.md` gained a "Security
  testing to date" section and its scope list was corrected (docs-site/website are separate repos).
- **`a7466ff`** — Removed `.claude/agents/pentester.md` (local tooling config that also leaked an
  absolute developer path) and gitignored `.claude/`.
- **Pending in this phase:** `CHANGELOG.md`/`GOVERNANCE.md`/`ROADMAP.md` (this commit, skeletons with
  placeholders for real maintainer/company details); `resources/dummy/dummy.json` — **NOT removed**:
  it is referenced by `ServiceProviderService.java:83` (`getResourceAsStream("/dummy/dummy.json")`),
  so removal needs a code look first (tracked below). Publisher/Subscriber/LocalAdapter renames are
  **gated** (app scans both `group.mfnr` and `io.helixiam`; a bad rename silently drops JPA entities)
  — I will propose these individually before touching public classes.

## Phase 3 — Runnable in 5 minutes  *(in progress)*
- **`f002592`** — `helix-iam-server/Dockerfile`: multi-stage (JDK 21 Maven build → minimal Temurin
  JRE), non-root uid 10001, read-only-root-FS compatible (writes only `/tmp`), container-aware heap,
  actuator readiness HEALTHCHECK. **Verified**: image builds; boots healthy.
- **`1c65745`** — Fixed the pre-existing `helix-dashboard/Dockerfile` (it referenced a
  `deploy/console/nginx.conf.template` that did not exist → unbuildable). Added the template as a
  same-origin reverse proxy to the server (the console session cookie is SameSite=Lax, so a
  cross-origin console would silently fail admin calls) and pointed the default API target at
  `helix-iam-server`. Added `helix-sandbox-rp/Dockerfile` (non-root Node, healthcheck).
- **`9cf2a3b`** — Root `docker-compose.yml`: Postgres + Redis + Mailpit + server + dashboard on
  `docker compose up`; sandbox-rp under a `demo` profile. **Verified end-to-end**: `compose config`
  valid; core comes up with all containers healthy; server `/actuator/health` UP; master realm
  seeded; OIDC discovery + JWKS (RS256/PS256) serve; `/admin/**` denied to anonymous (C1 stays
  fixed); `/actuator/info` not anonymously readable (L2 stays fixed).
- **`4260e6e`** — README: `docker compose up` is now the primary quickstart; replaced the `mvn -o`
  build that fails on a fresh clone with `mvn -B`; fixed the admin-password contradiction to match
  the code (username defaults to `admin`; password is `HELIX_ADMIN_PASSWORD` when set, else a strong
  random password generated once and logged — verified in `RealmAdminBootstrapService`).
- **`57f3051`** — Helm chart `deploy/helm/helixiam`: hardened `securityContext` (non-root,
  readOnlyRootFilesystem, drop ALL caps, seccomp RuntimeDefault), resource limits, startup/liveness/
  readiness probes, NetworkPolicy (restricted ingress + egress), secrets referenced from an existing
  Secret (never inlined), fail-fast on missing required values. **Verified**: `helm lint` clean,
  `helm template` renders 5 well-formed resources.
- **Deferred to a runnability-polish follow-up (depends on O4):** `deploy/seed-demo.sh` (demo
  realm/app/agent + `helix-sandbox` client), the sandbox OIDC round-trip, and the 60-second agent-
  delegation script. These need the single-issuer-host fix (O4) and admin-API seed scripting; not a
  blocker for `docker compose up` (the IdP + console + datastores come up and are usable now).
- **Known caveat (logged):** the sandbox-rp OIDC round-trip needs the issuer host to resolve
  identically in the browser and inside the container (the parked internal-host item) — the demo
  profile documents it; a reverse-proxy front is the likely fix. Tracked as **O4** below.

## Phase 6 — Claims vs reality  *(matrix done; website reconciliation pending Phase 7)*
Built `docs/FEATURES.md` — every feature with a Stable/Beta/Experimental status, code location and
test evidence. Audit findings:
- **Terraform provider**: `helix_application` + `helix_realm_role` resources only (+ `helix_client_id`
  / `helix_client_secret` data sources). The "realms, clients, flows" claim is **wrong** → correct
  the site or add resources. *(Open — website copy.)*
- **TypeScript SDK**: `helix-dashboard/src/sdk` has **no `package.json`** → `@helixiam/sdk` is **not
  published**. Website `import` example is aspirational → fix site or extract+publish. *(Open.)*
- **Keycloak importer**: **real and tested** (`KeycloakImporter.java` + `KeycloakImporterTest.java`) —
  the claim holds; documented as importing a Keycloak realm export.
- **eID (DigiD/eHerkenning/eIDAS)**: validators well-tested (35/15/4/6 test files) but the **live
  DigiD mTLS round-trip is untested** → labelled "connector included; requires your own Logius/broker
  agreement."
- **FAPI/DPoP/PAR/device/adaptive/magic-link/push**: all have automated tests → Beta (FAPI needs the
  OpenID conformance suite, wired in Phase 4).

## Phase 2 — Secure defaults  *(in progress)*
Correction to recon: `AttributeEncryption` only **warned** when `DB_ENCRYPTION` was unset (it fails
closed only on an encryption *error* mid-write) — so a missing key silently stored plaintext. Real work.

- **`4e37592`** — `ProductionReadinessCheck` (fail-fast + summary) and secure-default flips. **1108
  tests green.**
  - Fail-fast outside `dev`: unset `DB_ENCRYPTION` (opt out `HELIX_ALLOW_PLAINTEXT_SECRETS=true`),
    unset `IDP_BASE_URL`/`SP_BASE_URL`. Always logs a one-line summary of insecure settings in effect.
  - Defaults flipped: `USER_REGISTRATION_ENABLED` true→**false**, prometheus-anonymous true→**false**.
  - Removed production-looking fallbacks: base URLs no longer default to `*.kubedna.io`; DB defaults
    `kubeiam`/`kubedna-rw.project-kubedna` → `helixiam`/`localhost`. `dev` profile keeps localhost.

  **Migration notes (breaking-change compatibility):**
  - Set `IDP_BASE_URL` + `SP_BASE_URL` (were effectively required already; the kubedna defaults were
    wrong). Set `DB_ENCRYPTION` (or `HELIX_ALLOW_PLAINTEXT_SECRETS=true` to keep the old plaintext
    behavior).
  - To restore prior defaults: `USER_REGISTRATION_ENABLED=true`, `HELIX_ACTUATOR_PROMETHEUS_ANONYMOUS=true`,
    `DB_NAME=kubeiam` / `DB_USERNAME=kubeiam` / `DB_HOST=<your host>`.

- **`92a33fa`** — Flyway-default flip **attempted and reverted (finding O5).** A new Testcontainers
  test booting on the Flyway `V1..V8` baseline showed the app does **not** come up on it
  (`ServiceProviderService` init → `DuplicateException`): the migrations are not structurally
  equivalent to `schema.sql`. Kept `schema.sql` as the default (shipping a broken Flyway default would
  break fresh deployments); the test is `@Disabled` as the re-enable target; `baseline-version` is now
  configurable via `HELIX_FLYWAY_BASELINE_VERSION` for opt-in adopters.
- **`12b791c`** — SAML-7 fixed: HTTP-Redirect `SigAlg` now allowlists RSA-SHA-256/384/512 and rejects
  `rsa-sha1` + unknown/missing (was: accept SHA-1, silently verify unknown as SHA-256). Regression test
  proves a valid SHA-1 signature is refused and SHA-256 still verifies. **1112 tests green.**
- **`73e64dd`** — SAML-4 fixed: SP-initiated SLO now requires a registered SP signing certificate **and**
  a valid `LogoutRequest` signature (was: signature only checked when a cert happened to be configured, so
  a no-cert SP accepted unsigned requests → cross-user forced logout via `terminate(nameId)` + fan-out).
  Regression test: no-cert SP → SLO rejected.
- **S-I1 (SP-metadata signature) — assessed, no code change.** Verified: metadata is admin-authenticated
  paste that only auto-fills a reviewable form (no automated URL fetch), so it is not an active vuln, and
  the literal "reject unsigned metadata" fix would break the many SPs that publish unsigned metadata. Added
  a guard-rail note in `SamlSpMetadataParser` requiring signature verification + `OutboundUrlGuard` **if** a
  metadata-by-URL import is ever added. **Decision for you:** reject unsigned metadata outright, or a
  non-breaking "verify-signature-if-present" enhancement? (Default: keep the guard-rail note only.)
- **DEEP-3 (eID ArtifactResponse envelope signature) — deferred with rationale.** The inner assertion
  signature is already always enforced (the real guarantee); the envelope-sig is defense-in-depth on the
  DigiD back-channel, which has no live test peer. Changing that untestable path blind risks a regression;
  it should land with the live-DigiD `ArtifactResolve` work when a test environment exists.
- **`430db9b`** + **`bacc13f`** — L6 done: when `helix.admin.password-file` (`HELIX_ADMIN_PASSWORD_FILE`)
  is set, a generated bootstrap admin password is written to that file `0600` and only the path is logged.
  A background commit-review flagged credential exposure on partial failure; hardened in `bacc13f` —
  file created `0600` **atomically** (never briefly world-readable), any partial file deleted on failure
  (credential lands in exactly one place), `Path.of` guarded. 4 regression tests.
- **`e869979`** — kubedna sweep (start): the `USER_SIGNUP` verification path sent an internal
  "new registered user" notification to a hard-coded `contact@kubedna.com`. Now
  `helix.notifications.registration-recipient` (env `HELIX_NOTIFICATIONS_REGISTRATION_RECIPIENT`),
  default **blank = do not send** (so no kubedna address is ever used). 2 regression tests. Remaining
  `kubedna`/`kubeiam` hits are javadoc/tests plus the seeded `kubedna-cli` client_id — **kept**
  (renaming a seeded client_id breaks existing CLI callers; decision: leave the value, reword only
  prose, defer a migrated rename to post-1.0).
- **L5 — legacy-crypto re-encryption — scoped and deferred (needs live-DB/Testcontainers validation).**
  `AttributeEncryption` reads AES/GCM, falling back to legacy AES/ECB, and — critically — **returns the
  stored value as-is when neither key decrypts it** (`convertToEntityAttribute`/`tryLegacyDecryption`).
  So a naive "load-all-and-re-save" migration is **unsafe**: a corrupt or truncated GCM value would be
  read back as if it were plaintext and then re-encrypted, permanently corrupting it. The safe algorithm
  is: iterate each encrypted-column entity, and re-encrypt **only** rows that *positively* decrypt with
  the **legacy** key (GCM-fails **and** legacy-succeeds) — never the "returned as-is" rows — re-storing
  the recovered plaintext so the converter writes GCM; expose a gauge of rows still on the legacy path so
  the fallback can eventually be dropped. Because it rewrites columns holding realm private signing keys
  and TOTP secrets, it must be validated against a real dataset (a Testcontainers integration test that
  seeds a legacy-ECB value, migrates, and asserts GCM) before it ships — it is **not** something to land
  blind into the vendored crypto converter. Tracked as the primary remaining Phase 2 security item.
- **Also still to do in Phase 2:** reconcile Flyway vs `schema.sql` (O5, likely linked to O1). The
  remaining `kubedna`/`kubeiam` strings are javadoc/tests plus the seeded `kubedna-cli` client_id (kept,
  see the sweep note above).

## Phase 1 — Agent delegation  *(complete)*
Reviewing `DelegationTokenController.exchange()` (the on-behalf-of RFC 8693 `/agent/delegation/token`).
Built a from-scratch test harness (`DelegationTokenControllerTest`) — the endpoint previously had **no**
unit coverage. Nimbus signs realm-scoped user/actor tokens; the controller's decoder verifies against the
matching public JWKS.

- **Gap 1 — subject-token→agent binding (`c427e45`).** The exchange now refuses a `subject_token` that
  does not authorize *this* agent: it must carry the agent in `aud`, name it in `azp`, or carry a
  `may_act` claim (`sub`/`azp`/`client_id`) naming it. Without this any user access token the realm
  minted could be replayed by any registered agent. New config
  `helix.agent.delegation.require-subject-binding` (default **true**); set false to restore the old loose
  behavior. Tests: aud-bound mint, unbound reject (403 `invalid_grant`), `may_act` mint, loose-mode accept.
- **Gap 3 — delegation chain-depth limit (`e7e3fb3`).** Walks the nested `act` chain on the actor token
  and refuses when `depth + 1` would exceed `helix.agent.delegation.max-chain-depth` (default **3**) with
  400 `invalid_request`. Bounds unbounded on-behalf-of nesting. Test: depth-3 actor → next exchange 400.
- **Gap 4 — cross-realm key isolation — assessed, no code change.** `RealmJwkSource` already scopes
  signing/verification keys by `RealmContextHolder`; verified by the existing
  `RealmJwkSourceTest.servesEachRealmsOwnKey_withoutLeakingAcrossRealms`. No leak path found.
- **Gap 5 — RFC 8693 token-type conformance (`e7e3fb3`).** Validates `subject_token_type`,
  `actor_token_type` and `requested_token_type`: unsupported types are rejected with 400 `invalid_request`
  (previously the params were ignored). `issued_token_type` = access_token is returned in the response.
  Test: `requested_token_type=saml2` → 400.
- **Gap 6 — `resource` / RFC 8707 (`dbc14ab`).** A `resource` indicator, when present, must be an
  absolute URI without a fragment; otherwise 400 `invalid_target`. (A full per-realm/per-agent resource
  allow-list needs a resource registry — logged as a follow-up, not a security hole today since the
  minted token's audience is still bound.) Tests: non-absolute → 400 `invalid_target`; absolute URI → 200.

- **Gap 2 — actor client authentication (`8ce2f57`).** *(Decision: client-auth, strict default + opt-out.)*
  The `actor_token` alone was a bearer credential — capturing it let anyone act as the agent. The
  exchange now also requires the caller to authenticate as the agent's OAuth2 client
  (`client_secret_basic` or `client_secret_post`), and the authenticated `client_id` must equal the
  actor's agent; secrets are compared constant-time against the registered client's `{noop}` secret.
  **Breaking for existing agent callers**, so strict by default with
  `helix.agent.delegation.require-actor-auth=false` (env `HELIX_AGENT_DELEGATION_REQUIRE_ACTOR_AUTH`)
  to restore the pre-1.0 bearer-only behavior during migration; the three delegation keys are now
  documented in `application.properties`. Tests: no creds → 401 `invalid_client`; wrong secret → 401;
  authenticated client ≠ actor agent → 401; valid Basic → 200; valid `client_secret_post` → 200.
- **Gap 7 — revoke already-minted agent tokens on introspection (`b81b3e0`).** *(Decision: short-TTL +
  introspection re-check.)* A custom RFC 7662 introspection response handler
  (`AgentRevocationIntrospectionHandler`) re-checks live agent status: a token carrying `nhi`/`agent_id`
  whose agent is no longer ACTIVE (or was removed) introspects as `active:false`, so a resource server
  that introspects sees the kill-switch ahead of the token's (short) expiry. Non-agent tokens pass
  through unchanged and the token-validation hot path is untouched — RSes that validate the JWT locally
  still rely on the short token lifetime (300s delegation / 900s WIF) for revocation latency; a
  per-request global revocation validator was considered and **not** adopted for 1.0 (hot-path AMQP
  lookup on every agent request). Lookup failures fail open. 7 regression tests. **Phase 1 complete.**

**`WorkloadIdentityTokenController` review (the WIF exchange sibling) — assessed:**
- **Kill-switch: safe.** `resolve()` is backed by `findAllByRealmIdAndIssuerAndEnabledTrue`, so a
  disabled workload credential is filtered at the query and cannot mint. Mint-time enforcement matches
  the agent path; the already-minted-token residual is the same as gap 7 and bounded by the 900s TTL.
- **Fixed short TTL (900s), fixed audience (mapped client id), cryptographic verification gate** against
  the credential's expected iss/aud/sub — all present. No `resource`/audience injection surface.
- **Minor (logged, not a hole):** it does not read/validate RFC 8693 `*_token_type` params (it doesn't
  advertise them) and `exchange()` has no direct unit test. Tracked as a Phase-4/coverage follow-up.

## Phase 4 — CI, supply chain & releases  *(workflows landed; first CI run happens on push)*
Added under `.github/` (all actions **pinned to a full commit SHA**, version in a trailing comment;
Dependabot keeps them current). These run on GitHub, so they are validated by the first push/PR, not
locally — YAML validated locally.
- **`ci.yml`** (rewritten): server (`mvn -B clean verify`), dashboard (vitest + build), and
  `terraform-provider-helix` (`go vet` + `go test`) — the go module + dashboard tests were not run in CI
  before. `permissions: contents: read`.
- **`codeql.yml`**: CodeQL `security-extended` for `java-kotlin` + `javascript-typescript`
  (build-mode none), on push/PR/weekly, results to code scanning.
- **`security-scan.yml`**: Trivy fs scan (vuln + misconfig + secret, CRITICAL/HIGH, unfixed ignored) →
  SARIF to code scanning, on push/PR/weekly.
- **`dependabot.yml`**: maven, npm (dashboard + sandbox-rp), gomod, github-actions, docker — weekly, grouped.
- **`release.yml`** (on `v*` tag): build + push the server image to GHCR, **cosign keyless sign**,
  generate an **SPDX SBOM**, **cosign attest** the SBOM to the image, and publish a GitHub release with
  the SBOM attached. Uses the runner's `docker`/`gh` to keep the third-party action set minimal
  (checkout, cosign-installer, sbom-action). This makes real the supply-chain controls SECURITY.md
  describes; `SECURITY.md` gained a "Build & supply-chain security" section (honest: no release tagged
  yet, so no signed image exists on a registry today).
- **Still to do in Phase 4:** enable GitHub secret scanning + push protection and branch protection
  (repo settings — maintainer action, O2/O6); optionally add image scanning of the built release image
  and an OpenID conformance job (FAPI) once a hosted test env exists.

---

## Open questions / to raise
- **O1** `resources/dummy/dummy.json` — what does `ServiceProviderService` use it for? Remove, or is it
  a real seed/default? (Phase 5)
- **O2** Real maintainer names, decision process, and company/legal details for `GOVERNANCE.md` and the
  website About/Trust pages (Phase 5/7) — placeholders in place until you provide them.
- **O3** Third-party pentest before 1.0: SECURITY-REVIEW says it is **required** and the internal tests
  do not discharge it. Recommendation stands: yes, commission one before tagging 1.0.
- **O4** sandbox-rp OIDC round-trip in compose needs a single issuer host reachable identically from
  the browser and the container (parked internal-host item). Plan: front the stack with a small
  reverse proxy so browser + services share one origin. Non-blocking for the core stack.
- **O5** the Flyway `V1..V8` baseline is **not equivalent to `schema.sql`** — the app fails to boot on
  the Flyway path (`ServiceProviderService` init `DuplicateException`). Reconcile the two (diff the
  produced schema — likely a constraint/index the migrations create that `schema.sql` does not, or a
  duplicate seed) before Flyway can be the default. Until then `schema.sql` stays the default and
  Flyway is opt-in. `FlywayMigrationTest` (`@Disabled`) is the re-enable target.
