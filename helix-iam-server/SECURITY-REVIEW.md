# HelixIAM Server — Internal Security Review

> **This is an INTERNAL SELF-REVIEW.** It was performed by the HelixIAM engineering team on its own
> code to find real issues before release. **It is NOT an independent third-party audit.**
> An independent third-party security audit and a penetration test **remain REQUIRED before any
> production deployment or public/open-source release.**

> **REMEDIATION STATUS (post-review, same day):**
> - **C1 (CRITICAL) — FIXED.** `AdminAuthorizationManager` now DENIES unauthenticated/anonymous
>   callers on `/admin/**` (it is the sole authorization rule for those paths). Regression tests added
>   (`AdminAuthorizationManagerTest.anonymousPrincipal_onAdminPath_isDenied` / `unauthenticated...`).
> - **H1 (HIGH) — FIXED.** The shipped default at-rest encryption key was removed from production
>   config (`database.encryption=${DB_ENCRYPTION:}`); the app now fail-fasts when it is unset. A local
>   default remains only in `application-dev.properties`.
> - **M1 (MEDIUM) — FIXED.** `@EnableMethodSecurity` added to `SecurityConfig`, so method-level
>   `@PreAuthorize`/`@PostAuthorize` is now actually enforced instead of silently ignored.
>   *Note:* this changes no live behaviour today — the only two annotated methods
>   (`TenantService.assignUserToTRole` / `revokeUserToTRole`, guarding `ROLE_ADMIN_<tenantId>`, an
>   expression that correctly matches `UserCredentials.getAuthorities()`) currently have **no callers**.
>   The value is closing the footgun: any future `@PreAuthorize` would otherwise have looked enforced
>   while doing nothing. Consider deleting the two dead methods.
> - **H3 (HIGH) — FIXED.** Error bodies no longer echo internals. `application.properties` now pins
>   `server.error.include-message=never`, `include-binding-errors=never`, `include-stacktrace=never`,
>   `include-exception=false`. `application-dev.properties` re-opens `include-message` /
>   `include-binding-errors` (`always`) for local debugging only. Since Spring Boot 4 the keys are
>   `spring.web.error.include-*` (Boot ignores `server.error.*`); `ErrorDetailPropertiesTest` binds them.
> - **M2 (MEDIUM) — FIXED.** `RealmClientCorsConfigurationSource.corsConfigFor` no longer honours a `*`
>   web-origin entry: because every config it builds sets `allowCredentials(true)`, a wildcard would mean
>   reflect-any-origin-with-credentials (a same-origin-policy bypass). A realm configured with `*` is now
>   treated as having no origins (cross-origin denied) and the misconfiguration is logged with the realm
>   name. Explicit per-realm/per-client origins behave exactly as before. Regression tests added
>   (`aWildcardEntryIsIgnoredAndDeniesUnlistedOrigins`, `anExplicitOriginStillWorksAlongsideAStrayWildcard`,
>   `neverCombinesAWildcardOriginWithCredentials`).
> - **M4 (MEDIUM) — FIXED.** `server.forward-headers-strategy=framework` added, so `isSecure()`/scheme are
>   honoured behind a TLS-terminating proxy. The session cookie is now explicit and configurable:
>   `helix.security.cookie-secure=${HELIX_COOKIE_SECURE:true}` (single knob) drives
>   `server.servlet.session.cookie.secure`, alongside `http-only=true` and `same-site=Lax` (**not** `Strict`
>   — an IdP receives cross-site top-level POSTs/redirects: SAML POST binding, OIDC `form_post`,
>   RP-initiated logout). `application-dev.properties` sets `helix.security.cookie-secure=false`.
> - **M5 (MEDIUM) — FIXED.** The `XSRF-TOKEN` cookie's `Secure` flag is pinned from the same
>   `helix.security.cookie-secure` knob via `CookieCsrfTokenRepository.setCookieCustomizer`
>   (`SecurityConfig.csrfTokenRepository()`). `HttpOnly` stays **false** by design — the SPAs must read the
>   cookie to echo `X-XSRF-TOKEN`.
> - **L1 (LOW) — FIXED.** guava pinned to **33.4.0-jre** via `<dependencyManagement>` in `pom.xml`
>   (was transitively 31.1-jre), clearing CVE-2023-2976 / CVE-2020-8908. 33.4.0-jre is the newest line that
>   resolves in the offline (`mvn -o`) build with its transitive metadata intact; verified with
>   `mvn -o dependency:tree`.
> - **L2 (LOW) — FIXED.** `/actuator/info` removed from both the anonymous allowlist (`SecurityConfig`) and
>   `management.endpoints.web.exposure.include`. `/actuator/health` (+ `health/**`) stays anonymous — it is
>   the container probe. `/actuator/prometheus` anonymity is now an explicit switch,
>   `helix.actuator.prometheus-anonymous` (default **true** so in-cluster scraping is unchanged; documented
>   as "restrict the scrape path with a NetworkPolicy / ingress rule", and settable to `false` to push it
>   behind the authenticated gate).
> - **L3 (LOW) — FIXED.** Swagger UI + `/v3/api-docs` are no longer anonymous by default. `helix.springdoc.public`
>   (default **false**) gates the `permitAll`; when false those paths fall through to
>   `anyRequest().authenticated()`, so the admin API schema is not disclosed to anonymous callers.
>   `application-dev.properties` sets it `true`.
> - **L4 (LOW) — FIXED.** `spring-boot-devtools` removed from `pom.xml`. `<optional>true</optional>` only
>   hides it from downstream consumers — it was still on this app's own compile/runtime classpath and in the
>   repackaged jar. Nothing references devtools APIs; compilation and the full suite are unaffected.
> - **H2 (HIGH) — FIXED.** `AttributeEncryption.convertToDatabaseColumn` now **fails closed**: a crypto
>   error throws instead of silently persisting realm private signing keys / TOTP secrets in PLAINTEXT.
>   A missing `database.encryption` (which silently disabled at-rest encryption entirely) now logs a loud
>   startup warning, and the decrypt fallback that swallowed at `trace` now WARNs, so a corrupt or tampered
>   value is visible instead of being returned silently as-is.
> - **C1 residual (privilege escalation) — FIXED.** An unconfigured realm (the DEFAULT state of every realm)
>   or an RBAC resolution failure previously granted admin access to ANY authenticated principal — a normal
>   end user could reach the admin API. Both paths now require **`admin_<realmId>`**, so real admins are
>   never locked out by an RBAC outage while ordinary users are denied; realm-independent admin routes now
>   require admin of *some* realm. The two tests that encoded the old permissive behaviour
>   (`unconfiguredRealm_isDefaultSafeAllow`, `failsOpenWhenResolutionThrows`) were rewritten to assert both
>   sides (admin allowed / ordinary user denied).
>   *Admin is exactly one authority:* the legacy `ROLE_ADMIN_<realmId>` is deliberately **not** accepted.
>   Nothing reachable grants it — its only producer (`TenantService.createTenant`) has no callers, and the
>   bootstrap grants the curated `admin` role — so honouring it would widen a security-critical check for no
>   live caller. Pinned by `legacyRoleAdminAuthority_isNotAcceptedAsRealmAdmin`.
>   **Migration note:** a database carried over from an older deployment whose admins hold only
>   `ROLE_ADMIN_<realm>` rows would need those users granted the `admin` role before they regain admin access.
>
> - **M3 (MEDIUM) — FIXED.** Content-Security-Policy + `X-Frame-Options: DENY` / nosniff / Referrer-Policy /
>   HSTS on the server-rendered login chain (JSON API and the SPA console excluded). `script-src` is
>   `'self'` with NO `'unsafe-inline'` — every inline script + the one inline handler was externalized to
>   `/js/*.js` (WebAuthn/TOTP ceremonies included), per-request values passed via `th:data-*`. `style-src`
>   keeps `'unsafe-inline'` (per-realm branding CSS); `form-action` relaxed to `https:` on `/saml/idp/**`
>   + `/broker/**` only so federation POST-binding still works. Live-verified by booting and loading the pages.
> - **M6 (MEDIUM) — FIXED.** New `io.helixiam.common.net.OutboundUrlGuard` rejects non-http(s) schemes and any
>   host resolving to loopback/wildcard/link-local (incl. cloud metadata `169.254.169.254`)/private/ULA/
>   multicast, applied to the 9 attacker-configurable outbound sites (webhook, SCIM, OIDC-broker token+JWKS,
>   DCR JWKS, WIF `jwksUri`, eID artifact resolver, upstream + backchannel logout, realm HTTP SMS/email).
>   Secure default; `helix.egress.allow-private=true` only in dev. Residual: DNS-rebinding TOCTOU mitigated
>   (resolve-and-check, reject if any resolved IP is internal) but not eliminated by connection pinning.
>   **Fixed 2026-10-13 (branch `fix/wallet-network-hardening`, also affected released versions):** an IPv6
>   address that embeds a blocked IPv4 address (IPv4-mapped `::ffff:127.0.0.1` / `::ffff:169.254.169.254`,
>   IPv4-compatible `::/96`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) passed the check, so an AAAA answer could reach
>   loopback or cloud metadata. Such addresses are now judged by their embedded IPv4 address; `192.0.0.0/24`,
>   `198.18.0.0/15` and `240.0.0.0/4` (incl. broadcast) are blocked; the AWS IPv6 metadata address `fd00:ec2::254`
>   stays blocked even for an allowlisted host.
>   **Residual closed 2026-10-13:** the DNS-rebinding TOCTOU is eliminated by connection pinning. Every guard caller
>   (webhooks, SCIM, HTTP email/SMS/push and Cloudflare email drivers, back-channel and upstream logout, OIDC broker
>   token + JWKS, WIF JWKS + issuer discovery, FAPI request-object JWKS, eID ArtifactResolve, SAML metadata import,
>   wallet status lists and issuer CRL/OCSP) connects through `PinnedHttpFetcher` / `PinnedResourceRetriever`:
>   one guarded resolution inside the request deadline, a socket to the validated address, SNI and hostname
>   verification on the original name, no redirect following (metadata import re-guards each hop), per-caller size
>   caps and timeouts. Tests: one public→private rebinding test per caller (`RebindingTarget`).
>   **Re-review follow-ups (2026-10-13):** the token endpoint's `private_key_jwt` client JWKS (fetched by Spring
>   Authorization Server's own decoder: unguarded, redirects followed; reachable through open DCR) now goes through the
>   guard on the pinned transport (`GuardedClientAssertionDecoderFactory`), and DCR validates the auth method and an
>   https, guard-approved `jwks_uri`. APNs is the one deliberate exception to pinning: HTTP/2 to Apple's two fixed hosts
>   only (`ApnsHttp2Transport`), no admin-chosen host. Outbound slots are per feature group (wallet, login, OTP,
>   outbound) with a per-realm share, so a tarpit in one realm cannot starve logins, OTP or other realms. The guard
>   also judges SIIT addresses by their embedded IPv4 and refuses Teredo and `100::/64`.
>   **Third review (2026-10-13):** the fetch limiter no longer pins virtual-thread carriers (`ReentrantLock`), and
>   webhook/SCIM deliveries are bounded per realm; local-use NAT64 `64:ff9b:1::/48` is refused outright; `login`
>   slots are split into `login-admin` and `login-client`; decoder/JWKS caches are bounded LRU. Two pre-existing
>   egress gaps outside HTTP are closed: the **SMTP** driver (guarded, pinned, TLS on the configured name, standard
>   ports unless `helix.messaging.smtp.allowed-ports`) and **LDAP federation** (guarded, pinned, LDAPS on the configured
>   name, referrals off, internal directories only via the operator setting `helix.federation.ldap.allowed-hosts`).
>   The SIEM audit webhook has explicit timeouts and a bounded backlog.
>   **Final review (2026-10-13):** SMTPS is pinned too (Angus is given the validated IP; TLS is checked against the
>   configured name by our own endpoint identification); LDAP bind sequences have one 15 s deadline, at most two
>   addresses and per-realm `ldap` slots; non-https client JWKS URLs left from before the https rule are refused at
>   fetch time; the token endpoint auth method is case-insensitive with unknown values refused; pending deliveries have
>   a global ceiling; `3fff::/20` is matched exactly.
>
> **STILL OPEN — deliberately deferred** (documented in `DEFERRED-SECURITY-WORK.md`): **L5** (the legacy
> AES/ECB decrypt path is retained deliberately so existing rows stay readable — now logged), **L6** (the
> generated bootstrap admin password is written to the log; an intentional zero-config trade-off, avoided
> entirely by setting `HELIX_ADMIN_PASSWORD`), and the pentest test-coverage gaps (deeper XSW2–8, eID mTLS
> back-channel, full `/broker/{alias}/callback` round-trip) — those are testing depth, not code defects.
>
> **M7 is now FIXED (2026-09-17):** the OpenSAML stack was upgraded off the EOL 4.3.2 line to **5.1.4**
> (`net.shibboleth:shib-*:9.1.4` replacing `java-support:8.4.2`, Santuario `xmlsec` **3.0.5**, cryptacular
> **1.2.6**), with validation logic unchanged and all 1096 tests — including every SAML/eID security test —
> green. See `DEFERRED-SECURITY-WORK.md` M7 and `.sdd-m7-report.md`.

| | |
|---|---|
| **Repository** | `helix-iam-server` (`io.helixiam:helix-iam-server:1.0.0-SNAPSHOT`) |
| **Commit reviewed** | `18a593263be41cf94aeab718949187f759368f17` (branch `master`, 2026-09-16) |
| **Review date** | 2026-09-16 |
| **Reviewer** | Internal engineering (adversarial self-review) |
| **Scope** | Dependency currency, the AMQP→in-process migration's authz implications, token/key security, credential handling, SAML, session/web, dangerous flags/endpoints, secrets/config, input validation/injection |
| **Method** | Manual source review + `mvn -o dependency:tree` (offline). OWASP dependency-check could **not** run (no NVD network access); dependency findings are a manual CVE-class assessment — see caveat below. |

---

## Findings summary

| ID | Severity | Area | Location | Title |
|----|----------|------|----------|-------|
| C1 | **CRITICAL** | Authz / migration | `SecurityConfig.java:253` + `AdminAuthorizationManager.java:64‑88` + `AdminRbacService.java:112` | `/admin/**` is authorized-open by default (fail-open manager is the *only* gate — reaches even unauthenticated callers) |
| H1 | **HIGH** | Secrets / at-rest crypto | `application.properties:46`, `application-dev.properties:8` | Shipped default at-rest encryption key + no KDF — realm **private signing keys** and TOTP secrets encrypted with a public/known key when `DB_ENCRYPTION` unset |
| H2 | **HIGH** | At-rest crypto | `AttributeEncryption.java:81`, `:124` | Encryption failure silently **falls back to plaintext** for private keys / TOTP secrets |
| H3 | **HIGH** | Info disclosure | `application.properties:89` | `server.error.include-message=always` leaks exception messages in all environments |
| M1 | MEDIUM | Authz | `TenantService.java:160,177` (+ no `@EnableMethodSecurity` anywhere) | `@PreAuthorize` guards are **inert** (method security not enabled) — decorative access control |
| M2 | MEDIUM | CORS | `RealmClientCorsConfigurationSource.java:63‑70` | A realm web-origin list containing `*` → reflect-any-origin **with credentials** |
| M3 | MEDIUM | Web headers | `SecurityConfig.java` (order-2 chain) | No Content-Security-Policy on server-rendered login/consent/MFA pages |
| M4 | MEDIUM | Session / transport | `application.properties:68`; no `server.forward-headers-strategy` | Session cookie `Secure` not pinned; `isSecure()` is proxy-dependent → cookie/HSTS may drop behind TLS-terminating ingress |
| M5 | MEDIUM | CSRF cookie | `SecurityConfig.java:187` | `XSRF-TOKEN` cookie `Secure` flag not forced |
| M6 | MEDIUM | SSRF | webhook / SCIM / OIDC-broker / captcha / audit-forwarder clients (see body) | Admin-configurable outbound URLs (SSRF), **amplified** by C1 (attacker can configure them) |
| M7 | ~~MEDIUM~~ **FIXED** | Dependencies | `pom.xml` (`dependencyManagement`) | ~~OpenSAML **4.3.2** (EOL 4.x line) + Apache `xmlsec` 2.3.4~~ → upgraded to OpenSAML **5.1.4** + `xmlsec` **3.0.5** + `shib-*:9.1.4` + cryptacular **1.2.6** (2026-09-17); validation logic unchanged, 1096 tests green |
| L1 | LOW | Dependencies | transitive `com.google.guava:31.1-jre` | CVE-2023-2976 (insecure temp-dir) / CVE-2020-8908 |
| L2 | LOW | Endpoint exposure | `application.properties:90`, `SecurityConfig.java:256` | `/actuator/prometheus` + `/actuator/info` anonymous |
| L3 | LOW | Endpoint exposure | `SecurityConfig.java:259` | Swagger UI + `/v3/api-docs` `permitAll` — admin API schema disclosure |
| L4 | LOW | Build hygiene | `pom.xml:177‑181` | `spring-boot-devtools` on the compile/runtime graph (optional, but avoid in release artifacts) |
| L5 | LOW | Legacy crypto | `AttributeEncryption.java:113‑127` | Legacy AES/ECB (no-IV, no-integrity) decrypt fallback |
| L6 | LOW | Credential handling | `RealmAdminBootstrapService.java:91` | Bootstrap admin password written to application logs |
| H4 | **HIGH** — **FIXED 2026-10-16** | Authz | `AdminRoutePermissions.java`, `AdminAuthorizationManager.java` | Admin permission resolved on the **raw** request URI while Spring MVC routes on the decoded path — see [H4](#h4-high-fixed--admin-permission-resolved-on-the-raw-uri) |
| H5 | **HIGH** — **FIXED 2026-10-16** (present in rc.11) | Authz / privilege escalation | `RoleAdminService`, `GroupAdminService`, `ClientRoleAdminService`, `AdminRbacService`, SCIM, realm import | An admin could hand out admin permissions they do not hold — see [H5](#h5-high-fixed--admins-could-grant-admin-permissions-they-do-not-hold) |
| I1 | INFO | Positive | `PasswordEncoderService.java:32` | Argon2id (OWASP params) with constant-time legacy verify + transparent upgrade |
| I2 | INFO | Positive | 25 admin controllers use `@Valid` + `AdminValidationAdvice` | Bean Validation present on admin write APIs |
| I3 | INFO | Positive | `BreachedPasswordChecker.java`, `PasswordPolicyEnforcer.java`, `LoginFailureService.java` | HIBP k-anonymity, password policy+history, lockout wired |

_SAML-specific findings from the focused SAML/XML sub-review are folded into section 5 and the table is annotated there._

---

## C1 (CRITICAL) — `/admin/**` is authorized-open by default

**This is the single most important finding and is a direct consequence of the AMQP→in-process migration (review area #2).**

### The old boundary
In the two-service design, admin operations crossed the RabbitMQ RPC boundary and some listeners were `@SecuredListener` — authorization was (partly) enforced *at the queue*. The merge replaced that boundary with direct in-process `*LocalAdapter` calls. The intended replacement enforcement is the HTTP layer: `anyRequest().authenticated()` plus the fine-grained `AdminAuthorizationManager` on `/admin/**`.

### The defect
The manager is wired as the **sole** matcher for `/admin/**`:

```
// SecurityConfig.java:253
http.authorizeHttpRequests(requests -> requests.requestMatchers("/admin/**").access(adminAuthorizationManager));
...
// SecurityConfig.java:261
http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated());
```

Because Spring Security evaluates request matchers in order and the **first match wins**, every `/admin/**`
request is decided by `AdminAuthorizationManager` alone. `anyRequest().authenticated()` **never applies to
`/admin/**`** — yet the manager was written on the explicit assumption that it does:

```
// AdminAuthorizationManager.java:64-88 (abridged)
if (required.isEmpty())            return new AuthorizationDecision(true); // (only non-/admin paths)
if (auth == null || !auth.isAuthenticated())
                                   return new AuthorizationDecision(true); // "login gate handled by anyRequest()"  <-- FALSE
if (realmId == null)               return new AuthorizationDecision(true); // realm-independent /admin path
if (eff == null || !eff.modelConfigured())
                                   return new AuthorizationDecision(true); // realm with no admin-RBAC grants
```

Every one of these branches returns **grant**. And the last branch is the **default state**:

```
// AdminRbacService.java:112
if (grants.countByRealmId(realmId) == 0) {
    return new AdminEffectivePermissionsDto(realmId, false, List.of()); // modelConfigured = false
}
```

A fresh/normal deployment configures no admin-RBAC grants, so `modelConfigured=false` for every realm, so the
manager grants **every** `/admin/**` request. Anonymous requests reach the manager as an
`AnonymousAuthenticationToken` (whose `isAuthenticated()` is `true` by Spring Security default), and even if
anonymous auth were disabled the `auth == null` branch grants anyway. Realm-independent admin paths
(`/admin/audit/**`, `/admin/admin-roles` — the *most* sensitive, admin-RBAC management itself) hit the
`realmId == null` branch and are granted **unconditionally**.

### Impact
In the default configuration the **entire admin REST API is reachable without authentication**: create/modify
admin users (`UserAdminController`, `/admin/realms/{realm}/users`), rotate/retire realm **signing keys**
(`RealmKeyAdminController`, `/admin/realms/{realm}/keys/rotate`), register clients, read/modify realm settings,
configure identity providers, webhooks, SCIM targets, etc. This is full multi-tenant compromise. `/admin/**` is
CSRF-exempt only under `dev-open`; in prod writes require the `XSRF-TOKEN` cookie, but an unauthenticated
attacker obtains that cookie with one GET (finding M5) — it is not a mitigation.

### Recommendation
1. Make authentication a **hard, independent gate** for `/admin/**` that the fine-grained manager can only
   *narrow*, never replace — e.g. add `.requestMatchers("/admin/**").authenticated()` **and** enforce roles, or
   compose the manager with `AuthenticatedAuthorizationManager` via `AuthorizationManagers.allOf(...)`.
2. Change every fail-open branch in `AdminAuthorizationManager` to **fail closed** for `/admin`: unknown/anonymous
   principal → deny; `realmId == null` → deny (or require a global-admin authority); resolution failure → deny.
3. Enforce that the authenticated principal is an **admin of the target realm from the path** (cross-tenant
   check) — controllers currently take `realmId` from the path with no principal↔realm comparison
   (`UserAdminController.java:60`, `RealmKeyAdminController.java:36`).
4. Add an integration test: an anonymous request and a non-admin authenticated request to
   `/admin/realms/master/users` and `/admin/realms/master/keys/rotate` MUST return 401/403.

---

## H1 (HIGH) — Shipped default at-rest encryption key + no key derivation

`application.properties:46` and `application-dev.properties:8` both ship a concrete default:

```
database.encryption=${DB_ENCRYPTION:0f31bbdc3193a96c859c2e24b34da89e}
```

This value is the key for `AttributeEncryption`, the JPA converter that encrypts sensitive columns at rest —
including realm **private signing keys** (`RealmKey.privateKey`, annotated `@Convert(AttributeEncryption.class)`,
`RealmKey.java:43`) and TOTP secrets. Any deployment that does not set `DB_ENCRYPTION` encrypts these secrets
under a value that is **public in the (soon open-source) repo**. An attacker with the ciphertext (DB dump,
backup, replica) trivially decrypts realm private keys → forges tokens for every tenant.

Additionally the key derivation is non-existent: `generateKey()` uses the raw config-string bytes directly as
the AES key with **no KDF, no salt** (`AttributeEncryption.java:52-53`,
`new SecretKeySpec(password.getBytes(), "AES")`), so key strength is bounded by the passphrase's literal bytes
and any string not exactly 16/24/32 bytes long breaks AES init (→ see H2).

**Recommendation:** remove the default entirely (fail fast if `DB_ENCRYPTION` is unset in prod); derive the AES
key with a real KDF (PBKDF2/HKDF/Argon2 with a fixed salt or, better, take a base64 32-byte key directly);
document key provisioning and rotation. Treat the shipped default as compromised and rotate any data encrypted
under it.

## H2 (HIGH) — Encryption failure silently falls back to plaintext

```
// AttributeEncryption.java:79-82
} catch (final Exception e) {
    LOG.error("Encryption failed");
    return data; // Fallback to plaintext
}
```

On any exception during encryption (e.g. an invalid-length key from H1, provider issue), the **plaintext**
private key / TOTP secret is written to the database, logged only as a generic "Encryption failed". The decrypt
path has the same plaintext fallback (`:124`). A misconfiguration therefore degrades silently from
"encrypted at rest" to "cleartext at rest" with no failure surfaced.

**Recommendation:** fail closed — throw on encryption error so the write aborts; never persist plaintext for a
column declared encrypted. Alarm on the error.

## H3 (HIGH) — Verbose error messages returned to clients

`application.properties:89` `server.error.include-message=always` returns exception messages in error bodies in
all profiles, aiding user/realm enumeration and internal-detail disclosure. (`include-stacktrace` /
`include-exception` are correctly left at defaults → no stacktrace leak.) **Recommendation:** `never` (or
`on-param`) in production.

---

## H4 (HIGH, FIXED) — admin permission resolved on the raw URI

**Found 2026-10-16** (automated review of the bring-your-own realm keys branch); the defect predates that branch.

`AdminAuthorizationManager` passed `request.getRequestURI()` — still percent-encoded and with `;matrix` content — to
`AdminRoutePermissions`, which split it into segments and fell back to `manage-realm` for an unknown route group.
Spring MVC routes on the **decoded** path. So `POST /admin/realms/r/k%65ys/import` was authorised as `manage-realm`
but handled by the realm-key controller (which needs `realm-admin`), and the same differential applied to every route
group (`u%73ers` resolved to `manage-realm` instead of `manage-users`, `cl%69ents` instead of `manage-clients`, …).
An admin holding one low permission could reach writes guarded by another.

**Fix (three layers).**
1. `AdminPathEncodingFilter` (first servlet filter) answers `400` to a percent-encoded character in the realm or
   route part of an admin path (`/admin/realms/{realmId}/{group}`, or the first two segments of other `/admin` paths)
   and to a double-encoded `%25` anywhere under `/admin`. Realm ids are `[A-Za-z0-9._-]` and route names are fixed,
   so nothing legitimate is encoded there; deeper id segments (a SAML entity id such as `urn%3Aexample%3Asp`) still
   work, and they never decide the permission.
2. The permission is resolved on the decoded path within the application, without `;` content (`UrlPathHelper`), the
   path Spring MVC routes on; segments match exactly and case-sensitively; an unknown route group (or unknown
   realm-independent admin path) now fails closed to `realm-admin`. The groups that relied on the old default are
   listed explicitly (agents, events, scim-targets, webhooks, workload-identity, user-federation, flow, flow-engine,
   export, import). `admin-roles` is matched as the route group, not as a substring of the path.
3. The realm-key write endpoints check `realm-admin` themselves (`AdminAuthorizationManager.permits`).

**Tests.** `AdminAuthorizationManagerTest.resolvesThePermissionOnTheDecodedPath_asSpringMvcRoutesIt`,
`AdminRoutePermissionsTest` (fail-closed and explicit groups), `AdminPathEncodingFilterTest`, and
`RealmKeyPermissionsE2eTest.encodedCasedAndMatrixPathTricks_neverReachAWriteWithALowerPermission` (through the real
filter chain: `k%65ys`, `%6Beys`, `KEYS`, `keys;x=1`, `keys/`, `//keys`, `./keys`, `%2565`, and the same tricks
against `users` and `clients`).

---

## H5 (HIGH, FIXED) — admins could grant admin permissions they do not hold

**Found 2026-10-16, confirmed live against rc.11.** A `manage-users` admin called
`POST /admin/realms/r/users/{self}/roles` with the `admin` role and became realm admin; a `manage-roles` admin could
make `admin` the realm's default role, so every new user became an administrator. The same held for group roles and
group membership, service-account roles (whose realm roles feed admin bearer tokens), the realm import's `adminRoles`
slice (needs only `manage-realm`) and SCIM group membership.

**Fix.** `AdminGrantGuard`: a role confers its admin-RBAC grants, and the role named `admin` confers `realm-admin` by
its name (`admin_<realm>` authority). Assigning or removing such a role — user roles, group roles, group membership,
service-account realm roles, SCIM membership, realm import — needs the role's permissions to be a subset of the
caller's own, and `realm-admin` for a role conferring `realm-admin`; enforced in the services and in the controllers.
Changing admin grants needs `realm-admin` (the `admin-roles` route already did; the service now checks too, which
covers realm import). A role with admin permissions cannot be the default role (`400`), and the default role cannot be
given admin permissions. Existing default roles with admin permissions are reported at start-up (WARN +
`DEFAULT_ROLE_HAS_ADMIN_PERMISSIONS` audit event), not changed, and no longer handed to new users. Not applicable:
identity-provider mappers map claims to attributes only (no role mapping); DCR assigns no roles; organization roles
carry no admin permissions. Code outside any request (start-up bootstrap) is not restricted; a request without an
authenticated admin (SCIM) holds no admin permission.

**Second part — acting on a more privileged principal (also present in rc.11, found by live probes).** Without
handing out a role, a lower admin could still take over an administrator: `view-clients` could read an admin service
account's client secret (`GET /clients/{id}/secret`) and `manage-clients` could set or rotate it, then sign in as
that service account; `manage-users` could impersonate a realm admin or reset their password, change their e-mail
(then reset the password by mail), disable or delete them; SCIM could do the same to admins; an external IdP login
whose verified e-mail matched an administrator was linked to that administrator automatically; and a service-account
role of type `CLIENT` without a client was accepted.

**Fix.** `PrivilegedPrincipalGuard`: an admin action that targets a principal whose effective admin permissions (user:
direct and group roles; client: its service account's realm roles) are not a subset of the caller's own is `403` —
impersonation, password, credentials (TOTP, WebAuthn, recovery codes, devices), required actions, profile, e-mail,
username, enable/disable, GDPR erasure and deletion of users; revealing, setting or rotating the secret of, updating
(authentication method, keys, JWKS, redirect URIs, grant types) and deleting clients. Checked by
`PrivilegedPrincipalInterceptor` on `/admin/realms/{realm}/users/{id}/**` and `/clients/{id}/**` and again in the
services (`UserAdminService`, `ClientAdminService`, `ImpersonationService`), and for SCIM. Revoking sessions stays
allowed. Revealing a client secret needs `manage-clients` (it needed `view-clients`). `IdentityBroker` never links an
identity by e-mail to a user holding any admin permission: that user links it from the account console (OIDC, SAML,
eID and LDAP go through it; wallets never link by attribute). A `CLIENT` service-account role needs its client
(`400`). The unused `TenantService.save(TenantUser)` was removed.

**Trust bindings and sign-in clients** (final round, also present in rc.11): `manage-realm` could bind its own
workload-identity issuer to an admin service account (and the realm import's workload-identity slice could too), and
bind an agent to an admin service account or give it admin roles; `manage-clients` could add a redirect URI to the
built-in `helix-console` client and receive the master admin's authorization code. Workload-identity and agent
create/update/delete now act on the bound client (`requireMayActOnClient`, controller and service, so the import is
covered) and agent realm roles go through `AdminGrantGuard`; on the built-in sign-in clients (`helix-console`,
`helix-cli`) every change except the cosmetic name, description and "always display in console" needs `realm-admin`
— judged on the state the write produces (a missing list empties it), and including their roles, mappers and other
sub-resources. A client's privilege includes the realm roles of an agent bound to it, and suspending, activating or
revoking an agent is acting on it. Verified covered already: `private_key_jwt`/`jwks_uri`, mTLS subject and token-exchange
policies (client updates and `/clients/{id}/**` writes); DCR binds no existing client. `manage-X` now includes `view-X`
when permissions are compared.

**Who is acting is declared, never inferred** (review follow-up): an earlier fix decided "admin action" from the raw
URI and skipped enforcement otherwise (fail-open, the H4 pattern). The acting principal is now an explicit
`AdminActor`, declared by `AdminAuthorizationManager` where it authorises an admin route, by SCIM and DCR (no admin
permission) and by self-service (the user's own account only); internal work runs in `AdminActor.asSystem(...)`
(three reviewed callers, listed in the design doc). Without an actor, actions touching admin permissions are refused.
A target's privilege is evaluated like the authoriser's: `admin_master` (a master admin administers every realm) and
`admin_<realm>` reach the realm, so a master admin who is a member of a realm is protected there too.

**Tests.** `AdminGrantEscalationE2eTest` (the live scenario: `manage-users` self-assigns `admin` → 403;
`manage-roles` sets `admin` as default → 400; groups, service accounts, the grant editor, realm import, SCIM, the
start-up report) and `PrivilegedPrincipalE2eTest` (client secret reveal/set/rotate, client update and delete,
impersonation, password, profile and status, required actions, credentials, GDPR erasure, deletion, SCIM; ordinary
users and clients stay manageable; a realm admin may act on any of them), `IdentityBrokerTest`.

**Systematic sweep (round 6).** Instead of more case-by-case fixes, every admin write endpoint (141), every
realm-import slice (25) and every SCIM and DCR write was inventoried and classified by what it reaches: (a) a
privileged principal's credentials, identity, links or status; (b) how it signs in or which tokens it gets; (c) what
trusts it; (d) the roles and permissions in tokens. Anything in a to d needs the subset rule or realm-admin in the
service layer, so REST and import share the check. The table, with a guard or a reason for every row (77 endpoints and
15 slices guarded), is in `docs/superpowers/specs/2026-10-16-byo-realm-keys-design.md` (Revision 3). Closed by the sweep:

- **IdP re-pointing took over a linked admin (HIGH).** A `manage-identity-providers` admin could point an identity
  provider that a realm admin was linked to at their own issuer and sign in as that admin. Changing or deleting such a
  provider now needs the linked administrators' permissions; the same applies to trusted lists used by wallet
  providers. Links record their provenance (`federated_link.created_via`: JIT, AUTO, SELF, WALLET); an administrator
  signs in only through a link they made themselves (JIT, SELF, WALLET), never through an e-mail-matched (AUTO) or
  unknown one. No admin API creates links.
- **Applications of the sign-in clients (MEDIUM).** Their flow, subject claim and enabled flag, and deleting them
  (which soft-deleted the console client), need realm-admin; deleting any Application needs the permissions of every
  child client it removes.
- **Squatting `helix-cli` (MEDIUM).** A `manage-clients` admin could create `helix-cli` with its own redirect URI in a
  realm that lacked it. Creating either sign-in client id needs realm-admin; `helix-cli` is seeded with every realm,
  and its redirect URIs, grant types, public flag and secret are reset to the built-in values on every start (WARN +
  `SIGN_IN_CLIENT_RECONCILED` audit).
- **Import bypassed the sign-in client sub-resource check (LOW).** Mapper and allowed-resource writes call
  `requireMayChangeSignInClient` in the services.
- **Flows.** The browser flow and the flows of the sign-in clients and their Applications need realm-admin to change,
  rename, create (under that name) or delete.
- **Found by the inventory:** messaging providers and templates, the MFA policy, magic links, the subject claim and
  the realm's sign-in policy settings need realm-admin; registering a push device for a user needs that user's
  permissions; deleting a group or role, or moving a group, needs the permissions it grants.
- **Route level:** manage-X satisfies view-X routes (users, clients, identity providers, events).

Tests: `SignInSurfaceE2eTest` (one scenario per guarded row: the lower admin gets 403, a realm admin of the realm
gets 2xx, import leaves the protected value unchanged; the IdP takeover is replayed against a stub IdP, AUTO refused and
JIT accepted), `IdentityBrokerTest`, `LinkProvenanceTest`, `FlywayRealmKeyCertificatesTest` (provenance backfill).

---

## Section-by-section

### 2. Migration authz — see C1, M1.
No `@EnableMethodSecurity` exists in the codebase, so the only two `@PreAuthorize` annotations
(`TenantService.java:160,177`, `hasRole('ROLE_ADMIN_'+#role.tenantId)`) **do nothing** (M1). Combined with C1,
the effective authorization posture of the merged service is: HTTP-layer gate on `/admin/**` that fails open,
and no method-layer enforcement. The migration removed the `@SecuredListener` boundary without a working
replacement. This is the dominant risk of the review.

### 3. Token & key security
- Per-realm signing keys with `ACTIVE→ROTATED→RETIRED` lifecycle and JWKS overlap for zero-downtime rotation
  (`RealmKey.java`); rotation exposed via admin API. **Good design.**
- RS256 + PS256 advertised (FAPI metadata customizer, `SecurityConfig.java:120`). Reasonable.
- `RealmKeyView` (admin/JWKS DTO) carries only public material — private key never serialized to the API
  (`amqp/key/RealmKeyView.java`). **Good.**
- Private key at-rest encryption depends entirely on `AttributeEncryption` → see **H1/H2** (the weak link).
- Key rotation endpoint is reachable per C1 by unauthenticated callers — an attacker can **retire** all keys
  (DoS) or rotate to force re-issue. Fixing C1 closes this.

### 4. Password & credential handling — mostly strong
- **Argon2id** (`Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()`), constant-time legacy SHA-256 verify
  (`MessageDigest.isEqual`), transparent re-hash on login (`PasswordEncoderService.java`). **I1, good.**
- Password policy + reuse history + HIBP k-anonymity, realm-gated (`PasswordPolicyEnforcer`,
  `BreachedPasswordChecker`). Lockout wired (`LoginFailureService`, `LockedException` handled at
  `SecurityConfig.java:315`). **I3, good.**
- HIBP is **fail-open** on outage (documented, acceptable).
- Admin bootstrap: generates a 24-byte random URL-safe password when `HELIX_ADMIN_PASSWORD` unset — no shipped
  `admin/admin`. **Good**, but it is written to logs (`RealmAdminBootstrapService.java:91`) — **L6**, acceptable
  for first-boot but prefer a one-time file/secret and a forced change-on-first-login.

### 5. SAML security
Focused sub-review of `authorization/idp/saml/**`, `federation/saml/**`, `federation/eid/**`. Stack:
Spring Security SAML2 6.5.10 over **OpenSAML 5.1.4** (transitive; upgraded from 4.3.2 — M7) + Apache `xmlsec` 3.0.5.
- **M7 (dependency currency) — FIXED (2026-09-17):** OpenSAML was upgraded from the EOL 4.3.2 to **5.1.4**
  and Santuario `xmlsec` from 2.3.4 to **3.0.5** (with `net.shibboleth:shib-*:9.1.4` replacing the repackaged
  `java-support:8.4.2`, and cryptacular 1.2.5 → 1.2.6). The SAML IdP/SP is now on the supported XML-security
  stack. Only the `net.shibboleth.utilities.java.support.xml.*` imports moved to `net.shibboleth.shared.xml.*`;
  the signature/decryption/conditions validation logic is unchanged and all SAML/eID security tests pass.
- Detailed XXE / signature-verification / XML-Signature-Wrapping / ACS-URL-validation findings from the SAML
  sub-review are listed in **Appendix A** (SAML sub-review). _Note: `xmlsec` is now on the current **3.0.5**
  line (was 2.3.4, the patched CVE-2023-44483 line) as part of the OpenSAML 5 upgrade (M7)._

### 6. Session & web — see M2–M5 (from the session/CORS sub-review)
- No explicit session-cookie hardening; relies on Spring Session Redis defaults (`HttpOnly=true`,
  `SameSite=Lax`, `Secure=request.isSecure()`). `Secure` not pinned + no forwarded-header strategy → **M4**.
- CSRF enabled (`CookieCsrfTokenRepository.withHttpOnlyFalse()` + `CsrfCookieFilter`) for the SPA; state-changing
  admin writes require the token in prod. XSRF cookie `Secure` not forced → **M5**.
- CORS is **correctly** per-realm/per-client specific-origin reflection with credentials; unknown origins denied;
  filter runs pre-auth (`RealmClientCorsConfigurationSource`, `RealmCorsFilterConfig`). The one gap: a realm
  origin list containing `*` still reflects-with-credentials → **M2**.
- Security headers: Spring defaults present (`X-Content-Type-Options`, `X-Frame-Options: DENY`, HSTS on HTTPS).
  **No CSP** on login/consent/MFA pages → **M3**.

### 7. Dangerous flags / endpoints
- `helix.admin.dev-open` defaults **false**, not set in `application-dev.properties`, and gated in both
  `SecurityConfig.java:243` and `AdminAuthorizationManager.java:54`. **Correctly off by default**; clearly
  documented "NEVER enable in prod". (Its danger is now moot next to C1, which opens `/admin` even without it.)
- Actuator exposure limited to `health,info,prometheus` (`application.properties:90`); `env`/`beans`/`configprops`
  **not** exposed. `prometheus`+`info` anonymous → **L2** (metric/label and build-info disclosure). Swagger +
  `/v3/api-docs` public → **L3**.

### 8. Secrets & config defaults
- SAML IdP signing key externalized to `${HELIX_SAML_IDP_SIGNING_*:}` (empty default) — **good**.
- DB password empty default in prod profile (`${DB_PASSWORD:}`); dev profile uses `password` (dev-only) — fine.
- **Exception:** the at-rest encryption key ships a real default (**H1**). This is the one hardcoded secret and
  the most serious config-defaults issue.
- No TLS/`forward-headers-strategy` guidance in config (**M4**); document that HelixIAM must run behind TLS with
  scheme forwarding.

### 9. Input validation / injection
- Bean Validation (`@Valid` + `AdminValidationAdvice` `@RestControllerAdvice`) on 25 admin controllers — **I2**.
- Persistence uses Spring Data / JPA (`FilterSpecification`) — no raw SQL string-building observed in the admin
  path; low SQL-injection surface.
- **SSRF (M6):** several server-initiated HTTP clients fetch **admin-configured** URLs — `WebhookDispatcher`,
  `ScimProvisioningDispatcher`, `HttpOidcTokenClient` / identity-provider config (token/JWKS URIs),
  `HttpCaptchaVerifier`, `HttpAuditForwarder`, `UpstreamLogoutClient`, `federation/eid` artifact resolver. These
  are SSRF vectors to internal networks/metadata endpoints. Normally admin-gated, but **C1 removes that gate**,
  so any caller can point them at internal targets. After fixing C1, add egress allow-listing / block
  link-local + private ranges for outbound fetches.
- No SpEL-from-user-input or reflective dispatch observed in the reviewed surface.
- **JSON deserialization (re-checked at the Jackson 3 move, 2026-10-15).** No polymorphic typing anywhere: no
  default typing, no `@JsonTypeInfo`, no Spring Security Jackson modules; authorizations and sessions are stored with
  Java serialization behind JEP-290 allowlists that admit no Jackson class. Untrusted wallet input is parsed only by
  the strict mappers (`StrictJson`: depth 64, duplicate members and trailing tokens refused; status-list tokens depth
  16; LoTE lists 1 MB strings) and `StrictCbor` (own depth/item/byte limits). Every mapper keeps Jackson 2's 20 MB
  string limit and Jackson 3's 500 nesting limit (Jackson 2: 1000); `JsonMappersTest` and `JsonWireFormatE2eTest`
  pin them. Jackson 3's exceptions are unchecked: the `catch (IOException)` clauses around wallet, status-list and
  theme parsing were widened to `JacksonException`, so malformed input is still refused with its error code rather
  than escaping as a 500.

---

## Dependency scan summary

**OWASP dependency-check did NOT run** — the plugin needs the NVD data feed and this environment is offline
(`mvn -o` only). The following is a **manual CVE-class assessment** from `mvn -o dependency:tree` output plus
reviewer knowledge; it is **not** a substitute for a real scan, which must be run in CI before release.

Actual resolved versions (from the offline tree):

| Dependency | Version | Assessment |
|---|---|---|
| Spring Boot (parent) | 3.5.14 | Current line; OK |
| spring-security-* (core/web/saml2) | 6.5.10 | Current; OK |
| tomcat-embed-core | 10.1.54 | Boot-managed, recent; OK |
| opensaml-* | **5.1.4** | Current 5.x line — **M7 FIXED** (was 4.3.2 EOL); `opensaml-core` split into `core-api`+`core-impl` |
| net.shibboleth:shib-* (support/security/networking/velocity) | **9.1.4** | OpenSAML 5's repackaged shared libs — replaces `net.shibboleth.utilities:java-support:8.4.2` (M7) |
| org.apache.santuario:xmlsec | **3.0.5** | Current 3.x line — **M7 FIXED** (was 2.3.4) |
| cryptacular | 1.2.6 | Bumped with OpenSAML 5 (was 1.2.5); OK |
| nimbus-jose-jwt | 9.47 | Recent; OK |
| jackson-databind / core | 2.21.2 | Recent; OK |
| postgresql | 42.7.10 | Recent (CVE-2024-1597 fixed); OK |
| BouncyCastle (bcprov/bcpkix/bcutil) | 1.81 | Recent; OK (above the 1.78 CVE line) |
| webauthn4j-core/util | 0.21.5.RELEASE | Recent; OK |
| log4j-core | 2.24.3 | Post-Log4Shell; OK |
| snakeyaml | 2.4 | 2.x (constructor-RCE fixed); OK |
| flyway-core / -postgresql | 11.7.2 | Recent; OK |
| **com.google.guava** | **31.1-jre** | **CVE-2023-2976 / CVE-2020-8908** (temp-dir) — **L1**, bump to ≥32.0.1 |
| spring-boot-devtools | (Boot) | **L4** — keep out of release artifacts |

**Action:** run OWASP dependency-check (or Trivy/Grype on the built image) in CI with a fresh NVD feed and gate
the release on it.

---

## Threat model (concise, STRIDE-oriented)

**Assets:** realm signing **private keys** (token-forgery master material); issued access/ID/refresh tokens;
user credentials (Argon2id hashes, TOTP secrets, WebAuthn); realm/tenant configuration; admin sessions; the
audit log.

**Trust boundaries:** anonymous internet → login/OAuth/SAML/discovery; authenticated user session; **admin API
(`/admin/**`)**; realm-to-realm (multi-tenant isolation); server → external SSRF targets (webhooks, IdP JWKS,
HIBP, SCIM); server → Postgres/Redis/SMTP.

| STRIDE | Threat | HelixIAM posture |
|---|---|---|
| **Spoofing** | Forge tokens by stealing a realm private key | Keys per-realm, encrypted at rest — but **H1** (known default key) + **H2** (plaintext fallback) undermine this; PS256/RS256 supported. |
| **Tampering** | Unauthorized admin writes (users, keys, clients, IdPs) | **C1: default-open `/admin/**`** — critical exposure; CSRF present but not a control against an unauthenticated attacker. |
| **Repudiation** | Deny admin/auth actions | Audit log on login success/failure and admin ops (`AuditLog.emit`) — good; but `/admin/audit` is itself C1-exposed (attacker could tamper config). |
| **Information disclosure** | Leak secrets/details | **H3** verbose errors; **L2/L3** actuator+API-docs public; DB-dump → private keys via **H1**. Realm keys API correctly hides private material. |
| **Denial of service** | Lock out tenants / exhaust | **C1** lets anyone retire all realm keys or lock accounts; rate-limiting exists for login (`RateLimitFilter`). |
| **Elevation of privilege** | Non-admin / cross-tenant → admin | **C1 + M1** — the core failure: any (even anonymous) caller reaches any realm's admin surface; method guards inert. |

**Multi-tenant isolation** is the property most at risk: it depends almost entirely on the `/admin/**`
authorization that C1 shows is default-open, and there is no controller-level principal↔realm check.

---

## Top priorities before release

1. **Fix C1** — make `/admin/**` require authentication as a hard gate, make `AdminAuthorizationManager`
   fail **closed**, and add a controller/method-level check that the principal is an admin of the path realm.
   Add anonymous + non-admin negative integration tests. *(Blocker.)*
2. **Fix H1/H2** — remove the shipped `database.encryption` default (fail fast in prod), use a real KDF, and
   make encryption failures fail closed instead of writing plaintext. Rotate data encrypted under the default.
3. **Enable method security** (`@EnableMethodSecurity`) so the existing `@PreAuthorize` guards actually run
   (M1), and use it as defense-in-depth behind the URL rules.
4. **Set `server.error.include-message=never`** (H3) and lock down prod cookie/transport
   (`server.forward-headers-strategy=framework`, `session.cookie.secure=true`, force XSRF `Secure`) — M4/M5.
5. **Add a CSP** to the login/consent/MFA chain (M3); reject `*` realm web-origins with credentials (M2).
6. **Fix SAML assertion binding (S-H1/S-H2)** — DONE. The bearer `SubjectConfirmationData` is validated
   (Recipient/NotOnOrAfter) and the signed **assertion's** Issuer is checked on the generic-SP path. The
   residual `InResponseTo` binding is now closed (issue #2): the broker persists the outbound AuthnRequest id
   server-side and the validator requires a solicited assertion's `InResponseTo` to match it (single-use);
   unsolicited/IdP-initiated is gated by `SamlProviderConfig.allowIdpInitiated` (default off).
   Still open: cap DEFLATE inflate (S-M1) and move the replay cache to Redis for clustering (S-M2).
7. **Harden SSRF** egress once C1 is closed (M6); wire **OWASP dependency-check/Trivy in CI**. The
   **OpenSAML 4.3.2 → 5.1.4** upgrade (M7) is DONE; bump guava (L1); keep devtools out of release images (L4).
8. **Commission the independent third-party audit + penetration test** — required before production/public
   release; this self-review does not substitute for it.

---

## Appendix A — SAML/XML sub-review

Stack: `spring-security-saml2-service-provider` 6.5.10 → OpenSAML **4.x** (`net.shibboleth...ParserPool` imports
confirm 4.x). All SAML/eID XML flows through OpenSAML's `XMLObjectProviderRegistrySupport.getParserPool()`;
there is **no** custom `DocumentBuilderFactory`/`SAXParser`/`TransformerFactory` in `src/main`, and no naive
`getElementsByTagName` claim extraction.

### Positive / correctly handled (INFO)
- **XXE mitigated** — every parser uses OpenSAML's hardened default `BasicParserPool`
  (`OpenSamlAssertionValidator.java:91`, `OpenSamlEidAssertionValidator.java:127`,
  `SamlAuthnRequestParser.java:152`, `SamlLogoutRequestParser.java:81`, `SamlSpMetadataParser.java:46`,
  `OpenSamlEidArtifactResolver.java:171`); no pool is weakened. Residual: hardening is implicit (library
  default) with no defense-in-depth DOCTYPE-rejection test.
- **XSW largely mitigated** — both validators run `SAMLSignatureProfileValidator` before
  `SignatureValidator.validate` and read claims from the *validated* object, not a DOM re-query
  (`OpenSamlAssertionValidator.java:105-106`, `OpenSamlEidAssertionValidator.java:148-149`).
- **Signature mandatory / fail-closed** — at least one of Response/Assertion signature required
  (`OpenSamlAssertionValidator.java:101-104`, `OpenSamlEidAssertionValidator.java:144-146`); default bean is
  `UnconfiguredSamlAssertionValidator` (throws). No `wantAssertionsSigned=false`/skip toggle on the inbound path.
- **IdP ACS validation — no open redirect** (`SamlIdpController.resolveAcs()` `:298-309`).
- **SP callback CSRF** — `RelayState == expectedState` enforced (`Saml2IdentityProvider.callback()` `:75-77`).
- **eID back-channel** — signed `ArtifactResolve`, mTLS with chain verification, status-success check
  (`OpenSamlEidArtifactResolver.java:154-195`); inner assertion still fully signature-verified.

### SAML findings

| ID | Sev | File:line | Risk | Recommendation |
|----|-----|-----------|------|----------------|
| S-H1 | **HIGH — FIXED** | `OpenSamlAssertionValidator.java` `verifySubjectConfirmation`/`verifyInResponseTo`; `FederationBrokerController` `REQUEST_ID_ATTR`; `Saml2IdentityProvider.start` | Bearer assertion not bound to the in-flight AuthnRequest; stolen/misdelivered bearer assertions not caught | DONE: bearer `SubjectConfirmationData` validated (Recipient == our ACS + NotOnOrAfter). InResponseTo binding closed (issue #2) — the broker persists the minted AuthnRequest id server-side (session, keyed by alias) and consumes it single-use; a solicited assertion's `InResponseTo` MUST equal it, unsolicited SSO gated by `SamlProviderConfig.allowIdpInitiated` (default off). |
| S-H2 | **HIGH** | `OpenSamlAssertionValidator.java:66` | Generic-SP path checks `Issuer` only on the (possibly unsigned) Response, never on the signed Assertion → issuer check bypassable on unsigned-Response path (eID path does it right at `OpenSamlEidAssertionValidator.java:86-88`) | Check `assertion.getIssuer()` against expected IdP entityID |
| S-M1 | MEDIUM | `SamlAuthnRequestParser.java:169-175`; `SamlLogoutRequestParser.java:98-104` | Unbounded DEFLATE inflate on unauthenticated `/saml/idp/sso` + `/saml/idp/slo` → decompression-bomb DoS | Cap inflated output (reject > ~1 MB) |
| S-M2 | MEDIUM | `InMemorySamlAssertionReplayCache.java` | In-memory replay cache is per-node → cross-node assertion replay in multi-instance deployments | Back the replay cache with the shared Redis |
| S-M3 | MEDIUM | `OpenSamlAssertionValidator.java:69`; `OpenSamlEidAssertionValidator.java:81` | Response `StatusCode` never checked before consuming assertions | Require `StatusCode.SUCCESS` first |
| S-L1 | LOW | `SamlAuthnRequestParser.java:138-146` | `rsa-sha1` accepted and unknown `SigAlg` silently defaults to SHA-256 | Allowlist SHA-256/384/512, reject SHA-1/unknown |
| S-L2 | LOW | `OpenSamlAssertionValidator.java:62`; `OpenSamlEidAssertionValidator.java:78` | `expectedRelayState` parameter accepted but unused (validator doesn't independently bind the response) | Use or remove |
| S-L3 | LOW | `SamlIdpController.java:42,176` | Process-wide `FORCED_REQUESTS` set never pruned (slow DoS); ForceAuthn is one-shot per request ID | Bound/expire the set; session-scope ForceAuthn |
| S-L4 | LOW | `SamlIdpController.java:152` vs `:424` | AuthnRequest signature verification default-OFF while published metadata advertises `WantAuthnRequestsSigned="true"` | Default-require signed AuthnRequests, or align metadata to actual setting |
| S-I1 | INFO | `SamlSpMetadataParser.java` | SP metadata parsed without signature verification (acceptable while admin-pasted only) | Verify XML signature if metadata ever comes from URL/upload |
| S-I2 | INFO | `OpenSamlEidArtifactResolver.java:196-197` | eID ArtifactResponse accepted when unsigned (mitigated by mTLS + downstream assertion sig) | Consider requiring ARS signature for DigiD |

### Combined severity tally (main review + SAML sub-review)
**1 CRITICAL · 5 HIGH · 10 MEDIUM · 10 LOW · several INFO.**
(HIGH = H1, H2, H3, S-H1, S-H2. The dependency currency item M7 — the OpenSAML 4.x EOL underlying the SAML
stack — has since been FIXED by upgrading to OpenSAML 5.1.4 / xmlsec 3.0.5 on 2026-09-17.)

---

## Appendix B — EUDI Wallet (OpenID4VP verifier) threat model (Task 26, 2026-10-12)

This section was produced the same way as the rest of this document: an internal engineering self-review, with a
dispatched adversarial re-review at the point the one Critical finding below (§6.5 bypass) was fixed. It is
**not** an independent third-party audit; the same caveat and "required before release" statement at the top of
this file applies to the wallet feature too. Scope: `io.helixiam.authorization.federation.wallet.*` and its
callers in `security/flow`, `controller/account/console`, `controller/admin`.

### B.1 QR relay (cross-device flow)

The cross-device flow hands the wallet a request it fetches and answers over its *own* network path, with no
browser session of its own — this is inherent to QR-based presentation, not a HelixIAM-specific risk, but it
shapes several of the mitigations below:
- The relay window is the transaction TTL: **300 s by default, 60–900 s configurable**
  (`WalletProviderConfig.DEFAULT_TRANSACTION_TTL_SECONDS`). A QR scanned after expiry is an unknown transaction,
  reported generically ("expired or unknown") rather than distinguishing the two — a transaction ID is never
  confirmed to have existed to an unauthenticated prober (ledger Task 16 ruling).
- A cross-device `response_code` is issued **exactly once, atomically**, only to a `VERIFIED` transaction whose
  stored browser binding matches
  (`WalletTransactionStore#issueResponseCode`, introduced in Task 16's fix round); a second call for the same
  transaction gets nothing.
- See §6.3 of `docs/eudi-wallet.md` for the residual reverse-linking-CSRF risk this flow carries into the account
  console's "link an existing account" variant — an inherent limit of any cross-device presentation protocol, not
  something closed by code here.

### B.2 Replay and single-use

Every identifier the protocol hands to the wallet or expects back (`transactionId`, request/response ids,
`nonce`, `response_code`) is `SecureRandom`-generated at ≥128 bits and enforced single-use **atomically** at the
store (`WalletTransactionStore#redeem`: "Keeps the `WalletTransaction`s and makes every state transition atomic
and single use"). One deliberate exception, the request ids: the first fetch binds the transaction to that flow (the other
request id is refused from then on), and the **same** request id may be fetched again while the transaction is
`REQUEST_FETCHED`; once the response has been received, or the transaction has ended or expired, it is 404
(`claimRequest`, one atomic step in all three stores; `AbstractWalletTransactionStoreTest` runs the cases against
memory, Redis and PostgreSQL). **Ruling (2026-10-15, conformance run D2):** wallets retry a `request_uri` fetch after
a network error and the HAIP certification plan tests it. A re-fetch exposes nothing new: the request is the same
signed request (`iat` is the transaction's creation; the claims are identical unless an admin edits the provider
between fetches, since `response_mode` and `client_metadata` come from the live config, and a POST fetch carries its own
`wallet_nonce`), it reaches only whoever already holds that bearer id, and the response stays strictly single use and
encrypted to the verifier's key, so the extra fetch cannot be turned into a second answer.

**Residual risk of the re-fetch (accepted with the ruling).** Before D2, someone who saw a cross-device QR code and
fetched its request after the real wallet got a 404. Now they get the request too, and the real wallet does not
notice. With it they can:
- **race their own response** with their own wallet: sign in as *themselves* in the victim's browser session (the session fixation that OpenID4VP §14.2 says its response-code protection cannot stop in cross-device flows), or, in an account console "Link
  wallet" flow, link *their own* PID to the victim's account (the reverse linking-CSRF of `docs/eudi-wallet.md` §6.3,
  which the "wallet linked" email notice is there to surface). They cannot answer *as* the victim: the PID and its
  holder binding are theirs, and the response is single use, so only the first answer counts;
- **cancel the real login** by posting a malformed response first (`fail()` after the single-use claim), a nuisance
  the real user resolves by starting again.

QR-observation phishing of this kind was already possible before D2: an observer could scan the QR before the real
wallet did and take the request then. D2 only removes the "first fetch wins" ordering. What D2 does *not* add: a
request id fetched under another realm or alias used to fail the transaction (`OpenId4VpVerifierController`, the
`ownedHere` mismatch branch); that branch now answers 404 and leaves the transaction alone, so a re-fetch under the
wrong path cannot cancel the real wallet's login (`WalletWebControllersTest`). A *response* posted under another
realm or alias still fails its transaction, as before: the response was single use already. A second redemption attempt with a correct code does not "burn" the transaction for a third
party who does not hold the code — burning on mismatch would let anyone who merely observes/guesses a
`response_code` cancel the legitimate holder's login, which is a worse outcome than letting the real holder retry
(ledger Task 16 ruling). The `_sd`/`...` disclosure digests inside a credential, the KB-JWT/DeviceSignature,
and the SD-JWT `sd_hash` are each checked individually on top of this transaction-level replay protection.

**Defence-in-depth note (Task 23):** over a real HTTP round-trip, re-submitting the *exact same* callback URL a
second time from the same browser session does not surface as `REPLAY` — it surfaces as `STATE_MISMATCH`. The
generic federation broker (`FederationBrokerController`/`security/flow`) consumes its own session-held expected
state on the **first** callback for *any* protocol (OIDC, SAML, wallet alike), before the wallet-specific
`WalletIdentityProvider.redeemTransaction` (`WalletIdentityProvider.java:248-268`) even gets a chance to run its
own `response_code` replay check against the transaction store. Both outcomes refuse the second request; the
error code you observe is a byproduct of check ordering across two independent layers (generic broker
anti-CSRF state, then wallet-specific transaction redemption), not a gap — if the first layer's protection were
ever removed, the second layer's `REPLAY` code would still refuse it.

### B.3 Browser binding is a session *attribute* secret, never the session id

The login (and account-linking) flow is bound to the browser that started it via `BrowserBinding`
(`helix-iam-server/src/main/java/io/helixiam/authorization/security/flow/BrowserBinding.java`): at `start()` the
broker generates a random 128-bit secret, stores it as an **HTTP session attribute** keyed by provider alias
(`HELIX_FED_BINDING_<alias>`), and hands the wallet transaction only `base64url(SHA-256(secret))`. Every later
step — the login callback and the wallet page's cross-device status/code issuance — recomputes the hash from the
session and compares it to the one stored on the transaction.

Deliberately **not** the session id: Task 2 (this same plan) found and fixed a pre-existing gap where the session
id was not rotated on a federated login, and ids rotate on `request.changeSessionId()` elsewhere in the login
path. A secret kept as a session *attribute* survives that rotation (attributes move with the session), where a
binding keyed on the id itself would silently stop matching after rotation. This also means the binding has
nothing in common with the session cookie an attacker might otherwise try to fixate or guess.

### B.4 `helixState` never reaches the wallet

The broker's own CSRF state (`helixState`) is session-scoped browser-side state with no meaning to a wallet or to
the mobile device that might scan a QR code. The OpenID4VP request object's `state` parameter is instead
`base64url(SHA-256(transactionId))` (`AuthorizationRequestFactory.walletState`,
`helix-iam-server/src/main/java/io/helixiam/authorization/federation/wallet/AuthorizationRequestFactory.java:129-131,223`)
— deterministic from information the wallet already has (the transaction id is embedded in the request/response
URLs it fetches and posts to), recomputable by the response handler to check the decrypted response's `state`
claim, and carrying zero information about the browser's own anti-CSRF secret. An earlier design draft would have
threaded `helixState` through to the wallet-facing redirect; this was caught and fixed in Task 18's own code
review before merge (`task-18-review.md`), not something later Task 26 found.

### B.5 SSRF via status lists

Every Token Status List fetch (`TokenStatusListClient`) goes through the same `OutboundUrlGuard` every other
admin-configurable outbound HTTP call in HelixIAM uses (webhooks, SCIM, OIDC/eID discovery and JWKS, HIBP, audit
forwarding): `https` only, no loopback/private/link-local/cloud-metadata destination. Unlike those callers, the
status-list fetch (and every redirect hop, each re-vetted) runs over `PinnedHttpFetcher`: the guard resolves the host
once (`OutboundUrlGuard.resolveAllowed`) and the socket connects to one of the addresses it checked, never to the
name, so a resolver that answers differently the second time (DNS rebinding) cannot move the connection; TLS is still
verified against the host name. That resolution runs inside the 5 s deadline, so a slow resolver cannot hold a login
past it. A `status_list.uri` that fails these checks, or that is not in the operator's `statusList.allowedHosts`
when that allow-list is configured, is refused **by policy, before any connection** and is always treated as
"cannot be fetched" rather than "unavailable" — it is never given the fail-open path even under
`FAIL_OPEN_WITH_AUDIT` (ledger Task 10 ruling), because the URI is issuer-signed content, not something an attacker
can toggle per-request the way they could an HTTP response code. Verified lists are cached in one `StatusListCache`
shared by every provider, bounded by entry count (`helix.wallet.status-list.cache-max-entries`, 64) and by total
decoded list bytes (`helix.wallet.status-list.cache-max-bytes`, 32 MB; before, about 128 MB in the worst case). See
also §4/§5 of `docs/eudi-wallet.md` — this branch has no `trustedProxies` setting, so `OutboundUrlGuard`'s own egress
decisions are the only guard in front of these fetches; there is nothing *additional* scoping which proxy the
server itself may sit behind.

### B.6 The §6.5 mdoc status-list-signer rule, and the appended-anchor bypass that was fixed

ISO 18013-5 §6.5 requires the mdoc status list's signer to be verifiably related to the credential's own `MSO`
signer. `IssuerTrustValidator`/`ValidatedChain` enforce this on the **PKIX-validated** chain and trust anchor —
never on the raw `x5chain` bytes presented in the response. This matters because an earlier implementation
enforced it on the unvalidated chain: an attacker could append an unrelated certificate to the presented
`x5chain` that happened to share *some* ancestor with a trusted anchor, satisfying a naive "do these chains share
a root" check without the list actually having been issued by anyone the operator's PID trust anchors recognise.
This was found as a **Critical** finding in Task 19's review (`task-19-review.md`), fixed in the same round, and
independently re-reviewed adversarially afterwards with no further bypass found. See `docs/eudi-wallet.md` §7.1
for the accepted, narrower residual case (a shared IACA root that also issues DS certificates directly).

### B.7 Weak-tuple (attribute-tuple) subject: residual risk

Documented in full in `docs/eudi-wallet.md` §6.2 and in `WalletProviderConfig.Subject`'s javadoc; summarised here
because it is the one wallet-specific design choice with an accepted (not eliminated) risk: when an operator opts
into `subject.acknowledgeWeakSubject=true`, a PID lacking `personal_administrative_number` can be *linked* (never
auto-provisioned) via an HMAC of a configuration-fixed attribute tuple. Two distinct people who share that exact
tuple are indistinguishable to this mechanism; if one has linked their wallet, the other's wallet resolves to the
same account. There is no stronger subject available without the administrative number, so this is accepted as a
documented trade-off gated behind an explicit admin opt-in, not treated as a defect to "fix" — doing so would
require either refusing wallets without the number entirely (closing off a real deployment scenario the
maintainer decided to support) or inventing a subject out of less entropy than the tuple already provides.

### B.8 Log hygiene

Nothing wallet-specific is ever logged at any level: `vp_token`, disclosures, PID attribute values, nonces,
`response_code`, decryption/signing keys, and — since Task 22's fix round — the wallet subject hash itself (an
earlier version logged the subject HMAC on the theory that a hash is not the raw PID; Task 22 reversed that
because the hash is still a stable, computable, cross-login correlation handle for anyone with log access, and
operators can correlate via the audit log's `transactionId` instead). What *is* logged: transaction id, provider
alias, realm, credential format, issuer DN, the result, and the `WalletErrorCode`. Every user-controlled string
that does reach a log line is passed through `LogSafe.sanitize` first. `WalletAuditE2eTest` and the booted
`WalletLoginCompleterTest`/hygiene e2e pin this for both credential formats and the JIT/link/upgrade paths
(ledger Task 22).

### B.9 Known-narrow exception handling in wallet-adjacent code (see also `DEFERRED-SECURITY-WORK.md`)

Two small, deliberate-but-narrow catch clauses are worth a reviewer's attention rather than a fix, since widening
either changes observable behaviour for callers this document has not re-verified end to end:
- `AccountIdentityController.isWallet` (and this task's new `GdprAdminService.isWalletAlias`/`displayNameOf`,
  added for §6/§GDPR below) each catch only `IllegalArgumentException` from `IdentityProviderRegistry#get` — the
  one exception type that method's own contract documents throwing for an unknown alias. Both are inert today
  (the registry has no other failure mode on this path), tracked as a deferred hardening item, not a live bug.
- `FederatedLoginCommit.commit` (`helix-iam-server/src/main/java/io/helixiam/authorization/federation/
  FederatedLoginCommit.java:44-55`) catches `RuntimeException` around a committer (the wallet's own
  `WalletPendingLinkCommit` is the only implementation today) and refuses the login on any failure — but, by Java
  convention, does not catch `java.lang.Error`. An `Error` thrown from a committer propagates uncaught with the
  session already established by the caller a few lines earlier (`FederatedLoginCompleter.complete`,
  `:158-161`). This is accepted as a JVM-level edge case (the project does not catch `Error` anywhere else
  either) and tracked in `DEFERRED-SECURITY-WORK.md` rather than papered over with a `catch (Throwable)`.

### B.10 Issuer certificate revocation (CRL / OCSP)

The CRL distribution point and OCSP responder URLs come from the presented, attacker-supplied issuer certificates,
so the fetch is an SSRF and DoS surface. The JDK no longer fetches anything for wallet issuer certificates (its
`PKIXRevocationChecker` followed redirects, re-resolved names, had no CRL size cap and no cache under our control).
`IssuerRevocationClient` fetches instead, over `PinnedHttpFetcher`:
- nothing is fetched until the chain has validated to a configured anchor, so only a trusted CA's certificates can
  name a URL;
- every URL passes `OutboundUrlGuard` (http and https only — CRLs and OCSP responses are signed, so plain http is
  normal and their signature is the integrity; `ldap:` and non-URI names are never used), the connection goes to the
  validated address (no DNS rebinding), no redirect is followed, connect 3 s and 5 s in total per fetch including
  DNS, 10 s per chain, OCSP response at most 64 KB, CRL at most `helix.wallet.revocation.max-crl-bytes` (10 MB,
  100 MB at most); strict HTTP/1.1 framing (conflicting `Content-Length`, `Content-Length` with
  `Transfer-Encoding`, signed numbers, obs-fold, a protocol switch are refused);
- concurrent logins share one download per URL (single-flight); at most `helix.outbound.fetch.wallet.max-concurrent` (16; old name `helix.wallet.fetch.max-concurrent`)
  fetches run at once, permits held until the worker ends so DNS lookups that hang cannot pile up threads; a URL
  that served something that is not a CRL (or too large a one) is not downloaded again for 60 s;
- the JDK validates and never fetches. An OCSP response goes in through `setOcspResponses` (OCSP only, no fallback;
  with a response supplied it never contacts a responder). A CRL is pre-checked (issuer name and key identifier,
  cRLSign, signature algorithm and signature, thisUpdate/nextUpdate within the JDK's own 15-minute skew, no delta /
  indirect / partial CRL, no unknown critical extension) and then handed to the JDK's **legacy** CRL checker in a
  `CertStore`. Not `PKIXRevocationChecker`: its fallback to fetching every distribution point of the certificate
  (unpinned, uncapped) is hard-wired on whenever it cannot approve a CRL — the first version of this change relied on
  the pre-check alone and a review proved that fallback reachable. The legacy checker fetches nothing while
  `com.sun.security.enableCRLDP` is off (forced off at startup); if an operator re-enables it (or `ocsp.enable`,
  `com.sun.security.enableAIAcaIssuers`, `com.sun.security.onlyCheckRevocationOfEECert`), CRLs are not evaluated
  at all and an error is logged (`JdkRevocationNoFetchTest`);
- answers are cached until `nextUpdate` (a CRL until `nextUpdate` + 15 min; 24 h at most; without `nextUpdate`, not
  at all), bounded by `helix.wallet.revocation.cache-max-entries` (256) and `.cache-max-bytes` (32 MB; a CRL counts
  an estimate of its parsed heap: 3 × its encoding + 256 bytes per revoked entry), shared by every provider.

Each certificate below the anchor is checked on its own, against its own issuer, so an undeterminable upper CA no
longer stops the check before a lower CA (the former SOFT_FAIL gap with two or more intermediates). A `REVOKED`
answer anywhere refuses. `revocationChecking` defaults to `HARD_FAIL`: a certificate whose status cannot be
determined is refused; `SOFT_FAIL` accepts it with a warning (serial and subject DN only); `OFF` checks nothing.

Status lists (B.5) use the same transport. A TLS failure (untrusted certificate, host name mismatch) or an answer
that is not valid HTTP is an integrity failure and always fails closed, also under `FAIL_OPEN_WITH_AUDIT`; only
connect / read errors, timeouts (DNS included), 5xx and unresolvable hosts are transient. A provider's own
`allowedHosts` and https rule are applied before the shared status-list cache is consulted.

**Latency.** Worst case per credential, all endpoints slow: about 25 s — 10 s for the issuer chain's revocation
budget, 5 s for the status-list fetch, and 10 s for the revocation budget of the status-list signer's chain. Cached
answers make the common case a few milliseconds.

### B.11 Trusted lists (`EuTrustedListSource`): fetching and XML signature verification (2026-10-15)

Internal self-review, not an independent audit. Scope: `io.helixiam.authorization.federation.wallet.trust.tl.*`,
`TrustedListAdminController`, and the `trustedLists.*` path in `WalletIdentityProviders` / `WalletConfigValidator`.
A trusted list is a **trust root input**: whoever can make HelixIAM accept a forged list can mint PIDs it trusts.

**Assets.** The set of PID issuer anchors per realm; the pinned signer certificates; the availability of wallet
sign-in.

**Threats and mitigations.**

| Threat | Mitigation | Test |
|---|---|---|
| Forged or modified list (network attacker, compromised host, malicious mirror) | Signature must verify with an **admin-pinned** signer certificate; the list's own `KeyInfo`/`x5c` is never trusted; for a LOTL each pointed-to list must verify with the signer **the verified LOTL** names for it, and carry the `SchemeTerritory` and `TSLType` the pointer names | `TrustedListLoaderTest` tampered / added service / other signer / member wrong signer / territory-type mismatch |
| XML signature wrapping (valid signature over one element, data read from another) | Exactly one `ds:Signature` in the document, a direct child of the root; a reference with the enveloped-signature transform must cover the whole document (`URI=""`) or the root by its `Id`; the list is then read from that same root; duplicate `Id` attributes refused | `signatureThatDoesNotCoverTheWholeList_isRefused`, `duplicateIds_areRefused` |
| Reference tricks (external URIs, XPath/XSLT subsetting, weak algorithms) | Only same-document references; only enveloped-signature and canonicalization transforms; signature RSA, RSASSA-PSS with MGF1 and a fixed hash (`sha*-rsa-MGF1`; the parameterised `rsa-pss` identifier refused) or ECDSA with SHA-256/384/512, checked on the DOM before Santuario parses it; reference digests SHA-256/384/512 only, checked by HelixIAM (Santuario `secureValidation=true` refuses MD5 but **not** SHA-1 digests; it bounds references/transforms) | `sha1ReferenceDigest_isRefused`, `ecdsaSha1Signature_andParameterisedRsaPss_areRefused` |
| XXE, entity expansion, XInclude, deep nesting, huge documents | JDK built-in parser with `disallow-doctype-decl`, no external entities/DTD/schema, XInclude off, secure processing, `jdk.xml.maxElementDepth` 64 plus an explicit depth walk, byte cap before parsing | `doctype_andExternalEntities…`, `billionLaughs…`, `xinclude…`, `deeplyNested…`, `oversized…` |
| JWS (LoTE) tricks | `alg=none` cannot parse as JWS; algorithms allow-listed; `b64=false` and `sigD` (detached) refused; unknown `crit` refused except JAdES parameters that do not change the payload | `loteJson_unsignedOrAlgNone_isRefused`, `…signedByAnotherKey…` |
| SSRF / DNS rebinding through the list URL or LOTL pointers | https only (also for pointers); `OutboundUrlGuard` on every URL; pinned connection to the checked address; no redirects (a 3xx is refused); 16 MB cap; 5 s connect / 30 s total including DNS; `WALLET` fetch-limiter slots per realm; at most 64 pointers per load | `PinnedTrustedListFetcherTest` |
| Replay of an older member list after it moved URL or was dropped and re-added (re-review) | Rollback high-water mark per (source, territory, TSLType) that outlives member rows, MACed, enforced in the loader and by a conditional SQL upsert | `lotl_aMemberDroppedAndReAdded…`, `lotl_aMemberMovedToAnotherUrl…`, `theHighWaterMarkIsEnforcedInSqlToo`, `lotl_theHighWaterMarkFollowsTerritoryAndType…` |
| Replay of an old, validly signed list (re-adds a withdrawn issuer) | `NextUpdate` must not have passed and counts at most issue + 6 months (TS 119 612 §5.3.14), a list without one (closed) is refused, and the sequence number may not go down — for the top list **and for each member** of a list of lists (per-member state, also enforced in SQL) | `nextUpdateInThePast…`, `nextUpdateIsCapped…`, `closedList…`, `olderList_isRefusedAsRollback…`, `lotl_memberReplayWithALowerSequence…`, `lowerSequence_isRefusedBySqlToo` |
| Withdrawn issuer still trusted | Only the **current** status counts (history ignored), only accepted statuses (`withdrawn`/`deprecated…` can never be configured), a status starting in the future does not count; anchors are read live at every verification | `withdrawnService…`, `TrustedListWalletE2eTest` |
| Signer certificate compromised, weak or expired | The signer must have been valid at `ListIssueDateTime` **and**, at *now*, not expired beyond a grace: **0 by default for an admin-pinned top-level signer** (ETSI TS 119 615 PRO-4.1.4-07/08: INDETERMINATE), 180 days for a member's signer named by the verified LOTL (PRO-4.2.4-09, bounded by validity at issue and the 6-month cap), so a long-expired key cannot sign a backdated list; RSA ≥ 2048 / EC P-256+ only (pinned: field error; LOTL-named: not used); pinning is explicit (presets never fill a signer); pinned signers expiring within 30 days are audited and shown | `signerExpiredLongerAgoThanTheGrace…`, `weakSignerKeyNamedByAListOfLists…`, `weakPinnedSignerKey…`, `pinnedSignerExpiringSoon…` |
| Denial of service by an unreachable or broken list | Fail safe: the last good anchors stay until NextUpdate plus a bounded grace (≤ 720 h), then fail closed — **per member** for a list of lists, so one broken, plain-http or expiring member does not affect the others (status `DEGRADED`); every failure is audited and logged; refresh runs off the request path | `TrustedListServiceTest` (`lotl_oneBrokenMember…`, `lotl_memberNearExpiry…`, `lotl_plainHttpPointer…`) |
| Refresh racing a settings change (review: a list signed by a re-pinned, compromised key stored after the re-pin) | The refresh re-reads the row after taking the lease; results are stored only while it holds the lease and `config_version` is unchanged (a settings change clears the lease and bumps it); a dropped result is audited `REFRESH_DISCARDED`, never as success | `refreshInFlightWhenTheAdminRepins…` (the review's Race.java) |
| Two replicas racing, a re-entrant refresh, an expiring lease, or a stale replica | Non-re-entrant row lease renewed while the load runs; results written only by the lease holder; STALE/EXPIRED transitions conditional on the version judged; sync and refresh on separate threads; versions polled so replicas converge | `twoReplicas_refreshOnce…`, `consoleRefresh_whileTheSchedulerRefreshes…`, `leaseIsRenewed…`, `staleReplicaHealthCheck…` |
| Database tampering (pin another signer, stretch the grace, re-enable, rename, inject an anchor, replay an older row) by someone who can write the DB but not read `DB_ENCRYPTION` | HMAC-SHA256 (key derived from `DB_ENCRYPTION`) over **every** trust-deciding setting (realm, name, URL, format, signers, types, statuses, territories, grace, switch, `config_version`) and over the stored services of each source and member and the high-water marks, all bound to `config_version`; grace clamped on read. Failing settings: `INTEGRITY`, no anchors, refreshes refused until an admin re-saves (`TRUSTED_LIST_INTEGRITY_FAILED`). Failing anchors/marks with good settings: discarded and reloaded from the signed list at the next refresh (`TRUSTED_LIST_INTEGRITY_RESET`). The admin view shows a tampered member as `INTEGRITY`, not in use. Outside `dev` a source cannot be saved without `DB_ENCRYPTION` | `everySettingThatDecidesTrust…`, `storedAnchorsOfAnEarlierConfigVersion…`, `graceHoursAreClampedOnRead`, `anchorsThatFailTheirCheck_areReloaded…`, `afterDbEncryptionChanges…`, `tamperedHighWaterMarks…`, `aTamperedMember…`, `FlywayTrustedListIntegrityUpgradeTest` |
| Lost update between two admins; deleting a source in use | Updates are conditional on the `configVersion` read (409 otherwise); delete, like rename, is refused while providers name the source | `twoAdmins…`, `anEditOverAStaleRead_is409…`, `renamingASourceThatProvidersUse…` |
| One refresh acting under another's lease | A fresh lease token per refresh | `everyRefreshTakesTheLeaseWithItsOwnToken` |
| Silent re-pointing of providers by renaming a source | Providers name sources; a rename while providers use the source is refused; writes are audited with URL and signer fingerprints (old and new) | `TrustedListWalletE2eTest.renamingASourceThatProvidersUse…` |
| Non-CA or weak keys on a list becoming anchors | Only certificates passing `TrustAnchors.trustAnchorProblem` (CA, `keyCertSign`, EC P-256/384/521 or RSA ≥ 2048) are used | `nonCaCertificateOnTheList_isNotAnAnchor…` |
| Admin misuse / CSRF | `manage-identity-providers`, CSRF header on writes, server-side validation, admin audit | `TrustedListWalletE2eTest.settings_areValidated…`, `anAdminWithoutManageIdentityProviders_getsForbidden` |
| Log / audit injection | Names and realms through `LogSafe.sanitize`; exception messages are fixed strings, never parser output or list content | — |

An independent review (2026-10-15) ran an adversarial XSW/XXE harness against the signature core (wrapping with a new
root, evil content in `ds:Object`, duplicate Ids, comment/CDATA tricks, XPath and `xpointer` references, SHA-1
digests, DTD bombs, file/parameter/UTF-16 XXE) and found no hole in it; its state-layer findings (refresh race,
member rollback and isolation, SHA-1 digests, expired signers, NextUpdate cap, LoTE status denylist, member
territory/type, stored-row integrity, scheduler, key strength, health-check overwrite, renames, 403 test) are fixed
above.

A re-review of those fixes held for the race, digest, NULL-MAC and state-propagation fixes and found the items above
(member rollback across URL moves, integrity recovery, MAC coverage, lost updates, delete in use, lease tokens,
tampered member view, split signer grace); all are fixed.

**Scope of the MACs and the high-water marks (maintainer ruling).** HelixIAM does not defend against someone who can
write its database anywhere else: a wallet provider's pasted `trustAnchors` PEM is plain configuration, so a database
writer can add their own CA there and bypass trusted lists entirely. The trusted-list MACs are therefore best-effort
tamper *detection*, not a security boundary against database writers. The high-water marks exist to stop **network**
rollback (a man in the middle, or a stale mirror serving an older, validly signed list). A database writer who deletes
high-water-mark rows can re-open rollback; that is out of scope, consistent with `trustAnchors` and the rest of the
configuration. Within that scope: an integrity reset drops anchors and member state but never the rollback floors (the
top-level `sequence_number` and the high-water marks stay, whatever their MACs; a floor is only raised, by a verified
load, which also re-MACs it, so a key change never opens a rollback window); a member row below its floor is never
counted (audited); a settings save computes its MACs from rows it locked (`FOR UPDATE`), so a concurrent refresh is
never left with stale MACs; the high-water-mark territory is upper-cased.

**Delete vs. a concurrent provider write.** Deleting a source checks the providers that name it and then deletes;
a provider saved naming the source between the check and the delete is not caught by that check. The window is
small and fails closed: provider writes are validated against the realm's sources, and a provider naming a source
that no longer exists gets no anchors from it. Not made conditional in SQL (the reference lives inside the
provider's config map).

A row without a MAC is an integrity failure like a wrong MAC; nothing is ever adopted. V81-V84 ship together, so no
released database holds pre-V84 rows; a dev database that does gets `INTEGRITY` until an admin saves each source
again (`FlywayTrustedListIntegrityUpgradeTest`). An earlier design adopted such rows on their first refresh; it was
removed because a database writer could have marked a row to get its settings adopted.

**Residual risks (also in `DEFERRED-SECURITY-WORK.md`).** No LOTL pivot chain: a publisher's signer rotation needs a
manual re-pin (fails closed after grace, it never fails open). XAdES signed properties (signing time, signing
certificate digest) are covered by the signature but not interpreted. LoTE pointers are not followed. Realm
export/import does not carry sources. A list publisher can still list any CA it wants: pinning a publisher is
trusting it for every issuer it lists — choose service types and territories narrowly.

