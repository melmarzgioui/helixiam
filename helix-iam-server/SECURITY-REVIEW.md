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
>   `include-binding-errors` (`always`) for local debugging only.
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
6. **Fix SAML assertion binding (S-H1/S-H2)** — validate the bearer `SubjectConfirmationData`
   (Recipient/NotOnOrAfter/InResponseTo) and check the signed **assertion's** Issuer on the generic-SP path;
   cap DEFLATE inflate (S-M1) and move the replay cache to Redis for clustering (S-M2).
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
| S-H1 | **HIGH** | `OpenSamlAssertionValidator.java:60-87`; `OpenSamlEidAssertionValidator.java:76-123` | No `SubjectConfirmation`/`Recipient`/`NotOnOrAfter`/`InResponseTo` validation — bearer assertion not bound to the in-flight AuthnRequest; stolen/misdelivered bearer assertions not caught | Validate bearer `SubjectConfirmationData` (Recipient == our ACS, NotOnOrAfter, InResponseTo == issued request ID) |
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
