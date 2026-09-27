# CodeQL triage: Java security alerts

These are the CodeQL alerts from the first `master` scan that were reviewed and found to be **false positives**.
Code was not changed just to silence them. Alerts that were real are fixed in code and covered by tests; see
the list at the end. `java/log-injection` is tracked separately. Line numbers are those in the scanned commit
(`169d051`).

## False positives

### #84, #85: `java/ssrf`: `authorization/federation/UpstreamLogoutClient.java:44`, `:46`
`Http.get(url)` calls `egressGuard.checkAllowed(url)` (line 42) before it builds or sends the request, so
the guard rejects a non-http(s) scheme, an unresolvable host, or any resolved address that is loopback,
link-local (metadata), private, ULA, CGNAT or multicast. `HttpClient.newBuilder()` keeps the JDK default
`Redirect.NEVER`, so a public host cannot redirect the request inward. The response is discarded. The
remaining DNS-rebinding window is the documented, accepted residual in `OutboundUrlGuard`'s javadoc.
CodeQL does not model `OutboundUrlGuard` as a sanitizer.

### #245: `java/potentially-weak-cryptographic-algorithm`: `authorization/service/security/BreachedPasswordChecker.java:89`
SHA-1 is not used for security here. The HIBP Pwned Passwords k-anonymity range API is keyed by SHA-1:
the server sends only the first 5 hex characters of the digest and compares suffixes locally. The digest
is never stored, compared as a credential, or used as a MAC or signature. Passwords are hashed with
Argon2id elsewhere. Any other algorithm would break the protocol.

### #240, #241: `java/user-controlled-bypass`: `authorization/idp/agent/DelegationTokenController.java:176`, `:187`
The "sensitive" calls are `actorClientAuthenticated` and `subjectTokenAuthorizesAgent`. The only
user-controlled conditions that skip them are the earlier `return error(...)` rejections (bad grant or
token type, bad `resource`, bad signature, non-agent actor, issuer mismatch, unknown or suspended agent).
Each of those rejects the request, so no token is minted without the checks. The short-circuit operands
`requireActorAuth` and `requireSubjectBinding` are server configuration
(`@Value helix.agent.delegation.*`, default `true`), not request data.

### #242: `java/user-controlled-bypass`: `authorization/idp/workloadidentity/WorkloadIdentityTokenController.java:152`
`mint(...)` runs only after `verifier.verify(...)` succeeds. Every user-influenced branch before it
(missing token, malformed JWT, missing iss/sub/aud, no matching credential, verification failure) returns
`denied(...)`, a 401. No condition skips verification and still reaches the mint. Triaging this alert did
turn up an unguarded issuer-discovery fetch in the same method. That one is fixed separately; see below.

### #100: `java/uncontrolled-arithmetic`: `persistence/security/AttributeEncryption.java:87`
`iv.length + encrypted.length` adds a 12-byte IV to an AES-GCM output of `plaintext + 16` bytes. The
"uncontrolled" source is `SecureRandom` filling the IV bytes, which does not change the IV length. An
overflow would need a column value near 2 GiB, which a JPA `String` attribute cannot hold.

### #92: `java/sensitive-log`: `authorization/idp/agent/DelegationTokenController.java:255`
This logs `creds[0]`, the **client_id** (a public identifier), at DEBUG. The secret is `creds[1]` and is
never logged. CodeQL taints the whole array.

### #93, #96: `java/sensitive-log`: `authorization/service/realm/RealmAdminBootstrapService.java:110`, `:157`
These log the password-file **path** and a `java.nio.file` exception message ("could not write file X").
They do not log the password. The variables are only flagged because their names contain "password".
The neighbouring line that did log the password (#94) is fixed. #95 (`:154`) was the same kind of path
log, and that line was removed by the fix (the atomic temp-file rename leaves no partial file to clean up).

### #91: `java/sensitive-log`: `authorization/flow/push/LoggingPushSender.java:25`
This is the dev push sender. It logs the approval id, user id, the number-matching number with its
decoy choices, and the challenge nonce. None of these can approve a login. The browser that started the
login already shows the expected number (that is how number matching works). The challenge is a public
nonce that is also sent in clear through FCM/APNs. `PushApprovalService.approve` and `.deny` require an
ES256 signature over it from the device key enrolled for the user the approval is bound to.

### #86: `java/xss`: `authorization/idp/saml/SamlIdpController.java:432`
The only request-derived value in the metadata document is the realm, which appears in the SSO and SLO
`Location="..."` attribute values. `RealmRoutingFilter` takes it from the **raw, undecoded**
`getRequestURI()` segment, and it 404s unknown realms. Realm ids are `[A-Za-z0-9._-]`. Tomcat rejects
unencoded `<`, `>` and `"` in the request line, and percent-escapes stay escaped. A raw `&...;` entity
inside an XML attribute value is character data. It cannot close the attribute or add markup, and the
worst case is malformed XML. The response is `application/xml`, not HTML.

### #87: `java/unvalidated-url-redirection`: `authorization/security/flow/ResolveSavedRequestRedirect.java:61`
The target is `SavedRequest.getRedirectUrl()` from Spring Security's session-scoped `HttpSessionRequestCache`.
Spring Security stores it when this user's own browser asked this server for a protected URL. It is
rebuilt from that request's scheme, host, port, URI and query, so it always points back to this server's
own origin as the browser addressed it. An attacker cannot write another user's session cache, and
nothing from the current request feeds the target.

### #88: `java/unvalidated-url-redirection`: `authorization/security/oidc/PromptAndMaxAgeAuthorizeFilter.java:180`
The redirect happens only after `client.getRedirectUris().contains(redirectUri)`, an exact match against
the client's registered redirect URIs. An unknown client, a missing URI or a mismatch gets a 400. The only
additions are `error=login_required` and a URL-encoded `state`, which is what OIDC Core §3.1.2.6 requires.

### #89: `java/spring-boot-exposed-actuators-config`: `pom.xml:314`
`application.properties` exposes only `health,prometheus` (`/actuator/info` and everything else are
off). `health` is anonymous for k8s probes with the default `show-details=never`.
`helix.actuator.prometheus-anonymous` defaults to `false`, so `/actuator/prometheus` needs
authentication unless an operator enables anonymous access, and `ProductionReadinessCheck` warns when
they do. No sensitive endpoint (`env`, `heapdump`, `loggers`, `configprops`, …) is exposed.

### Still reported after the fixes (scan of `a30ad06`)
CodeQL re-reports some alerts under a new number when the flagged line moves, and cannot see a fix that
depends on a setting or a custom guard.

- **#250** (`DelegationTokenController`, was #92), **#251** (`RealmAdminBootstrapService:119`, the password
  *file path*, never the password), **#252** (`OutboundUrlGuard`, logs `safe(url)` = `scheme://host[:port]`
  only): same reasoning as #92/#93/#96 above and the #97 fix; the logged values are not secrets.
- **#243, #244** (`RealmAdminAuthorities`): the real problem behind them (a role named `admin_<x>` reading as
  admin of another realm) is fixed in `f063eac` (reserved names refused) and `aadb9ef` (an existing reserved
  name grants no authority), with `AdminRoleNameCollisionE2eTest`. The flagged comparisons themselves are the
  exact-match checks and fail closed.
- **#90** (`java/insecure-cookie`, `RiskAuthenticator`): the device cookie's `Secure` flag follows
  `helix.security.cookie-secure` (default `true`), like the session cookie; it must stay switchable for local
  plain-http development. CodeQL only accepts a literal `true`.
- **#249** (`java/local-temp-file-or-directory-information-disclosure`, `RealmAdminBootstrapService:110`):
  when no password file path is configured, the generated bootstrap password goes to
  `<java.io.tmpdir>/helixiam-admin-password`. The file is created with `rw-------` as a creation attribute
  (`Files.createTempFile(..., PosixFilePermissions.asFileAttribute(...))`) and atomically renamed into place,
  so it is never readable by other users, and a rename replaces (never follows) anything planted at that path.
  In the container image `/tmp` is private to the process. Production deployments set `HELIX_ADMIN_PASSWORD`.
- **#248** (`js/user-controlled-bypass`, `helix-mcp-demo/mcp-server.js:93`): the flagged condition is the
  router (`POST /mcp`). Every request to that endpoint goes through `verify()` (signature, RS256, issuer,
  audience, `exp`/`nbf`, scope); there is no branch on the Authorization header that skips it.

## Fixed (for reference)

| Alert(s) | Rule | Fix | Test |
|---|---|---|---|
| #90 | insecure-cookie | device cookie `Secure` follows `helix.security.cookie-secure`, not `request.isSecure()` | `RiskAuthenticatorTest.newDeviceCookie_isSecure_evenWhenTheRequestLooksPlainHttp` |
| #98, #99 | tainted-arithmetic | SCIM paging end = `from + min(count, total - from)` | `ScimListPagingTest` |
| #94 | sensitive-log | generated bootstrap admin password is never logged; always written 0600 | `RealmAdminBootstrapServiceL6Test` |
| #97 | sensitive-log | `OutboundUrlGuard` logs and echoes only `scheme://host[:port]` | `OutboundUrlGuardTest.blockedUrl_neverLogsOrEchoesCredentialsPathOrQuery` |
| #243, #244 | user-controlled-bypass | The flagged flow is fail-closed, but review found a real cross-realm escalation: role `admin_x` in realm `y` produced the authority `admin_x_y`, the same string as "admin of realm `x_y`". Role names starting with `admin_` are now reserved. | `AdminRoleNameCollisionE2eTest`, `RoleAdminServiceTest.create_rejectsAReservedAdminPrefixedName_soItCannotPoseAsAnotherRealmsAdmin` |
| (from #242 review) | ssrf | WIF issuer-discovery GET now passes `OutboundUrlGuard` | `WorkloadIdentityDiscoveryEgressTest` |

## rc.5 scan

Alerts from the scan of `v1.0.0-rc.5` (19). Line numbers are those in the scanned commit (`b21afba`). Fixed alerts are
listed in the table at the end of this section; the false positives are explained first.

### False positives

#### #256: `java/unvalidated-url-redirection`: `authorization/security/mfa/MfaEnforcementFilter.java:194`
The target is a redirect URI registered for the client: `sendInteractionRequired` looks the client up with
`RegisteredClientRepository.findByClientId`, which is realm-scoped (`RealmScopedKey.pack(RealmContextHolder.get(), …)`),
and uses the request's `redirect_uri` only when `client.getRedirectUris().contains(requested)` (exact match), else the
client's only registered URI, else nothing is sent (the user gets the second step instead). Only `error`,
`error_description` and `state` are added, through `UriComponentsBuilder.queryParam(...).encode()`, so they cannot
change the host or path. This is the `prompt=none` error response OpenID Connect requires.

#### #257: `java/unvalidated-url-redirection`: `authorization/security/realm/OrganizationMembershipFilter.java:105`
Same validation as #256: `registeredRedirectUri` returns the requested `redirect_uri` only when it is exactly one of the
(realm-scoped) client's registered redirect URIs, or the client's only one; an unknown client or an unregistered URI
returns `null` and the filter passes the request on to the authorization endpoint, which rejects it. The redirect then
carries only `error=access_denied`, a fixed description and the encoded `state`.

#### #265–#270: `java/user-controlled-bypass`: `authorization/controller/admin/io/RealmImportService.java:644`, `:646`, `:648`, `:684`, `:810`, `:847`
The "sensitive methods" on these lines are record accessors whose names match CodeQL's authentication-name heuristic:
`c.authFlowAlias()`, `c.loginTheme()`, `c.tokenEndpointAuthMethod()` (clients), `sp.defaultAuthnContextClassRef()`
(SAML), `app.authFlowAlias()` (applications) and `a.authMethod()` (agents). They read a field of the imported document
to copy it into the write DTO; none of them checks anything. The user-controlled conditions that can skip them
(`c == null || isBlank(key)`, `blocked(existing, …)` for the `onConflict` policy, and `existing.containsKey(key)` for
create vs update) only decide whether that document row is skipped, created or updated. The import itself is an admin
write: `/admin/realms/{realmId}/import` needs `manage-realm` for that realm (`AdminRoutePermissions` default), and every
row is written into the path's `realmId`, never a realm named in the document. Skipping a row skips no check.

#### #271: `java/user-controlled-bypass`: `authorization/security/PageCspPolicy.java:137`
The "sensitive method" is `pendingAuthorizationClientId(request)`, a session lookup of the saved authorize request's
`client_id`, flagged for the word "Authorization" in its name. It only feeds the page's CSP `form-action` list, and
the condition that skips it (`clientId == null && !logout`) means an explicit `client_id` on `/oauth2/authorize`,
`/oauth2/consent` or `/connect/logout` is used instead. Either way the only origins added are those of redirect URIs
registered for that realm-scoped client (post-logout URIs on logout), each filtered by `formActionSource` (http(s)
origin or a private-use scheme; no wildcards, quotes, separators or script-capable schemes). These are exactly the
places the authorization server will redirect to for that client. An unknown client or any error leaves `'self'` only.
No security check depends on this value.

### Fixed

| Alert(s) | Rule | Fix | Test |
|---|---|---|---|
| #258 | csrf-unprotected-request-type | `GET /required-actions` only shows the page. The verification email is sent by `RequiredActionsGate` inside the sign-in `POST`; "send again" stays a `POST` | `RequiredActionsVerifyEmailTest`, `EmailVerificationE2eTest` |
| #259 | csrf-unprotected-request-type | `GET /account/email/verify` shows a confirmation page (`account/email-confirm`); its button `POST`s the token with the CSRF token, and only the `POST` confirms the address (same pattern as C3 `/verify-email`) | `AccountConsoleBrowserE2eTest.anEmailChange_isUnverifiedUntilTheLinkSentToTheNewAddressIsOpened` |
| #253 | polynomial-redos | `EmailLayout` finds `data-button` links with a one-pass scanner instead of `(.*?)</a>` | `EmailLayoutTest.manyUnclosedButtonLinks_areHandledInLinearTime`, `…buttons_areFoundCaseInsensitively_acrossLines_andOtherLinksAreLeftAlone` |
| #254 | polynomial-redos | `EmailChangeService.normalise` checks the address in one pass (`isPlausible`), no regex. The input was already capped at 254 characters before the regex ran, so this was defence in depth | `EmailChangeServiceNormaliseTest` |
| #260 | sensitive-log | an unreadable `HELIX_BOOTSTRAP_CLIENT_SECRET_FILE` is reported without its path | `BootstrapServiceAccountServiceTest.anUnreadableSecretFile_isReported_withoutLoggingItsPath` |
| #261–#264 | log-injection | `FederatedLoginCompleter` and `QueueSpringSessionStore` wrap the user id / principal name and exception messages in `LogSafe.sanitize` | (`LogSafeTest`) |
| #255 | unvalidated-url-redirection | Hardening. The target was the authorize request saved in the user's own session, so it was always this server. `InFlightClientResolver.pendingAuthorizeUrl` now returns only its path and query, never its scheme and host, and refuses a path starting with `//` | `InFlightClientResolverTest.pendingAuthorizeUrl_*` |
