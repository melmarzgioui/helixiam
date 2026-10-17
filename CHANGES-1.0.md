# CHANGES — road to a credible 1.0

Running log for branch **`overhaul/1.0-gaps`**. Every finding, fix, commit, deferred item and open
question. Newest first within each phase.

## Next release (after `v1.0.0-rc.11`)

### Security: admins could grant admin permissions they do not hold (H5, present in rc.11)

A `manage-users` admin could assign itself the `admin` role, and a `manage-roles` admin could make `admin` the default
role. Assigning or removing a role through any path (user roles, group roles and membership, service-account roles,
realm import, SCIM) now needs the role's admin permissions to be the caller's own (`realm-admin` for the admin role);
changing admin grants needs `realm-admin`; a role with admin permissions cannot be the default role. And **you cannot
act on an admin more privileged than you**: impersonating, resetting the password or credentials of, changing,
disabling or deleting a user, and revealing, setting or rotating the secret of, changing or deleting a client (through
its service account), need the target's admin permissions to be your own; revealing a client secret needs
`manage-clients`; SCIM cannot change admins; IdP logins never auto-link by e-mail to an administrator; a `CLIENT`
service-account role needs its client; workload-identity and agent bindings to an admin service account need its
permissions; redirecting the built-in sign-in clients (`helix-console`, `helix-cli`) needs `realm-admin`. See
`helix-iam-server/SECURITY-REVIEW.md` (H5).

**Round 6 (systematic sweep).** Every admin write, import slice and SCIM/DCR write was inventoried (design doc,
Revision 3). Changing or deleting an identity provider that administrators are linked to, or a trusted list their
wallet providers use, needs those administrators' permissions. Federated links record how they were made (new
`federated_link.created_via`). Links that exist at the upgrade are grandfathered (`LEGACY`, still trusted; wallet
links `WALLET`) and every administrator with one is reported at start-up (`PRIVILEGED_LEGACY_LINK`). A link made
afterwards by matching an e-mail address (`AUTO`) never signs in an administrator; an administrator links a provider
from the account console (Connected accounts → Link: a fresh sign-in, then the provider in link mode bound to the
session; `SELF`), or a realm admin confirms the link (`POST .../users/{id}/federated-identities/{alias}/confirm`,
`ADMIN_CONFIRMED`) and can revoke trust in a suspect one (`.../revoke-trust`; both also need the user's admin
permissions in every realm they belong to); refusals are audited (`PRIVILEGED_LINK_REFUSED`). Federated links are now
realm-scoped (`federated_link.realm_id`, key realm + alias + subject): a link signs its user in only in its realm. Realm-admin is now needed for: the Applications of the sign-in clients; creating `helix-console`/`helix-cli`;
their mappers and allowed resources (also on import); the browser flow and the sign-in clients' flows; messaging
providers and templates; the MFA policy; magic links; the subject claim; and the realm's sign-in policy settings.
`helix-cli` is seeded with every realm; on start, a `helix-cli` that allows more than the built-in one (a
non-loopback redirect URI, an extra grant type, a secret, a confidential client) is corrected, while narrower choices
are kept. Push devices for a user
need the user's permissions. Deleting a role or group, or moving a group, needs the permissions it grants. manage-X
satisfies view-X routes.

> **Upgrade note (H5).** A realm whose default role carries admin permissions is reported at start-up (WARN and a
> `DEFAULT_ROLE_HAS_ADMIN_PERMISSIONS` audit event); new users no longer get that role. Pick another default role or
> remove its admin grants. V86 also removes duplicate `realm_key` rows an rc.11 first-use race could leave (keeping the
> ACTIVE, else the newest, per realm); if the same key is stored in two realms the migration stops and names them.
> Admins with only `view-clients` can no longer read client secrets; an administrator whose verified e-mail matches
> an external IdP login is no longer linked automatically.
> Round 6: V86 places each existing federated link in a realm: the realm that owns the alias. A link whose alias is in
> several realms or in none is held `UNRESOLVED` until start-up: once the realm config folder's providers are loaded,
> a link whose alias is in exactly one realm moves there and keeps working (`LEGACY`, audited `LEGACY_LINK_RESOLVED`);
> any other becomes `AUTO` and signs no administrator in until a realm admin confirms it (reported as AMBIGUOUS,
> `PRIVILEGED_AMBIGUOUS_LINK`); links that cannot be placed at all sign no one in.
> Existing federated links keep working (`LEGACY`); review the start-up report (WARN and
> `PRIVILEGED_LEGACY_LINK` audit events: realm, username, provider) and revoke trust in any that is suspect. New links
> to administrators need the account console's link flow or a realm admin's confirmation. A `manage-realm` admin can
> no longer change messaging, MFA, magic-link, subject-claim or sign-in policy settings. A `helix-cli` that allows more
> than the built-in client is corrected on start (logged and audited as `SIGN_IN_CLIENT_RECONCILED`). Step by step:
> `operations/upgrade-rc11-rc12.md` on the docs site.

### Security: admin permissions resolved on the decoded path (H4, predates this release)

The admin permission resolver read the raw request URI while Spring MVC routes on the decoded path, so an encoded
route name (`k%65ys`, `u%73ers`) resolved to the `manage-realm` default and let a low-permission admin reach writes
guarded by another permission. Percent-encoding in the realm id or route name of an `/admin` path is now refused with
`400`, the resolver reads the decoded path, and unknown admin routes fail closed to `realm-admin`. See
`helix-iam-server/SECURITY-REVIEW.md` (H4).

### Bring your own realm signing keys and certificates

Customers can change the keys and certificates their realm signs OIDC/JWS and SAML with. Design and every decision:
`docs/superpowers/specs/2026-10-16-byo-realm-keys-design.md`. Docs: `operations/realm-keys.md` on the docs site.

- **Import** (`POST /admin/realms/{realm}/keys/import`): a PEM private key (PKCS#8, PKCS#1, SEC1; RSA ≥ 2048 or EC
  P-256) and its certificate chain, leaf first. The leaf must match the key, be valid now and have digitalSignature
  if it has a keyUsage; every certificate must be valid and issued by the next. A self-signed single certificate is
  allowed; a key already stored in any realm is refused. Refusals are `400 {message, fieldErrors}`.
- **CSR** (`POST /keys/csr`, `GET /keys/{keyId}/csr`): the server generates the key (RS256 or ES256), keeps the
  private key and returns a PKCS#10 CSR; `PUT /keys/{keyId}/certificate` attaches the CA-signed chain (PENDING or
  ACTIVE keys).
- **Staged rollover**: new keys start PENDING — published in the JWKS and SAML metadata, not signing —
  until `POST /keys/{keyId}/activate` (after `helix.keys.min-staging`, 5 min, unless `?force=true`); the previous
  ACTIVE key of the same algorithm becomes ROTATED and stays published. `POST /keys/rotate` still generates and
  activates at once (no staging) and takes an optional `{"algorithm"}`. Retiring the ACTIVE RS256 key is now refused
  (`409`; it used to succeed); retiring the ACTIVE ES256 key is refused while clients ask for ES256 ID tokens (names
  listed) unless `?force=true`. Key ids are realm-scoped on every route (`404` across realms); transitions are
  serialised per realm.
- **Permissions**: every key write needs `realm-admin` (it used to be `manage-realm`); reads keep `manage-realm`.
- **Publishing**: every JWK has `kid`, `alg`, `use: sig`; keys with a chain add `x5c` and `x5t#S256`. SAML metadata
  and signatures use the ACTIVE key's leaf certificate when it has one (else the deterministic self-signed one, as
  before); PENDING and ROTATED certificates are extra signing KeyDescriptors.
- **ES256 alongside RS256**: every realm keeps an ACTIVE RS256 key; an ES256 key can be active beside it. ID tokens
  use the client's `id_token_signed_response_alg` (validated against the ACTIVE keys); access, logout, delegation,
  workload-identity tokens and JARM use the new realm setting `signing.defaultAlg`
  (`/admin/realms/{realm}/settings/signing`, RS256 by default); SAML signs RSA unless `signing.samlAlg` is ES256.
  Discovery lists exactly the ACTIVE keys' algorithms. The MCP demo verifier now
  accepts RS256/PS256/ES256 by kid; the sandbox RP takes the ID-token algorithm from discovery and trusts every SAML
  signing certificate in the metadata.
- **Expiry**: import/attach refuse expired certificates; ACTIVE/PENDING certificates within 30 days of expiry (or
  expired) raise `REALM_KEY_CERTIFICATE_EXPIRING|EXPIRED` audit events and a WARN once a day per key; the always-UP
  `realmSigningKeys` health indicator joins the readiness group. An expired ACTIVE certificate keeps signing.
- **Audit**: `REALM_KEY_IMPORT|CSR|CERTIFICATE_ATTACH|ACTIVATE|ROTATE|RETIRE`, with key id, algorithm and fingerprint.
- **Console**: the Realm keys page shows status (Pending / Active / Retained), algorithm, certificate subject/issuer,
  expiry chips and fingerprint, with Import, Create CSR, Upload signed certificate, Activate (with confirmation),
  Rotate (generate) and Retire.

> **Upgrade note.** Flyway **V86** (and `schema.sql`) adds `certificate_chain_pem`, `csr_pem`, `source`,
> `activated_date` and `expiry_warned_on` to `realm_key`, a unique index on `realm_key.public_key`, and the table
> `realm_signing_settings`, and rewrites `algorithm` from `RSA` to `RS256` (existing keys keep their kid and keep
> signing). Admins who rotated keys with only `manage-realm` now need `realm-admin`; admin routes not named in the
> permission catalogue now need `realm-admin` too. Clients whose ID-token algorithm has no ACTIVE key (for example
> RS384) must be changed before their next save. Rolling upgrade: rc.11 replicas ignore PENDING keys and keep signing with RSA
> keys, so you can import and stage keys mid-roll — but activate an **ES256** key only once every replica runs this
> release (an rc.11 replica cannot load an EC key). Changing the signing settings needs `realm-admin`.
> Realm exports still contain no keys, certificates or signing settings.

## v1.0.0-rc.11 (2026-10-15)

rc.11 closes out the EUDI Wallet program: the EU reference-wallet interop (SD-JWT VC and mdoc, same-device and
cross-device, with third-party DeviceAuth test vectors drawn from it), an OpenID Foundation conformance self-run, the
W3C Digital Credentials API, a verify-only / step-up mode, EU trusted lists for wallet trust anchors (ETSI TS 119 612
/ 119 602), a Terraform resource for the wallet identity-provider connection, and realm-delete cleanup of wallet
secrets. It also moves the application onto Jackson 3, closes the Info/Low findings of an internal pentest, and picks
up the post-1.0 dependency upgrades (Express 5, `openid-client` 6, otplib 13, cosign 3) — on top of the rc.10 CodeQL
fixes. On the strength of the reference-wallet interop, the third-party vectors, the conformance self-run and the
pentest, the maintainer has lifted the core OpenID4VP verifier's **Experimental** label; the Digital Credentials API
and verify-only mode are new and carry a **Preview** label instead. Read the Upgrade checklist below and
`docs/UPGRADING.md` before upgrading.

> **Upgrade checklist.**
> 1. **Rolling upgrades (wallet providers).** An old-version node refuses a DCQL query carrying `trusted_authorities`;
>    a transaction started on an upgraded node and answered on an old one sharing the Redis/PostgreSQL store then
>    fails. Upgrade every replica in one step, drain wallet transactions first (wait out `transactionTtlSeconds`), or
>    set HAIP-profile providers' `dcql.trustedAuthorities` to Off for the duration of the roll.
> 2. **Trusted-list signer grace now defaults to 0 (behaviour change).** `signer-expiry-grace-days` (admin-pinned
>    top-level signers) now defaults to **0**, split from the new `member-signer-expiry-grace-days` (180, for signers
>    named by a verified LOTL). As of 2026-10-15 the EUDI test LOTL needs `signer-expiry-grace-days` ≥ ~120 and the EC
>    acceptance LoTE ≥ ~30; set these before upgrading if you use trusted-list sources, or the console will say a list
>    is refused for an expired pinned signer.
> 3. **`eudi-wallet-verify` needs the flow engine on.** With `helix.flow-engine.enabled=false` (the default), a login
>    whose flow has the wallet-verification step is refused (`error=flow`), and such a flow cannot be saved or bound
>    (400). Turn the flow engine on before binding a verify-only step to a flow.
> 4. **New standard scope `verified_claims`.** Seeded (and backfilled) in every realm; a client must request it to
>    receive the verify-only step's released claims in the ID token. No action needed unless a client enumerates or
>    restricts its realm's scopes.
> 5. **`view-identity-providers` is now on the built-in auditor role.** Auditor-role admins can now read identity
>    providers and trusted lists (writes still need `manage-identity-providers`). Review the auditor role if you rely
>    on it carrying no federation read access.
> 6. **Flyway V81–V85.** New storage for trusted-list sources, their config-version guard, member lists, integrity
>    MACs, and the wallet realm-delete cascade trigger; applied automatically on startup, no manual step.
> 7. **Jackson 3.** The nesting limit for parsed JSON is now 500 (Jackson 2's default was 1000); `max-string-length`
>    stays 20 MB. Nothing to do for an upgrade from rc.10 — stored state and wire formats are unchanged — unless you
>    configure Jackson through Spring properties directly: `spring.jackson2.*` is no longer read, use
>    `spring.jackson.*`.
> 8. **Wallet request objects may be re-fetched (behaviour change).** A `request_uri` now returns the same request
>    again until the wallet answers, instead of 404ing after the first fetch; a relying party that assumed
>    single-fetch semantics should not depend on that.

- **EUDI Wallet: the core OpenID4VP verifier is no longer Experimental (maintainer ruling).** The redirect
  same-device flow, the QR cross-device flow, `direct_post.jwt`, and SD-JWT VC and mdoc presentations are promoted out
  of the **Experimental** status in `docs/FEATURES.md` and `docs/eudi-wallet.md`, on the strength of the EU
  reference-wallet interop (§10), the third-party DeviceAuth test vectors drawn from it, the OpenID Foundation
  conformance self-run (§11), and the internal pentest of 2026-10-15 (no exploitable Critical/High/Medium issue). Two
  newer parts are **Preview** instead: the W3C Digital Credentials API (§12, not yet tested with a real wallet) and
  the verify-only / step-up mode (§13). Honest limits stay as documented: no national wallet has been tested, the DC
  API has not been tested with a real wallet, and the OIDF conformance run was a self-run, not a certification.
  Console: the Digital Credentials API section and the verify-only option now carry a Preview badge (EN + NL, the
  existing `Badge`/`Section` kit, no inline styles).
- **Changed (platform): the application is on Jackson 3** (`tools.jackson` 3.2.3), closing the last open item of
  `DEFERRED-SECURITY-WORK.md`. Spring Boot's deprecated `spring-boot-jackson2` module and
  `spring.http.converters.preferred-json-mapper=jackson2` are removed; Spring MVC and every mapper of the application
  use Jackson 3, configured to keep Jackson 2's formats (Jackson 3 changed many defaults: alphabetical member order,
  enums written with `toString()`, `null` for a primitive and trailing tokens refused, `java.beans` property names,
  `Locale` as a language tag, characters outside the BMP written raw in UTF-8, a 100 MB string limit):
  - Boot's `JsonMapper`: `spring.jackson.use-jackson2-defaults=true`, `spring.jackson.mapper.detect-parameter-names`,
    `spring.jackson.json.write.combine-unicode-surrogates-in-utf8=false`, `max-string-length` 20 MB, and `JacksonConfig`
    (Jackson 2 bean names, `Locale` as `toString()`).
  - The application's own mappers (stores, outbound payloads, wallet parsers) come from `JsonMappers`, which behaves
    like a default Jackson 2 `ObjectMapper`; the strict wallet, status-list and LoTE parsers keep their own limits
    (depth 64 / 16, duplicate members and trailing tokens refused) and the canonical theme form stays sorted.
  - Jackson 3's `JsonNode` accessors throw where Jackson 2 returned a default (`asText()` on an object, `textValue()`
    on a number, `asBoolean()` on `"yes"`); code reading JSON it does not control keeps Jackson 2's lenient reads
    (`JsonNodes`). Jackson 3's exceptions are unchecked: every `catch (IOException)` around a Jackson call now catches
    `JacksonException` too, so a malformed wallet disclosure, SD-JWT segment, status-list token, decrypted VP payload
    or file theme is still refused with its usual error instead of escaping as a 500.
  - Stricter: the nesting limit is Jackson 3's 500 (Jackson 2: 1000). Read limits are pinned by `JsonMappersTest`.
  - No change for stored state: authorizations and sessions are Java-serialized (no Jackson classes are allowlisted),
    and every Jackson-written store (wallet transactions, DCQL queries, trusted-list `services_json` and MACed
    settings, `config_json` / `secret_json`, flow and messaging config, email retries, pending `verified_claims`, theme
    JSON and its version hash, audit detail) reads what rc.10 wrote and writes the same bytes. Fixtures recorded on the
    Jackson 2 code (`src/test/resources/upgrade/jackson2`) prove it, together with the wire formats: the MVC mapper's
    behaviour, webhook bodies and their `X-Helix-Signature`, the outbound SCIM user, admin error bodies, member order
    and types of admin/token/userinfo/introspection responses, UTF-8 escaping, and the import of an rc.10 realm export
    (`*UpgradeTest`, `PlainJsonMapperUpgradeTest`, `JsonWireFormatE2eTest`).
  - Jackson 2 stays on the classpath only as a transitive dependency of OpenSAML 5 (`opensaml-core-impl`) and
    springdoc-openapi (swagger-core 2.2.x builds `/v3/api-docs` with Jackson 2); no HelixIAM class imports it
    (`JsonMappersTest`), and the 2.21.7 BOM pin stays for its CVE fixes.

  > **Operator note:** nothing to do for an upgrade from rc.10: stored state, sessions and refresh tokens carry over,
  > and a rolling update is safe in both directions as far as JSON is concerned. Only if you configured Jackson through
  > Spring properties: `spring.jackson2.*` is no longer read; use `spring.jackson.*` (Jackson 3 names, e.g.
  > `spring.jackson.datatype.datetime.*` for date features).

- **Fixed (internal pentest 2026-10-15 follow-ups)** — two internal pentest reports (EUDI wallet
  surfaces; admin API/trusted lists/core) found no exploitable Critical/High/Medium issue; this
  batch closes the Info/Low items: a view-only admin can now read trusted lists
  (`view-identity-providers` permission, `AdminRoutePermissions` read/write split on the
  `trusted-lists` group); `StrictCbor` rejects indefinite-length CBOR (ISO 18013-5); the console
  wallet-provider form requires an explicit confirmation before saving
  `revocationChecking=OFF`; and the verify-only step-up's trust comparison
  (`WalletVerifyLinkRules.anchorsWithin`) now covers trusted-list sources/service types, not just
  PEM trust anchors. Also added `WalletVerifyDcApiE2eTest`, the first e2e test driving a verify-only
  step-up through the W3C Digital Credentials API to `/flow/wallet/callback`. See
  `docs/compliance/internal-pentest-2026-10-15.md` for the full disposition.
- **Changed (dependencies)** — the post-1.0 platform-upgrade items from `ROADMAP.md` landed:
  - `helix-sandbox-rp`: **Express 4.22 → 5.3**, **openid-client 5.7 → 6.8** (a full API rewrite — the
    `Issuer`/`Client`/`generators` object API is replaced by the functional API: `discovery()`,
    `buildAuthorizationUrl`, `authorizationCodeGrant`, `refreshTokenGrant`, `fetchUserInfo`,
    `buildEndSessionUrl`, `randomPKCECodeVerifier`/`calculatePKCECodeChallenge`/`randomState`/`randomNonce`,
    and `AuthorizationResponseError` in place of `errors.OPError`; the package was already ESM so no
    conversion was needed). openid-client 6 enforces HTTPS by default where v5 didn't — the harness talks to
    Helix over plain `http://localhost`, so `ensureClient()` now opts out via `discovery()`'s
    `execute: [allowInsecureRequests]` only when the issuer itself is `http:`. Also **otplib 12.0 → 13.5**
    (declared for TOTP code generation in manual testing; not imported by any committed source, so no call-site
    changes were needed). The now-redundant/conflicting `body-parser` and `qs` npm overrides were dropped —
    Express 5 depends on `body-parser@^2.3.0` and `qs@^6.16.0` directly, and forcing the old `body-parser@^1.20.6`
    override would have broken Express 5's own body-parsing internals.
  - CI release workflow: **cosign-installer 3.10.1 → 4.1.2**, which moves its default installed **cosign 2.6.1 →
    3.1.3**. No flag changes were needed in `release.yml` — cosign 3's new default bundle format
    (`--new-bundle-format`) only changes behavior when `--bundle` writes a local bundle file, which this
    workflow doesn't use (it signs/attests directly against the pushed OCI reference).
  - Verified: `helix-sandbox-rp`'s unit tests and `npm audit` are clean (0 vulnerabilities); a live
    authorization_code + PKCE login, a `/claims` userinfo fetch, a refresh_token grant, RP-initiated logout,
    and a `prompt=none` → `login_required` round trip were driven via Playwright against a locally built
    `helix-iam-server` jar. Behavior is unchanged; see `helix-sandbox-rp/server.js`.
- **EUDI Wallet: W3C Digital Credentials API (`dc_api` / `dc_api.jwt`)** — a wallet connection can now also offer
  OpenID4VP over the browser's Digital Credentials API (OpenID4VP 1.0 Appendix A, HAIP 1.0 §5.2), the path the EU
  wallet ecosystem recommends instead of a redirect-based cross-device flow. Opt-in per connection (`dcApi.enabled`,
  console: Policies → "Digital Credentials API"); the QR code and "Open wallet app" stay as the fallback.
  - Signed requests by default (`openid4vp-v1-signed`: the access certificate, `x509_hash`, `expected_origins`), or
    unsigned (`openid4vp-v1-unsigned`). The response is `dc_api.jwt` (encrypted to the per-transaction key) whenever
    `responseMode` is `direct_post.jwt`; `dc_api` only with the dev-only `direct_post`.
  - The expected origins come from configuration only (`dcApi.expectedOrigins`, else the origin of `IDP_BASE_URL`;
    each must be a host the server answers for), never from the request. SD-JWT VC presentations must carry
    `aud = origin:<origin>`, mdoc DeviceAuth must verify over the `OpenID4VPDCAPIHandover` SessionTranscript of an
    expected origin (checked byte for byte against the spec's Appendix B.2.6.2 example).
  - New page endpoints `POST /realms/<realm>/broker/<alias>/wallet/dc-api/request` and `…/response`: bound to the
    browser that started the login, CSRF-protected, body-limited, single use (a new store transition
    `claimDcApiResponse`, flow `DC_API`; no schema change). DC API failures are audited as `WALLET_LOGIN_FAILURE` with
    `invocation=dc_api`.
  - Not yet run against a real wallet over the DC API: the Android emulator image used for the reference-wallet run
    ships Chrome 124, which predates the API (`docs/eudi-wallet.md` §12.6). Covered by unit tests and
    `WalletDcApiFlowE2eTest`, with the in-repo test wallet playing the browser and wallet sides.
- **Added (Terraform provider) — `helix_wallet_identity_provider` resource.** The EUDI Wallet (OpenID4VP
  verifier) identity-provider connection can now be managed as code: alias/display_name/enabled plus every
  key of `WalletProviderConfig`'s stored map (`client_id_scheme`, `access_key_ref`,
  `access_certificate_chain`, the dev-only `access_certificate_private_key` (sensitive, write-only — the
  admin API never returns a secret's value, though it is stored in plaintext in Terraform state, same as
  any other attribute), `credential_formats`, the `pid_*` PID-request settings, `trust_anchors`,
  `revocation_checking`, the `status_list_*` Token Status List policy, the `subject_*` subject-derivation
  strategy, `minimum_loa`, `clock_skew_seconds`, `allow_legacy_vc_sd_jwt_typ`, the `limits_*` parser
  bounds, and (master `201cb40e`) `dcql_trusted_authorities`, the nullable `dcql.trustedAuthorities`
  DCQL Trusted Authorities Query toggle. An attribute left unset is left out of the write so the server's own default applies, with no
  perpetual diff; import is supported (`terraform import helix_wallet_identity_provider.<name> <alias>`).
  A 400 from the admin API (field-level validation) is reported as one Terraform diagnostic per field,
  attributed to the right attribute where known (`client.go`'s `AdminError`). Removing
  `access_certificate_private_key` from the configuration while state still has a value explicitly clears
  it server-side (`clearAccessCertificatePrivateKey=true`) rather than merely abandoning it; this is never
  sent when state has no value, e.g. right after `terraform import`. Tested against a mock admin API
  (`terraform-provider-helix/internal/provider/wallet_identity_provider_test.go`): the model/wire helpers
  in isolation, and the resource's own Create/Read/Update/ImportState through real
  `tfsdk.Plan`/`tfsdk.State` values (create → read → update, the secret's keep-vs-clear behaviour, field
  errors becoming attribute diagnostics, and an import → read → no-op-update sequence with no drift). The
  gated live test (`TestLiveWalletIdentityProviderCRUD`) has been run against a dev-profile server and
  passed. Closes the item `ROADMAP.md` listed as "a Terraform resource for the wallet identity-provider
  connection."
- **Fixed — EUDI Wallet: realm deletion no longer leaves wallet secrets behind.** `realm_wallet_pepper`,
  `verifier_signing_key` and the PostgreSQL `wallet_transaction` rows had no cleanup wired to `realm_config`, so
  nothing removed them when a realm row was deleted; a realm created again under the same id would silently
  inherit the previous realm's verifier access key and wallet pepper. A new `realm_config_delete_wallet_secrets`
  trigger (Flyway `V85__wallet_realm_cascade.sql`) now deletes all three on an actual `realm_config` delete — not a
  foreign key: all three are routinely written for a realm id that has no `realm_config` row yet (the admin
  wallet/identity-provider APIs never require one, and `JdbcWalletTransactionStore` is exercised the same way by
  its own tests), so a real FK would turn a working insert into a constraint violation. The trigger is a single
  statement in the deleting transaction — all-or-nothing — and the pepper is unrecoverable the instant the realm
  row is gone. The same trigger also deletes the realm's EU trusted list sources (`trusted_list_source`), whose members and rollback high-water marks cascade with them. `federated_link` (wallet account links) has no `realm_id` column and is unaffected; it
  already cascades off the linked user. `FlywayWalletRealmCascadeTest`; `docs/eudi-wallet.md` §2.5;
  `ROADMAP.md`.
- **EUDI Wallet: verify-only / step-up mode (`subject.strategy=NONE`)** — maintainer decision 4, the last open
  wallet design question (`docs/superpowers/specs/2026-10-15-wallet-verify-only-design.md`; operator guide
  `docs/eudi-wallet.md` §13). A wallet connection with `subject.strategy=NONE` never signs anyone in and never creates
  or links an account. The new flow step **`eudi-wallet-verify`** (setting `providerAlias`) runs after the user is
  identified: it starts a `VERIFY` wallet transaction for that user, and accepts the presentation only when the same
  PID, resolved by the linked login connection (`verify.linkedProvider`: its subject settings, the realm pepper), is
  linked to that user (the administrative number wins; the tuple only when the linked connection accepts it; an
  unlinked wallet or another person's wallet is refused, `WALLET_VERIFY_FAILURE` with `BINDING_MISMATCH` /
  `SUBJECT_UNAVAILABLE`). On success the login's `acr` becomes the wallet's LoA (eIDAS high) and the claims listed in
  `verify.releasedClaims` (requested mapped PID claims, or a derived `age_over_NN`) go into the ID token as an OIDC
  Identity Assurance-style `verified_claims` object, for the authorization request the login completes only (never a
  later SSO code of another client); nothing is persisted. `WALLET_VERIFY_SUCCESS` carries the released claim names
  only.
  - **`acr_values`** — a request whose `acr_values` the session's `acr` does not satisfy (same value, or a lower eIDAS
    rung) now forces one re-authentication (the `prompt=login` mechanism, no loop), so an SSO session without the
    wallet is stepped up by the client's flow. `acr_values` stays voluntary: if it is still not met the code carries
    the actual `acr`, which the RP must check.
  - **Never a first factor**: a verify-only connection is not on the login page, `/broker/<alias>` refuses it, the
    account console neither lists nor links it, and the step refuses a login connection. Validation (400
    `{message, fieldErrors}`): NONE needs `verify.linkedProvider` (another alias), refuses
    `subject.acknowledgeWeakSubject`, and allows only requested mapped claims or `age_over_1..150` (with `birthdate`)
    in `verify.releasedClaims`; `verify.*` without NONE is refused. Flow saves refuse an `eudi-wallet-verify` step
    without `providerAlias`. `verified_claims` is now a reserved claim (protocol mappers cannot set it).
  - **Console**: the wallet connection's Policies tab has a third strategy, "Verify only (step-up)", with the linked
    sign-in connection and the released claims (age thresholds included); the flow editor's wallet verification step
    has a connection picker and blocks saving without one (EN + NL).
  - **Fixes found on the way**: `/flow` redirects were realm-prefixed twice (`/realms/<r>/realms/<r>/flow`, 403) when the
    flow engine ran in a realm; a flow step that failed and then asks again (retry) no longer fails the whole flow.
  - **Note**: a password-first login runs flow steps only with `helix.flow-engine.enabled=true` (default off, as
    before); a federated first factor always runs them.
  - No schema change: the transaction purpose `VERIFY` fits the existing `wallet_transaction.purpose` column.
  - **Security review fixes**: `verified_claims` is released only to a request that asked for the new standard scope
    `verified_claims` (seeded in every realm), pinned to the request the step started for (client + hash of
    `client_id`/`state`/`nonce`/`redirect_uri`, 5-minute TTL, dropped on any other code or consent denial), put in the
    code exchange's ID token only and removed from the stored authorization (never on refresh). With the flow engine
    off, a password login whose flow has the wallet step is refused (`error=flow`) and such flows cannot be saved or
    bound (400); the console shows a banner. The linked sign-in connection must exist in the realm, sign in and not
    have a lower minimum LoA (400); an application's SSO setting cannot name a verify-only connection (400). The
    broker no longer touches the step's browser binding; `age_over_NN` uses the date at UTC-12 and treats 29 February
    as reached on 1 March; the `/flow` redirect refuses `\`. The retry page says when the wallet is not the one linked
    to the account. `acr` stays session-wide until the next login and `acr_values` stays voluntary (RPs must check
    `acr`), both recorded in `DEFERRED-SECURITY-WORK.md`.
- **EUDI Wallet: interop with the EU reference wallet (test only, no product change)** — the EU Digital Identity Wallet
  reference app for Android (2026.10.43-Demo, released APK, `demo` flavour) signed in to HelixIAM on an Android 15
  emulator with SD-JWT VC and mdoc PIDs from the EU test issuer `issuer.eudiw.dev`: same-device and cross-device, both
  formats, all four pass with the defaults (`x509_hash`, `haip-vp://`, `direct_post.jwt`, revocation `HARD_FAIL`,
  status list `FAIL_CLOSED`). The verifier's access certificate came from the EU Testing Relying Party Registration
  service, because the released wallet only accepts verifiers on the reference implementation's WRPAC trusted list.
  Deviations: the cross-device QR content was passed to the wallet by an Android intent rather than the camera;
  `x509_san_dns` was not tested (the registrar's certificates have no dNSName); the wallet posts nothing when the user
  declines, so the page waits for the transaction to expire. Record, steps and screenshots:
  `docs/compliance/eudi-reference-wallet/README.md`; `docs/eudi-wallet.md` §10.
- **tests (third-party DeviceAuth vector)** — four of those presentations, with the signed request objects, the
  `direct_post.jwt` responses and the verifier's per-transaction decryption keys (copied by a test-only database
  trigger), are test vectors under `wallet/vectors/eudi-reference-wallet/` (provenance in `SOURCES.md`).
  `EudiReferenceWalletCaptureVectorTest` decrypts and verifies them offline with the production code: mdoc IssuerAuth,
  MSO digests and DeviceAuth over the real OpenID4VP SessionTranscript, SD-JWT VC issuer signature, disclosures and
  Key Binding JWT; DeviceAuth fails for any other `client_id`, `nonce`, `response_uri` or JWK thumbprint. This closes
  the item `ROADMAP.md` listed as needed before the wallet's "Experimental" label can be lifted.
- **EUDI Wallet: OpenID Foundation conformance run** — the OpenID4VP verifier was run against the OpenID Foundation
  conformance suite (5.3.3, revision `f0133e9`). This was a self-run, not a certification, and covered:
  - the HAIP plan (`oid4vp-1final-verifier-haip-test-plan`) and the OpenID4VP 1.0 plan;
  - `dc+sd-jwt` and `mso_mdoc`, `x509_hash` and `x509_san_dns`;
  - `direct_post.jwt` (and `direct_post` in `dev`), `request_uri` GET and POST;
  - same-device and cross-device: 68 modules plus 12 linking runs per pass, run once before and once after the fixes
    below.

  Every positive test signed the linked account in, and every negative test was refused by the check it targets.
  After the fixes: 32 pass, 30 pass (review), 2 fail, 4 skipped, 16 with a warning. The two failures and the
  warnings are justified in `docs/compliance/oid4vp-conformance/README.md`:
  - the HAIP cross-device happy flow fails a `redirect_uri` check that HAIP requires only for same-device logins;
  - the suite's nonce-entropy heuristic warns on 128-bit base64url nonces. An issue text for the suite is in
    `docs/compliance/oid4vp-conformance/upstream-issue-nonce-entropy.md`.

  The logs (secrets removed) are in `docs/compliance/oid4vp-conformance/2026-10-15/` and `2026-10-15-rerun/`. The
  harness that repeats the run (suite containers, TLS proxy, test PKI, Playwright driver, export with redaction) is
  `e2e/oid4vp-conformance/`.
- **EUDI Wallet: a wallet may fetch its request object again (behaviour change)** — this was conformance finding D2,
  and the maintainer ruled on it.
  - Before, each `request_uri` was served once. Now the first fetch binds the login to its flow (the other invocation
    stays `404`), and the same `request_uri` returns the same request again until the wallet's response arrives. After
    the response, or once the login ended or expired, it is `404`. The response stays single use.
  - The change is atomic in all three transaction stores (memory, Redis, PostgreSQL), and the store contract suite
    covers it against each.
  - The request object's `iat` is now the transaction's creation time, not the fetch time, so a re-fetch carries the
    same claims, unless an admin edits the provider between fetches (`response_mode` and `client_metadata` are read
    from the live config).
  - **`wallet_nonce` caveat:** a `request_uri_method=post` re-fetch carries the `wallet_nonce` of *that* POST (OpenID4VP
    §5.10 requires echoing it), so a POST re-fetch is not byte-identical and its `wallet_nonce` differs from the first
    fetch's.
  - A request id fetched under another realm or alias is now a `404` that leaves the transaction alone; before, it
    failed the transaction. The residual risk of re-fetching (a cross-device QR observer can also fetch the request
    and race their own response) is recorded in `SECURITY-REVIEW.md` §B.2.
  - Wallet spec security requirement 2 and `SECURITY-REVIEW.md` §B.2 record the ruling.
- **EUDI Wallet: HAIP `trusted_authorities` in the DCQL query** — each PID Credential Query now carries
  `{"type": "aki", "values": [...]}` (OpenID4VP §6.1.1.1, required by HAIP §5).
  - The values are the base64url key identifiers of the provider's trust anchors and pinned intermediates.
  - The new per-provider setting `dcql.trustedAuthorities` (console: Credentials → "Name the trusted issuers in the
    request", Default/On/Off) defaults to on for `x509_hash` with `direct_post.jwt` (the HAIP profile) and off
    otherwise.
  - Existing HAIP-profile providers start sending it without a configuration change.
  - PKIX validation to the trust anchors still decides which issuers are accepted. If a wallet answers with no
    credential, set the provider to Off.
  - Key identifiers are never guessed: if any anchor or pinned intermediate has no SubjectKeyIdentifier, the query
    leaves `trusted_authorities` out, with one WARN per loaded provider. Saving the setting explicitly On with such an
    anchor is a `400` on `dcql.trustedAuthorities`.

> **Upgrade note (rolling upgrades, wallet providers).** A node of an earlier version refuses a DCQL query that carries
> `trusted_authorities`. A wallet transaction started on an upgraded node and answered on an old node that shares the
> Redis or PostgreSQL transaction store therefore fails. Do one of these:
> 1. upgrade every replica in one step;
> 2. drain wallet transactions first: no new wallet logins on old nodes, then wait out their lifetime
>    (`transactionTtlSeconds`, 300 s by default);
> 3. set the HAIP-profile providers to Off (`dcql.trustedAuthorities=false`) for the duration of the roll, then back to
>    Default.
>
> The new version reads both forms: it accepts a query with or without `trusted_authorities`.
- **tests** — `TokenStatusListClientTest.connectTimeoutIsThreeSeconds` no longer assumes `10.255.255.1` is
  unroutable. That address answers at once on some networks, which made the test fail there. It now connects to a
  loopback listener whose accept queue is full, and it still asserts the 3 s connect timeout.
- **feature (EUDI Wallet, experimental): trust anchors from signed trusted lists (`EuTrustedListSource`).** A realm can
  add trusted list sources (console: Federation → Trusted lists; API `/admin/realms/{realm}/trusted-lists`) and a
  wallet provider can name them in `trustedLists.sources` (optionally narrowed by `trustedLists.serviceTypes`)
  instead of, or as well as, pasted `trustAnchors`. Formats: ETSI TS 119 612 XML (a trusted list, or a list of
  trusted lists followed one level with the signer it names per pointer) and ETSI TS 119 602 LoTE JSON (JWS), the two
  formats the EU publishes for EUDI Wallet trust. Lists are fetched over the pinned transport (https, egress guard,
  no redirects, 16 MB, 30 s), parsed without DOCTYPE/entities/XInclude, and their signature must verify with a pinned
  signer certificate (Santuario secure validation, no wrapping, whole-list reference only). Only current services of
  the configured types and statuses count; `NextUpdate`, closed lists and sequence-number rollback are enforced. One
  replica refreshes under a row lease; the verified services are stored (Flyway **V81** `trusted_list_source`, also in
  `schema.sql`) and every replica reloads them. A list that cannot be fetched or verified keeps the last good anchors
  until its NextUpdate plus a per-source grace period (default 24 h), then fails closed. Audited as
  `TRUSTED_LIST_REFRESHED|REFRESH_FAILED|STALE|EXPIRED` and `TRUSTED_LIST_CREATE|UPDATE|DELETE|REFRESH_REQUEST`.
  Settings `helix.wallet.trusted-lists.*`. See `docs/eudi-wallet.md` §7.3 (including what is published today: the EUDI
  reference implementation's test list, the Commission's acceptance LoTE of PID providers; no production list of PID
  providers yet) and `helix-iam-server/SECURITY-REVIEW.md` Appendix B.11. Tests: `TrustedListLoaderTest`,
  `PinnedTrustedListFetcherTest`, `TrustedListServiceTest` (PostgreSQL, two replicas), `TrustedListHealthTest`,
  `TrustedListWalletE2eTest`; opt-in `PublishedTrustedListsManualTest` verified the three published lists.
- **security (trusted lists, review of 2026-10-15).** All findings fixed: a refresh racing a settings change can no
  longer store a list after a re-pin (`config_version`, Flyway **V82**; non-re-entrant, renewed lease;
  `TRUSTED_LIST_REFRESH_DISCARDED`); each member of a list of trusted lists has its own state, rollback protection,
  territory/type match and fail-safe grace, and a broken or plain-http member no longer fails the source (Flyway
  **V83** `trusted_list_member`, status `DEGRADED`, per-member audit); reference digests SHA-256/384/512 only (Santuario
  still accepted SHA-1) and no parameterised `rsa-pss`; signers expired more than
  `signer-expiry-grace-days` (180) ago and RSA < 2048 / EC < P-256 keys are refused, expiring pinned signers are
  audited; NextUpdate is capped at issue + 6 months (`max-validity-months`); LoTE service statuses use the
  accepted-status allowlist; stored settings and anchors carry an HMAC keyed from `DB_ENCRYPTION` (Flyway **V84**,
  `TRUSTED_LIST_INTEGRITY_FAILED`); health transitions are conditional on the version judged; sync and refresh run on
  separate threads; renaming a source that providers use is refused, and admin writes are audited with the URL and
  signer fingerprints. Console: FAILING and DEGRADED explained, "Never verified" for ERROR, members table, signer
  expiry warnings, unknown trusted lists caught before saving, and dark-mode danger alerts fixed (a legacy
  `.hx-alert` rule in `app.css` overrode the themed one).
- **security (trusted lists, re-review).** Rollback high-water marks per territory and TSLType that outlive member rows
  (a moved or re-added list cannot come back older; `trusted_list_hwm`, folded into V84); a failed integrity check of
  the stored anchors, member anchors or marks now resets and reloads them from the signed list at the next refresh
  (`TRUSTED_LIST_INTEGRITY_RESET`), and failing or missing settings MACs (including rows stored before V84) need an
  admin re-save, nothing is adopted; the settings MAC covers name, grace, switch and `config_version` too, anchors are bound to
  `config_version`, grace is clamped on read, and a tampered member shows `INTEGRITY`; updates need the `configVersion`
  read (`409` on a concurrent edit; console "changed by someone else, reload"); deleting a source in use is a `409`;
  one lease token per refresh; an integrity reset keeps the rollback floors (top-level sequence number and high-water
  marks, re-MACed by the next verified load), a member row below its floor is not counted, settings saves compute
  their MACs from locked rows, and high-water-mark territories are upper-cased. Scope (maintainer ruling): the MACs are
  best-effort tamper detection, not a defence against database writers; the high-water marks stop network rollback. **Behaviour change:** the signer-expiry grace is split per ETSI TS 119 615 —
  `signer-expiry-grace-days` (admin-pinned top-level signers) now defaults to **0**, and the new
  `member-signer-expiry-grace-days` (signers named by a verified LOTL) to 180. As of 2026-10-15 the EUDI test LOTL
  needs `signer-expiry-grace-days` ≥ ~120 and the EC acceptance LoTE ≥ ~30; the console says when a list is refused
  for an expired pinned signer.
- **admin API:** `trustAnchors` on a wallet connection is no longer required when `trustedLists.sources` is set;
  an unknown source name is a `400` on `config.trustedLists.sources`.

## v1.0.0-rc.10 (CodeQL follow-up to rc.9)

Clears the CodeQL alerts raised by the rc.9 scan (`845fd29`). Details and the one dismissed alert are in
`helix-iam-server/CODEQL-TRIAGE.md` ("rc.9 scan").

- **security (log injection, #294, #295)** — `IdentityProviderRegistry` logged the realm id and the provider aliases
  of a store-backed reload (both admin input, via the identity-provider and realm import/export APIs) as they were.
  They now go through `LogSafe.sanitize`, as does the static alias list, so a CR/LF cannot forge a log line.
  `IdentityProviderRegistryTest.reloadLogs_neutraliseLineBreaksInTheRealmAndAliases`.
- **security (sensitive log, #293)** — the egress guard's "blocked outbound URL" warning logged the URL's scheme, host
  and port. Callers pass URLs that carry tokens (an APNs device token in the path, an upstream logout's
  `id_token_hint` in the query); only scheme, host and port were ever printed, but that guarantee lived in a helper.
  The warning now names only the resolved address and the port. The exception still names the host.
  `OutboundUrlGuardTest.aBlockedUrl_isLoggedOnlyAsTheResolvedAddressAndPort_neverAsTheUrl`.
- **import (user-controlled bypass, #296)** — a false positive (a client refused for its `jwksUrl` was never written,
  so skipping its auth-method check skipped nothing), restructured anyway: realm import checked a client's `jwksUrl`
  and then its `tokenEndpointAuthMethod` in two early-exit steps, so a refused client reported only the first problem.
  Both rules now run in one `clientProblems` step for every client that reaches validation, and the failure lists
  every invalid field. The document-to-write mapping is a separate method.
  `RealmImportServiceTest.anImportedClientWithSeveralInvalidFields_isRefusedOnce_withEveryFieldError`.
- **crypto naming (#290, #291)** — not SHA-1: the imported-key match proof built its JCA algorithm as `"SHA" + "256"
  + "withECDSA"`. It now maps ES256/ES384/ES512 to the constants `SHA256withECDSA`/`SHA384withECDSA`/`SHA512withECDSA`
  (RFC 7518 §3.4) and refuses anything else. `SoftwareRealmSigningKeysSignatureAlgorithmTest`.
- **tests (#288, #292)** — `SoftwareRealmSigningKeysTest` proves RSA keys are refused with 2048- and 3072-bit keys
  instead of 1024; the eID mutual-TLS test's stub ARS trusts a trust store holding only the SP certificate (no
  trust-all manager) and reads the presented certificate from the TLS session.
- **tests (build hang)** — `AdminPasswordFileBootE2eTest`'s stdout tee read the test class's statics while the class was
  still initialising; a background thread writing to stdout then held the log appender's lock while waiting for the
  class, and the initialising thread waited for that lock, hanging `mvn verify`. The tee now holds its own references.
- **dismissed (#287)** — `TestPki.KeyType.RSA_1024` (test code) is the input for the wallet tests that check a
  1024-bit RSA issuer or anchor key is refused; a small key is the point of those tests.

## v1.0.0-rc.9 (2026-10-13; also lists what shipped in `v1.0.0-rc.8`)

rc.9 adds the EU Digital Identity Wallet sign-in (OpenID4VP 1.0 / HAIP 1.0 verifier, **experimental**), the
Spring Boot 4.1 / Spring Framework 7 / Spring Security 7 platform, and a complete outbound-request (SSRF /
DNS-rebinding) hardening, on top of the rc.8 security fixes. Read the upgrade checklists below and
`docs/UPGRADING.md` before upgrading: the Spring Boot 4 step must not run old and new pods side by side.

> **BREAKING — upgrade checklist (reverse proxies and host names).** The server now trusts forwarded headers only
> from `HELIX_TRUSTED_PROXIES` and, outside `dev`, answers only for its own host names. Before upgrading:
> 1. Behind any TLS-terminating proxy (ingress, external load balancer, Gateway API, service mesh), set
>    `HELIX_TRUSTED_PROXIES` (Helm: `config.trustedProxies`) to the addresses it connects from. Otherwise issuers
>    and redirects become `http://` (relying parties then reject the tokens' `iss`) and all clients share one
>    rate-limit bucket. The server logs an ERROR once a minute when an https `IDP_BASE_URL` is reached over http.
> 2. List every other host name clients use to reach the server in `HELIX_ALLOWED_HOSTS` (Helm:
>    `config.allowedHosts`), e.g. the in-cluster service name relying parties call for tokens or JWKS. The hosts of
>    `IDP_BASE_URL` and `SP_BASE_URL` are allowed already, on that URL's port; any other `Host`, or one of those hosts
>    with another explicit port, gets `400` (write `host:port` in `HELIX_ALLOWED_HOSTS` to allow it). Probes are
>    unaffected.
> 3. If the install ran without `DB_ENCRYPTION` and you now set it, plan the time-boxed
>    `HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT` / `HELIX_DB_ENCRYPTION_MIGRATE_UNTIL` window (see below).
> 4. eID connections must name a minimum level of assurance the server knows (see below).
> 5. **Spring Boot 4 (see below): upgrade without mixing versions; rollback signs users out.** The new version reads
>    every session and token 1.0 stored, but 1.0 cannot read what the new version writes or rewrites. Follow
>    `docs/UPGRADING.md`:
>    1. list roles named `FACTOR_…` (`deploy/scripts/factor-roles-check.sql`): the prefix is now reserved and such a
>       role is ignored; rename them first;
>    2. back up PostgreSQL, token store included (`helix_authorization`, `helix_authorization_token`,
>       `helix_http_session`), and Redis if used;
>    3. upgrade so that no 1.0 pod runs while a new one serves: `helm upgrade --server-side=false --set
>       strategy.type=Recreate` (Helm 4 needs the client-side apply once, because the 1.0 chart never rendered
>       `spec.strategy`), or scale to **0** first and then upgrade. A rolling update, or one replica, still mixes them;
>    4. a rollback signs out every session the new version wrote and drops every authorization it wrote or rewrote (a
>       sign-in, code exchange, refresh, revocation, consent). The 1.0 chart has no `strategy` value, so: scale to 0,
>       delete `spring:session:*` (and `helix:authz:*` with `HELIX_TOKEN_STORE=redis`) with
>       `deploy/scripts/redis-delete-keys.sh` (on Redis, 1.0 answers HTTP 500 for them), `helm rollback`, scale back
>       up if needed;
>    5. sessions: every new sign-in carries Spring Security 7's sign-in factor (`FactorGrantedAuthority`), a class 1.0
>       does not have, which is why 1.0 cannot read them.
>
>    Only if you set Spring properties directly (environment variables `SPRING_*` / `MANAGEMENT_*` or a mounted
>    `application.properties`; the Helm chart and the `HELIX_*` settings are unchanged): `server.error.*` is now
>    `spring.web.error.*` (e.g. `SERVER_ERROR_INCLUDE_MESSAGE` → `SPRING_WEB_ERROR_INCLUDE_MESSAGE`; the shipped
>    configuration is renamed, see below); `spring.session.redis.*` is now `spring.session.data.redis.*`; the
>    application's JSON mapper is configured by `spring.jackson2.*` (was `spring.jackson.*`, which now configures
>    Boot's Jackson 3 mapper only); `spring.dao.exceptiontranslation.enabled` is now
>    `spring.persistence.exceptiontranslation.enabled`.
> 6. EUDI wallet providers without an explicit `revocationChecking` now check issuer certificates with `HARD_FAIL`
>    (was `SOFT_FAIL`): an issuer certificate whose CRL / OCSP status cannot be determined, including one that names
>    no CRL or OCSP endpoint, is refused. Set `revocationChecking` to `SOFT_FAIL` (console: Credentials → Issuer
>    certificate revocation) for an issuer that publishes neither (see below).
> 7. An SMTP relay on a private or loopback address (in-cluster mailer, `localhost` relay) must be listed in
>    `HELIX_EGRESS_ALLOWED_PRIVATE_HOSTS` (Helm: `config.egressAllowedPrivateHosts`), and a relay on a port other than
>    25, 465, 587 or 2525 in `helix.messaging.smtp.allowed-ports` (`HELIX_MESSAGING_SMTP_ALLOWED_PORTS`, ports or ranges
>    such as `1025,8025-8030`). Until then sends fail with `CONFIGURATION` ("not allowed by the egress policy"). This
>    covers the operator's **global relay** too (`helix.notification.smtp.*`, the fallback when a realm has no email
>    provider), not only realm providers. List entries as `host:port` (e.g. `mailer.mail.svc.cluster.local:587`) so
>    only that port of the host is opened.
> 8. An LDAP federation provider pointing at a private or loopback directory (the usual Active Directory setup) must
>    be listed in `HELIX_FEDERATION_LDAP_ALLOWED_HOSTS` (Helm: `config.ldapAllowedHosts`) by host name or CIDR range.
>    Until then LDAP logins for that provider fail (logged as refused by the egress policy). Only `ldap://` and
>    `ldaps://` URLs are accepted.
> 9. `helix.outbound.fetch.login.*` is split into `login-admin` (OIDC broker, eID, workload identity) and
>    `login-client` (client-assertion JWKS, FAPI request-object JWKS). The old `login` names are still read as
>    `login-admin`.
> 10. Admin, console and realm-import client writes need an `https` `jwksUrl` (`http://localhost` / `http://127.0.0.1` in `dev`
>    only). Flyway `V80` rewrites DCR-stored lowercase `private_key_jwt` to `PRIVATE_KEY_JWT`, and the server logs a
>    WARN at startup for every `private_key_jwt` client without a JWKS URL (it cannot authenticate).
> 11. A `private_key_jwt` client stored earlier with an `http` JWKS URL can no longer authenticate outside `dev`: the
>     token endpoint refuses to fetch it (`invalid_client`). The startup log lists such clients (WARN from
>     `ClientAuthMethodAudit`); change their JWKS URL to https before upgrading.

- **security** — Token exchange on `/oauth2/token` refuses `actor_token` and `actor_token_type` with
  `invalid_request` (maintainer ruling; HelixIAM's supported delegation is `/agent/delegation/token`). 1.0 could not
  complete such an exchange (Spring Authorization Server 1.5 could not store the actor); Spring Security 7 can, and
  HelixIAM's `act` claim would have named the requesting client rather than the actor, with no `may_act` policy. The
  refusal happens before any provider runs, so nothing is issued or stored. Exchanges without an actor
  (impersonation, `audience`/`resource`) are unchanged. Until RFC 8693 actor semantics are implemented there.
  `ActorTokenRefusingConverter`; `TokenExchangeActorRefusedE2eTest` (queue store) and
  `TokenExchangeActorRefusedRedisE2eTest` (Redis store).
- **security** — A sign-in factor is never a role. Spring Security 7 marks every password login with the authority
  `FACTOR_PASSWORD`, and admin RBAC matched authorities to realm role names, so a realm role named `FACTOR_PASSWORD`
  with a grant would have been granted to every password login. Roles are now derived without factors everywhere
  (admin RBAC and its cache, realm-admin checks, `realm_access`/`resource_access` in tokens), every sign-in path
  carries exactly one factor (password, magic link, federated, impersonation) so the derived roles are identical,
  and **the `FACTOR_` prefix is reserved** (any case) like `admin_`: the admin API refuses it for realm roles, client
  roles, service-account roles and agent roles (400), realm import refuses it, and an existing role with that prefix
  (realm role, client role, agent role) is ignored everywhere a role reaches a token: `realm_access`,
  `resource_access`, the `USER_ROLE` protocol mapper, and an agent's own roles.
- **oidc** — `requireProofKey` is pinned on every client HelixIAM builds: Spring Security 7's `ClientSettings` default
  became `true` (1.x: `false`), which had silently made PKCE mandatory for `HelixClientPolicies.tokenExchangeClient`.
  Database clients already pinned it (public: required; confidential: optional), unchanged.
- **security** — The Redis stores now apply the same JEP-290 deserialization allowlists as the queue (PostgreSQL)
  stores (pre-existing gap, found in the Spring Boot 4 review): the Redis token store and SSO-session reader
  (`HELIX_TOKEN_STORE=redis`) use the token allowlist, Spring Session's Redis HTTP sessions (the default session
  store) the session allowlist. A refused or unreadable value is no longer an error: a token entry is absent, and a
  session with any such attribute is dropped and deleted (the user signs in again; with
  `spring.session.data.redis.repository-type=indexed` too, where Spring Session would only skip it), each logged once
  at WARN by class name only. Bytes written are unchanged. `FilteredJdkRedisSerializer`, `RedisSessionSerializationConfig`;
  `FilteredJdkRedisSerializerTest`, `RedisSessionAllowlistE2eTest` (a gadget planted in a real Redis session).
- **helm / config** — Kubernetes service links no longer collide with `REDIS_PORT`. In a namespace with a Service
  named `redis`, Kubernetes injects `REDIS_PORT=tcp://<ip>:<port>`, the variable the server reads as the Redis port
  (binding failed at start-up, also without Redis in use). The server now takes the port from that form
  (`RedisServiceLinkEnvironmentPostProcessor`), and the chart sets `enableServiceLinks: false` (new value, default
  `false`; the server needs none of the injected variables).
- **helm** — New value `strategy` (the Deployment's `spec.strategy`), always rendered in full: by default Kubernetes'
  own default (RollingUpdate, 25% / 25%; existing releases see no change), `strategy.type=Recreate` for the Spring Boot 4
  upgrade. Rendering it in full lets Helm 4's server-side apply switch between the two (a Kubernetes-defaulted
  `rollingUpdate` belongs to no field manager and would otherwise survive a switch to Recreate, which the API server
  rejects). An unknown type, or `rollingUpdate` with `Recreate`, is refused at render time. `e2e/helm-template-check.sh`
  covers the rendering; the new `e2e/monthfold/k3d-helm-upgrade.sh` gate installs v1.0.0-rc.8, upgrades with Recreate,
  switches the strategy both ways and rolls back, on k3d with Helm 4. New `deploy/scripts/redis-delete-keys.sh`
  (rollback; checked by `e2e/redis-delete-keys-check.sh` against requirepass, ACL, TLS and a cluster) and
  `deploy/scripts/factor-roles-check.sql` (pre-upgrade check).
- **security (platform)** — **Spring Boot 4.1.1** (from 3.5.16): Spring Framework **7.0.9**, Spring Security **7.1.1**
  with its OAuth2 authorization server (formerly Spring Authorization Server 1.5.8), Spring Session 4.1, Hibernate
  7.4, Tomcat **11.0.27** (Jakarta EE 11, Servlet 6.1; pinned above Boot's 11.0.24 for CVE-2026-65182 CRITICAL,
  CVE-2026-65905, CVE-2026-68525), Flyway 12.4, springdoc-openapi 3.1.1, Testcontainers 2.0. Spring Framework 6.2
  left open-source support on 2026-06-30; this closes **CVE-2026-47884 and CVE-2026-47890** (spring-webmvc,
  CRITICAL), fixed publicly only in 7.0.9, and puts the server back on a supported line. `trivy fs --scanners vuln
  --severity HIGH,CRITICAL helix-iam-server` reports 0. Behaviour is unchanged; the full suite passes unmodified
  except where an API moved:
  - The authorization server chain applies what `OAuth2AuthorizationServerConfiguration.applyDefaultSecurity` did
    (removed in Spring Security 7) itself: scoped to the authorization server endpoints, authenticated, those
    endpoints exempt from CSRF. `AntPathRequestMatcher` (removed) is replaced by `PathPatternRequestMatcher` for the
    CSP path groups, the admin 401 entry point and the device/PAR public-client converter; the realm routing filter's
    virtual context path is honoured by both. Filter order, CSRF exemptions, session-fixation rotation, the MFA gates,
    rate limits, CSP and the `StrictHttpFirewall` (`%`, `;`, `//` refused) are unchanged and covered by the existing
    tests (`LoginRateLimitPathEncodingE2eTest`, `WalletLimitPathEncodingE2eTest`, `LoginSecurityHeadersTest`, …).
  - **Stored tokens survive the upgrade.** Spring Authorization Server 1.x gave its serializable classes one shared
    `serialVersionUID`; Spring Security 7 gives each its own, so every `OAuth2Authorization` 1.0 stored (queue/
    PostgreSQL and Redis token stores) failed to deserialize and would have been dropped, invalidating every refresh
    token at the upgrade. `LegacyAuthorizationServerSerialization` accepts the 1.x descriptor only for classes in
    the authorization server package whose serialized fields are unchanged (all persisted ones); the stores'
    JEP-290 allowlists still apply. `PersistedStateUpgradeCompatibilityTest` reads an authorization and a sign-in
    session written by 1.0 (Boot 3.5.16) and checks every token, claim and attribute; sessions needed no change.
  - **Jackson:** the application stays on Jackson 2 (`com.fasterxml.jackson`, 2.21.7) through Boot's deprecated
    `spring-boot-jackson2` module, and `spring.http.converters.preferred-json-mapper=jackson2` keeps Spring MVC's
    JSON exactly as before (controllers return Jackson 2 `JsonNode` trees; Boot 4's Jackson 3 defaults differ).
    Jackson 3 (3.2.3) is on the classpath for webauthn4j, Flyway 12 and Spring Security's internals, as webauthn4j
    already brought it in 1.0; `jackson-annotations` 2.22 serves both. Moving the application to Jackson 3 is on
    the roadmap.
  - Spring Security 7's `JwtGenerator` copies `auth_time` from the previous ID token on a refresh and reads it as a
    `java.util.Date`; HelixIAM's ID tokens (and every one 1.0 stored) carry it as epoch seconds, so each ID-token
    refresh failed with HTTP 500 (`IdTokenSessionClaimsE2eTest`, `BackchannelLogoutE2eTest`, … caught it). The
    token store's binding layer hands a loaded authorization out with the same instant as a `Date` (in memory; the
    stored row and the emitted `auth_time`, still epoch seconds, are unchanged).
  - Log4j 2.25 (with Boot 4): the console appenders now `follow` `System.out`, as Boot's own configuration does.
    Output and format are unchanged.
  - Spring Boot 4 ignores `server.error.include-*`; the security review H3 pin (no exception message, binding
    errors, stack trace or exception class in error bodies) is now set under `spring.web.error.include-*`, where
    Boot reads it (`spring-boot-properties-migrator` found the four keys; Boot's defaults happened to match, so
    production answered the same, but the dev profile's `always` was lost). `ErrorDetailPropertiesTest` guards it.
  - `Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers` is again on every response that
    passes HelixIAM's CORS filter (discovery, JWKS, token endpoint, pages, …), CORS request or not, as with Spring
    Framework 6. Spring Framework 7 adds it only when a CORS configuration applies, so a shared cache could have served
    one origin's response to another. `VaryingCorsProcessor`; `CorsVaryHeaderE2eTest`.
  - Discovery: the OIDC discovery document and the RFC 8414 metadata carry exactly the same keys and values as in 1.0;
    only the order differs (key order, and `grant_types_supported` lists token exchange before the device code).
    Harmless: JSON object keys and these value sets are unordered. `DiscoveryDocumentsE2eTest` pins both documents in
    full, ignoring order, and passes on 1.0 and on this release.
  - Flyway's auto-configuration needs `spring-boot-starter-flyway` now; the environment post-processor is
    registered under Boot 4's `org.springframework.boot.EnvironmentPostProcessor` key; Logback is excluded from the
    new web starter (Log4j2 only, as before).

- **security** — Replica convergence: see the version-based poller (`feat/wallet-production`). An identity provider
  disabled, deleted or re-keyed through one replica, or imported with a realm, reaches the other replicas through that
  branch's `idp_config_version` poll.
- **security** — A realm import now checks an eID connection's scheme and minimum level of assurance like an admin
  write (review #9): an unknown one is reported as a failed import with the field error instead of being saved and
  only skipped, with a WARN, when the registry loads it.
- **security** — `X-Real-IP` is no longer read, not even from a trusted proxy (review #13). A trusted hop that neither
  set nor stripped it (an L4 load balancer, an ingress with forwarded headers off) let a client that sent no
  `X-Forwarded-For` choose its own address for rate limits and the audit log. **Operators:** a trusted proxy must
  append to `X-Forwarded-For`; one that sets only `X-Real-IP` now makes every client appear as the proxy.
- **security** — The wallet's fail-open status audit (`WALLET_STATUS_CHECK_FAILED`, written when
  `FAIL_OPEN_WITH_AUDIT` lets a login through without a revocation check) now carries the wallet `transactionId`, so an
  operator can tie the fail-open to the login it let through (final review m4).
- **security** — Wallet review minors: `IdentityProviderConfig.toString()` (both copies) now redacts every secret
  value, so a future log line of the runtime config cannot leak a client secret, private key, bind password or
  pepper. An identity-provider update that changes the protocol drops the stored secrets the new protocol does not use
  (they stayed encrypted and unread). A federated login whose pending commit throws an `Error` no longer stays signed
  in: `PendingFederatedLogin.finish` catches it around the commit only, clears the context, invalidates the session,
  reports the failure, and then rethrows it.
- **security** — L6 done: the generated bootstrap admin password is never logged. It is written (0600) to
  `HELIX_ADMIN_PASSWORD_FILE` (default `$TMPDIR/helixiam-admin-password`, `/tmp/helixiam-admin-password` in the image)
  and only the path is logged; a whole-boot test captures every log line and checks it. `HELIX_ADMIN_USERNAME`,
  `HELIX_ADMIN_PASSWORD` and `HELIX_ADMIN_PASSWORD_FILE` are now declared in `application.properties`, so they also
  work as `--HELIX_ADMIN_PASSWORD=…` command-line arguments, as the README shows. The Helm install notes and
  `values.yaml` no longer say the password is in the logs; the chart README, NOTES, the README and the compose file
  show how to read it (`kubectl exec deploy/helixiam -- cat /tmp/helixiam-admin-password`,
  `docker compose exec server cat /tmp/helixiam-admin-password`).
- **security** — L5 done: the legacy AES/ECB format of secret columns is migrated away. At every startup (Flyway and
  `schema.sql` paths) `LegacyEncryptionBackfill` re-encrypts every value of every `AttributeEncryption` column (realm
  keys, TOTP and HOTP secrets, client secrets, SCIM tokens, webhook secrets, identity-provider and messaging secrets,
  SAML relying-party certificates, verifier keys, wallet peppers) that is still in the legacy format to AES-GCM. It is
  idempotent, logs table, column and row id only, and skips and names rows it cannot read in a production-readiness
  WARN. After the run the converter no longer falls back to ECB, so a legacy value fails closed, unless
  `HELIX_DB_ENCRYPTION_ALLOW_LEGACY=true` (default `false`). A legacy decryption must also be valid UTF-8, so a value
  under another key no longer "decrypts" to garbage about 1 time in 256 (review #10). Each column is migrated in its own
  transaction: a column that fails (a database error) is logged at ERROR by table and column, reported as a
  production-readiness WARNING and counted in the gauge `helix_db_encryption_legacy_failed_columns`, the other
  columns are still migrated, and the ECB fallback then stays on (legacy TOTP secrets and keys keep reading) until a
  start migrates it. A WARNING, not fatal: the condition comes from a runtime database failure after the startup
  check, and refusing to serve would also lock out every legacy secret that still reads. The candidate rows are read in
  id order, so two replicas booting together lock them in the same order. **Upgrade:** nothing to do; the
  first start rewrites the legacy rows (check its log for the readiness WARN). Only if that WARN names rows, or a
  database restored from an older backup is attached to a running server, set `HELIX_DB_ENCRYPTION_ALLOW_LEGACY=true`
  (or restart, which re-runs the job) while you investigate.
- **security** — The Host allow-list ignored the port, so `Host: localhost:6666` on a server whose `IDP_BASE_URL` is
  `http://localhost:8080` put `:6666` into the request-derived issuer. Outside `dev`, a host of `IDP_BASE_URL` or
  `SP_BASE_URL` now accepts only that URL's port (its explicit one, or the scheme's default), plus a `Host` without a
  port, which no built URL shows. `HELIX_ALLOWED_HOSTS` entries accept any port unless written `host:port` (or
  `[v6]:port`). A port outside 1–65535 gets `400`. The probe exemptions (the connection's own address, `localhost`
  from a loopback peer) apply only on the port the connection arrived on or the scheme's default port (which no URL
  shows); `/actuator/health/**` still answers any host and port. **Operators:** a client that reaches the server by its base URL's host on another port (for example
  through a port mapping) needs that `host:port` in `HELIX_ALLOWED_HOSTS`.
- **security** — `HELIX_DB_ENCRYPTION_MIGRATE_UNTIL` was checked only at startup, so a server started inside the
  plaintext-read window kept reading plaintext secret columns after it ended, until its next restart. The end date
  (its last day included, UTC) is now enforced on every read: after it, a plaintext read fails closed and logs an
  ERROR naming the date.
- **security** — `/flow` completion now applies the MFA enrolment rule too. In a realm that requires MFA, a user who
  had not enrolled TOTP and completed an admin-built flow whose challenge was not TOTP (email OTP, push, QR) got a
  full session at `/flow`. Like the password and federated completions, the user now goes to `/mfa/enable` with the
  sign-in still pending (and a federated login's pending commit kept until the enrolment ends), on a new session id.
- **eID** — Classic DigiD: the AuthnRequest asked for the `urn:nl-eid-gdi:1.0:LoA:*` URN, which a DigiD endpoint
  does not know. Logius' Koppelvlakspecificatie DigiD SAML Authenticatie v3.5 maps the levels to SAML 2.0 context
  classes (Basis = `PasswordProtectedTransport`, Midden = `MobileTwoFactorContract`, Substantieel = `Smartcard`, Hoog
  = `SmartcardPKI`), requested with `RequestedAuthnContext Comparison="minimum"`. The DigiD keywords `loa1`–`loa4`
  (and `basis`/`midden`/`substantieel`/`hoog`) now resolve to those classes, both in the request and in the
  comparison. A minimum stored as an `urn:nl-eid-gdi:1.0:LoA:*` URN is compared as before but requested as the oasis
  class of the same level, and brokers that assert those URNs keep working. No scheme sends an nl-eid-gdi URN in the
  request any more (see `docs/FEATURES.md`). The
  earlier "Other (custom)" workaround (storing the oasis class by hand) is no longer needed.
- **security** — SAML runs on OpenSAML **5.2.3** only (M7 done). The unused `spring-security-saml2-service-provider`,
  whose POM still pulled OpenSAML 4.3.2, is removed; the pom declares OpenSAML 5 (`opensaml-saml-api`/`-impl`,
  `shib-support` 9.2.3, xmlsec 3.0.6, cryptacular 1.3.0, BouncyCastle 1.86) directly. No 4.x is left on the tree.
- **security** — eID artifact binding (classic DigiD): the back-channel `ArtifactResponse` must now carry a valid
  signature by the IdP's metadata signing key. An unsigned response is refused, and so is any response when the eID
  connection has no IdP signing certificate (DEEP-3). The inner assertion signature check is unchanged.
- **security** — **BREAKING.** The request-derived issuer could be steered with the `Host` header itself: a server
  reached directly answered `Host: evil.example` with issuer `http://evil.example/realms/...`. Outside the `dev`
  profile, a request whose host (after trusted forwarded-header processing) is not the host of `IDP_BASE_URL` or
  `SP_BASE_URL` or listed in the new `HELIX_ALLOWED_HOSTS` now gets `400` before any issuer or URL is derived. The
  connection's own address (kubelet probes send the pod IP), `localhost` from a loopback peer (Docker
  `HEALTHCHECK`) and `/actuator/health/**` stay reachable. An https `IDP_BASE_URL` reached over plain http logs an
  ERROR (once a minute) that names `HELIX_TRUSTED_PROXIES`. The Helm install notes now warn whenever
  `config.trustedProxies` is empty (not only with the chart's ingress), and the chart gains `config.allowedHosts`.
  The SAS issuer is not pinned. Only `server.forward-headers-strategy=framework` is supported.
- **security** — A federated sign-in (OIDC, SAML or eID broker) skipped the post-broker second factor. The realm's
  browser flow gates the TOTP step with the `mfa-enabled` condition, which read the user from the security context;
  `FederatedLoginCompleter` starts that flow before anyone is in the context, so the condition answered "MFA not
  enabled" and a full session was established for a user with MFA enabled. The `/oauth2/authorize`, SAML and account
  console gates still asked for the code, but other surfaces saw a full session. The condition now answers for the
  flow's own user (the flow state's user id, loaded by id unless the pending principal is that user), and a flow user
  that cannot be loaded fails the flow instead of skipping the step. The flow's TOTP check likewise only verifies a
  code against the flow's own user. No other flow condition read the security context.
- **security** — An eID connection (DigiD, eHerkenning, eIDAS) whose minimum level of assurance was not a level Helix
  knows accepted every asserted level: `EidLevelOfAssurance.meetsMinimum` ranked the unknown minimum as rung 0, so any
  recognised level met it. An unrecognised non-blank minimum is now never met (fail closed); a blank minimum still
  means "no minimum". The keywords the console stores (`loa1`–`loa4` for DigiD, `loa2`/`loa2plus`/`loa3`/`loa4` for
  eHerkenning, `low`/`substantial`/`high` for eIDAS) were never mapped, so the console's default `loa3` was such an
  unknown minimum; they are now mapped to the scheme's URN, which the AuthnRequest also asks for. An unknown minimum is
  refused when the connection is saved (`400` with `fieldErrors.minimumLoa`) and when it is built (a stored connection
  is skipped with a warning; a connection in `helix.federation.eid` fails startup).
- **security** — A secret column (TOTP and HOTP secrets, realm signing keys, client and webhook secrets, SCIM tokens,
  messaging-provider secrets, SAML relying-party certificates) whose stored value could not be decrypted was returned
  as stored: `AttributeEncryption` fell back to the legacy AES format and then handed back the raw column, so a
  plaintext row, a value written under another key, or an altered value was read as if it were the secret. The read
  now fails with an `IllegalStateException` that names the cause (not encrypted, or the key changed or the value was
  altered), never the value. The legacy AES format still decrypts. **Operators:** a deployment that ran without
  `DB_ENCRYPTION` and then set it may hold plaintext rows; it uses the migration mode below while it migrates.
- **security** — The client IP came from a client-controlled header. The rate limiter, the audit log, the adaptive-auth
  risk signals and the CAPTCHA `remoteip` took the first `X-Forwarded-For` (or `X-Real-IP`) address from any client, so
  a client could get a fresh sign-in rate-limit budget per request, put any address in the audit log, or claim a
  known IP. `server.forward-headers-strategy=framework` did the same to `getRemoteAddr()`. One `ClientIpResolver` now
  decides the client IP everywhere: the TCP peer, read beneath Spring's `ForwardedHeaderFilter`, unless that peer is
  listed in the new `helix.security.trusted-proxies` (`HELIX_TRUSTED_PROXIES`, comma-separated IPs or CIDR ranges, IPv4
  or IPv6, default empty). From a trusted proxy, `X-Forwarded-For` is read from the right and the first address that
  is not a trusted proxy is the client. Header values are parsed as IP literals only. **Operators:** behind an ingress
  controller, load balancer or the console's nginx, set `HELIX_TRUSTED_PROXIES` (Helm: `config.trustedProxies`) to the
  addresses the proxy connects from. Otherwise every request appears to come from the proxy and all clients share one
  sign-in rate-limit bucket. The same list now also gates `X-Forwarded-Proto`/`-Host` (next entry).
- **eID** — Classic DigiD (Koppelvlak SAML) asserts SAML 2.0 context classes, not the `urn:nl-eid-gdi` levels, so
  with the fail-closed minimum above every classic DigiD sign-in against a set minimum (such as the console's `loa3`)
  would have been refused. The DigiD ladder now also ranks `PasswordProtectedTransport` (Basis),
  `MobileTwoFactorContract` (Midden), `Smartcard` (Substantieel) and `SmartcardPKI` (Hoog), the mapping of Logius'
  Koppelvlakspecificatie DigiD SAML Authenticatie v3.5; eHerkenning and eIDAS are unchanged.
- **security** — `Forwarded` and `X-Forwarded-Proto/-Host/-Port/-Prefix` were honoured from any client
  (`server.forward-headers-strategy=framework`). The OIDC issuer is derived from the request, so a single request with
  `X-Forwarded-Host: evil.example` got a discovery document with issuer `https://evil.example/...`; the same headers
  steered `isSecure()`, redirects and every absolute URL. `TrustedProxyForwardedHeaderFilter` replaces Spring Boot's
  `ForwardedHeaderFilter` and applies those headers only when the TCP peer is in `helix.security.trusted-proxies`;
  from any other peer they are removed. **Operators:** behind a TLS-terminating ingress or load balancer,
  `HELIX_TRUSTED_PROXIES` (Helm: `config.trustedProxies`) is now required: without it the server sees plain HTTP and the
  issuer and redirects become `http://`. A startup warning says so when `IDP_BASE_URL` is https and the list is empty.
- **security** — eHerkenning EH2+ (`loa2plus`) ranked the same as EH2, so a connection with minimum `loa2plus` accepted
  a plain EH2 assertion. EH2+ now has its own rung between EH2 and EH3 (the ladders are spaced by 10 internally).
- **security** — When a `/flow` sign-in completes, the pending authentication is promoted only if it belongs to the
  user the flow completed for; otherwise nothing is promoted, the session is invalidated and the user is sent back to
  sign in. The completed sign-in also gets a new session id (`changeSessionId`).
- **security** — Reading plaintext secret rows is its own, loud, time-boxed migration mode instead of a side effect
  of `HELIX_ALLOW_PLAINTEXT_SECRETS` (an install that had set that flag and later added a key would have been in the
  mode without noticing). `HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT=true` reads undecryptable secret columns as stored
  (a WARN per read, naming entity and column where known; encrypted on the next write), logs an ERROR banner at
  startup and every hour, and outside `dev` the server refuses to start unless `HELIX_DB_ENCRYPTION_MIGRATE_UNTIL` is
  a date at most 30 days ahead. `HELIX_ALLOW_PLAINTEXT_SECRETS` again only accepts running without a key, and an
  empty `DB_ENCRYPTION` now means "no key" (it failed startup with "Empty key" before). The per-thread record of
  plaintext reads is removed after each entity load and at the end of each transaction.
- **security** — In a realm that requires MFA, a user who had not enrolled a second factor got a full session from a
  federated sign-in, and from a password sign-in whose post-password flow completed (the flow engine, and resuming
  after required actions such as a password update). The authorize, SAML and account gates still asked for
  enrolment, but the session was full. Both now keep the MFA gate and send the user to `/mfa/enable`, like the
  magic-link and legacy password paths. A federated sign-in also gets a new session id (`changeSessionId`) and drops
  any second-factor pass from an earlier sign-in in that session.
- **docs** — eID minimum levels of assurance are documented in `docs/FEATURES.md` ("eID minimum level of
  assurance"): the keywords and URNs each scheme accepts, and the DigiD levels per Logius' Koppelvlakspecificatie
  DigiD SAML Authenticatie v3.5.
- **security (checked, no change)** — Re-spelling the sign-in path does not bypass the login rate limit.
  `RateLimitFilter` matches the still-encoded servlet path that `RealmRoutingFilter` passes on, so
  `/realms/{r}/l%6Fgin` is not counted. But Spring Security's `StrictHttpFirewall` then refuses any `%` or `;` in the
  URL (400), Tomcat refuses `%2F`, `/./` and `//` are refused, and a different case or a trailing slash is not the
  login endpoint (401), so no sign-in attempt is processed. `LoginRateLimitPathEncodingE2eTest` keeps it that way.
- **feat (EUDI wallet, production readiness)** — Identity-provider changes reach every replica without a restart.
  Every save and delete (admin API, console, realm import) bumps the realm's row in the new `idp_config_version` table
  (Flyway V78, `schema.sql`) in the same transaction; each replica polls it every
  `helix.federation.store.poll-interval-seconds` (default 10, 0 = off) and reloads the realms that moved. Plain
  PostgreSQL, so the `queue` deployment converges as well. A realm import now also reloads the importing replica at
  once (it used to refresh nothing). Publication is version-ordered: a refresh reads the realm's version before its
  configs and an older set is never published over a newer one (two concurrent writes could leave the older set live).
- **feat (EUDI wallet)** — A PostgreSQL wallet transaction store (`JdbcWalletTransactionStore`, table
  `wallet_transaction`, Flyway V79): a multi-replica deployment without Redis needs no sticky sessions any more. It is
  the store whenever the session store is `queue`, and whenever no Redis is configured; Redis stays the store with the
  Redis session store. Same semantics as the Redis store (one conditional `UPDATE … RETURNING` per transition, the
  shared 20-thread race suite passes), secrets hashed (SHA-256 lookups) or encrypted (`DB_ENCRYPTION`, fails closed),
  expired rows swept every `helix.wallet.transaction-sweep-seconds` (default 60). **Behaviour change:** the in-memory
  store is now used only with `helix.wallet.transaction-store=memory` (development and tests); a server with neither
  Redis nor a database refuses to start instead of falling back to it.
- **feat (EUDI wallet, security)** — "Wallet linked" notice: when a wallet is linked to an account (the account
  console, or the sign-in upgrade path that adds the administrative-number link), the account's email address is told
  so and asked to unlink it and change the password if it was not them. New default message template
  `wallet-linked-notice` (English, Dutch); no wallet or PID data in it; nothing is sent without an email address.
  Mitigates the documented QR-relay and reverse linking-CSRF limits.
- **fix (EUDI wallet)** — The broker's per-login session attributes (state, nonce, SAML request id, browser binding,
  wallet transaction) and the account console's wallet-link state are keyed by (realm, alias) instead of alias only:
  wallet logins in two realms that both use the alias `eudi-wallet`, from one browser at the same time, no longer
  clobber each other. **Upgrade note:** the session keys were renamed, so a federated or wallet login (or a wallet
  link) that is in flight while the deploy rolls out, started on the old version and finished on the new one, ends
  with `error=federation` (or a refused link); starting it again works. Transient, no data is affected.
- **fix (EUDI wallet)** — Another realm's wallet connection whose alias matched this realm's OIDC connection made the
  user's OIDC link look like a wallet link: hidden from `/account/identities`, its delete answered 409, its subject
  left out of the GDPR export, and an anonymizing erasure deleted it. The alias is now resolved in the user's own realm
  first.
- **fix (mfa)** — A federated sign-in that had to enrol in MFA first, and whose pending commit was then refused, showed
  the recovery-codes page (whose "continue" led to the federation error) and issued codes for a sign-in that did not
  happen. It now shows the federation error and issues no codes.
- **test (EUDI wallet)** — The mdoc decoding path is checked against DeviceResponses from the EU Digital Identity
  Wallet reference implementation (Apache-2.0, source recorded in `wallet/vectors/SOURCES.md`): IssuerAuth signatures
  with their own `x5chain`, MSOs, item digests. Interop finding: one reference credential carries a 31-byte device-key
  coordinate (a leading zero octet dropped). By maintainer ruling a short coordinate is left-padded and accepted (the
  same point, on-curve check unchanged); longer or empty is still refused, nothing is truncated.
- **security** — SMTPS (implicit TLS) was not pinned: Angus Mail connects its own socket to the configured name for an
  SSL socket factory, so the host was resolved again after the egress check. The SMTP driver now hands Angus the
  validated IP and layers TLS itself with the configured name (SNI, certificate checked against that name, the
  realm's CA bundle); STARTTLS works the same way.
- **security** — LDAP federation: one bind sequence (DNS, service bind, search, user bind) has one 15 s deadline, tries
  at most two resolved addresses, and takes a slot in the new `ldap` outbound group with a per-realm share
  (`helix.outbound.fetch.ldap.max-concurrent` 32, `.per-realm-max` 8).
- **security** — A `private_key_jwt` client whose stored JWKS URL is not https (a row from before the https rule) can no
  longer authenticate outside `dev`: the token endpoint refuses to fetch it, and the startup audit lists such clients.
- **security** — The token endpoint auth method is matched case-insensitively (`Private_Key_Jwt` used to fall back
  silently to a client secret) and stored in one spelling; the admin API and realm import refuse unknown values.
- **security** — Pending webhook and SCIM deliveries are capped across all realms as well (default 20,000 per queue,
  `helix.outbound.deliveries.max-pending`), on top of the 1,000 per realm.
- **fix** — `helix.outbound.fetch.login-client.*` was read but never applied; it is now.
- **fix** — The documentation-prefix check matched `3ff0::/12` instead of `3fff::/20` (RFC 9637), blocking public
  addresses such as `3fff:1000::1`; it now matches `3fff::/20` exactly.
- **fix** — Console: a refused client save shows the server's field errors on the form fields (it showed
  "400 Bad Request").
- **security (affects released versions)** — SMTP relays were not egress-checked: the SMTP driver connected to any
  host and port a realm admin typed, including loopback, cluster-internal and metadata addresses, and resolved the
  name itself. It now goes through `OutboundUrlGuard` (private hosts only via `HELIX_EGRESS_ALLOWED_PRIVATE_HOSTS`),
  connects to the validated address while TLS still verifies the configured host name, accepts only ports 25, 465,
  587 and 2525 unless `helix.messaging.smtp.allowed-ports` lists more, and reports generic errors (no internal
  address or banner in the result). **BREAKING** for internal relays, see the checklist.
- **security (affects released versions)** — LDAP federation was not egress-checked: `JndiLdapDirectory` let JNDI
  resolve and connect to any URL a realm admin typed (any scheme JNDI accepts, referrals per JNDI default). Now only
  one `ldap://` or `ldaps://` URL; the host is resolved once and both binds connect to the validated address through a
  pinned socket factory; LDAPS verifies the certificate against the configured name; referrals are ignored and reads
  time out. Private and loopback directories need `helix.federation.ldap.allowed-hosts` (host names or CIDR ranges,
  set by the deployment; a realm admin cannot widen it); metadata and link-local addresses stay refused even inside a
  listed range. **BREAKING** for internal directories, see the checklist.
- **security** — APNs: the provider `host` was free text, so push requests carrying the realm's APNs bearer token
  could be sent to any public host. It is now restricted to `api.push.apple.com` / `api.sandbox.push.apple.com`
  (HTTP/2, no redirects); anything else is a configuration error.
- **security** — Virtual-thread pinning: the outbound fetch limiter and socket slots waited inside `synchronized`
  blocks, which on JDK 21 pins the carrier thread, so 1,000 webhook or SCIM deliveries stuck on one realm's tarpit
  could stall every virtual thread, logins included. They now use `ReentrantLock` / `Condition`. Webhook and SCIM
  deliveries are bounded per realm (1,000 pending; overflow dropped and logged once a minute, never blocking the
  caller).
- **security** — Outbound slots: the `login` group is split into `login-admin` (OIDC broker, eID, workload identity)
  and `login-client` (client-assertion and FAPI request-object JWKS, whose URLs any registered client chooses), each
  with its own `helix.outbound.fetch.<group>.max-concurrent` (32) and `.per-realm-max` (8). Back-channel logout and
  SAML metadata import pass their realm explicitly; calls without a realm share one bounded "no realm" partition.
- **security** — The decoder / JWKS caches of the client-assertion decoder, the FAPI request-object filter and the
  OIDC broker token client are bounded LRU caches (1,000 entries) instead of unbounded maps cleared on overflow.
- **security** — Local-use NAT64 `64:ff9b:1::/48` is refused outright (it has no public meaning), also for an
  allowlisted host.
- **security** — Realm import (API, realm-config folder, Keycloak import) wrote a client's `jwksUrl` unchecked; it now
  applies the admin API's rule (https with a host; http to `localhost` / `127.0.0.1` only in `dev`). A client that
  breaks it is not created or updated and is reported as a failed `clients` entry with its field error
  (`jwksUrl: The JWKS URL must be an https URL.`). The console client form checks the same rule before save and shows
  the error inline.
- **fix** — `private_key_jwt` client assertions are accepted with `typ` `JWT`, absent, or `client-authentication+jwt`.
- **fix** — The SIEM audit webhook (`helix.audit.http.*`) has an explicit connect timeout, a request timeout within
  (0, 30 s] (2 s when unset, zero or negative; zero used to make every forward fail), no redirects, and a bounded
  backlog of 1,000 lines (overflow dropped and logged; stdout keeps every line).
- **security (affects released versions)** — private_key_jwt client JWKS fetched unguarded: for a `private_key_jwt`
  client, the token endpoint's client-assertion decoder (Spring Authorization Server's) fetched the client's
  `jwk_set_url` with its own RestTemplate: no outbound guard, redirects followed. Anyone who can register a client (an
  admin, or anyone through open DCR) chooses that URL, so the token endpoint could be made to call internal or
  metadata addresses. It is now fetched through `OutboundUrlGuard` on the pinned transport, without redirects, with
  Nimbus caching (refetch on an unknown `kid`). DCR now accepts only `client_secret_basic`, `private_key_jwt` and
  `none` as `token_endpoint_auth_method`, requires an https `jwks_uri` that the guard allows (checked at registration),
  and stores `private_key_jwt` so the token endpoint actually enforces it.
- **fix (regression found before release)** — APNs push (iOS push and push MFA) failed after the M6 move: APNs is
  HTTP/2 only and the pinned client speaks HTTP/1.1. APNs goes over the JDK client with HTTP/2 again, redirects off,
  and only to `api.push.apple.com` / `api.sandbox.push.apple.com`; a provider `host` setting naming anything else is
  a configuration error (it was free text before).
- **security** — Outbound slots per feature group with a per-realm share: `helix.outbound.fetch.<group>.max-concurrent`
  and `.per-realm-max` for `wallet` (16; old name `helix.wallet.fetch.max-concurrent` still read), `login`, `otp` and
  `outbound` (32 / 8 each), so one realm's slow webhook endpoints cannot delay another realm, or any login or OTP.
- **security** — More IPv6 forms judged by their embedded IPv4 address (RFC 8215 local-use NAT64 `64:ff9b:1::/48`,
  SIIT `::ffff:0:0:0/96`); Teredo `2001::/32` and discard-only `100::/64` refused outright.
- **security** — Pinned-client hardening after review: JWKS fetches use 500 ms connect / 500 ms per read / 3 s total
  and are cached (FAPI request objects, OIDC broker); a redirect's body is never read and duplicate `Location` headers
  are refused; error bodies are capped at 16 KB and truncated (the status is kept); NUL, bare CR and bare LF in a
  response head are refused; TAB is allowed in request header values, non-ASCII and control characters give a clear
  configuration error (Cloudflare driver included).
- **security (affects released versions)** — DNS rebinding (M6 residual): every server-initiated call to an
  admin- or client-configured URL checked the URL with `OutboundUrlGuard` and then let the JDK `HttpClient` (or Nimbus's
  `HttpURLConnection` for JWKS, which also followed redirects) resolve the host again, so a DNS answer that changed
  between the check and the connection could reach internal or metadata addresses. All of them now connect through the
  pinned transport (`PinnedHttpFetcher`): one guarded resolution inside the deadline, a connection to the validated
  address, TLS verified against the host name, no redirects. Moved: webhooks, SCIM provisioning, HTTP email/SMS/push
  drivers, the Cloudflare email API, back-channel and upstream logout, the OIDC broker's token endpoint and JWKS, WIF
  JWKS and issuer discovery, FAPI request-object JWKS, the eID ArtifactResolve, the SAML metadata import. Behaviour is
  otherwise unchanged (methods, bodies, headers, auth, error mapping); new bounds where there were none: the OIDC token
  request 10 s, response bodies 64 KB-1 MB depending on the caller. JWKS fetches keep Nimbus's 500 ms / 500 ms / 50 KB.
- **security (affects released versions)** — SSRF guard bypass: `OutboundUrlGuard` judged an IPv6 address by its
  IPv6 properties only, so a host whose AAAA record was an IPv4-mapped (`::ffff:127.0.0.1`,
  `::ffff:169.254.169.254`) or IPv4-compatible (`::127.0.0.1`) address passed the block-private check and reached
  loopback or cloud metadata. Every guarded outbound call was affected: webhooks, SCIM, OIDC/eID discovery and JWKS,
  DCR and WIF JWKS, logout endpoints, realm HTTP email/SMS, wallet status lists and issuer CRL/OCSP. IPv6 addresses
  embedding an IPv4 address (mapped, compatible, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) are now judged by that
  address; `192.0.0.0/24`, `198.18.0.0/15` and `240.0.0.0/4` (incl. `255.255.255.255`) are blocked; the AWS IPv6
  metadata address `fd00:ec2::254` and broadcast stay blocked even for a host in `HELIX_EGRESS_ALLOWED_PRIVATE_HOSTS`.
  Upgrade; until then, egress filtering in front of the server is the mitigation.
- **security (EUDI wallet)** — **BREAKING default.** Issuer-certificate revocation (CRL / OCSP) no longer uses the
  JDK's own fetching, which followed redirects, resolved names a second time after the outbound guard, had no CRL size
  cap and no cache of ours. `IssuerRevocationClient` fetches over a new pinned transport (`PinnedHttpFetcher`): every
  URL through `OutboundUrlGuard` (http/https only), one DNS resolution and a connection to the validated address (no
  DNS rebinding), no redirects, connect 3 s and 5 s in total per fetch including DNS, 10 s per chain, OCSP at most
  64 KB, CRL at most `helix.wallet.revocation.max-crl-bytes` (10 MB). The JDK PKIX checker still validates what was
  fetched (OCSP through `setOcspResponses`, CRLs through a `CertStore` after a pre-check that keeps its own fallback
  fetch from ever running). Answers are cached until `nextUpdate` (24 h at most), bounded by
  `helix.wallet.revocation.cache-max-entries` (256) and `.cache-max-bytes` (32 MB), shared by every provider. Every
  certificate in the path is now checked on its own, so under `SOFT_FAIL` an undeterminable upper CA no longer hides a
  revoked lower CA. `revocationChecking` defaults to `HARD_FAIL` (was `SOFT_FAIL`) and is now a console field with
  warnings for `SOFT_FAIL` and `OFF`. Docs: `docs/eudi-wallet.md` §7.2.
- **security (EUDI wallet)** — Token Status List fetches use the same pinned transport: the outbound guard's DNS
  resolution now runs inside the 5 s deadline (a slow resolver could hold a login past it) and the connection goes to
  the address the guard validated, with TLS still checked against the host name.
- **security (EUDI wallet)** — The status-list cache is bounded by total decoded list bytes as well as by entry count,
  and one cache is shared by every wallet provider: `helix.wallet.status-list.cache-max-entries` (64) and
  `helix.wallet.status-list.cache-max-bytes` (32 MB; the worst case was about 128 MB per provider).
- **security (EUDI wallet)** — Hardening of the above after review: the JDK's own CRL distribution-point fetching is
  now impossible (CRLs go to the JDK's legacy CRL checker, `com.sun.security.enableCRLDP=false` is forced at startup,
  and JVM settings that would re-enable JDK fetching make CRL evaluation refuse); a CRL is accepted within the JDK's
  15-minute clock skew; a status-list TLS failure or malformed HTTP answer fails closed even under
  `FAIL_OPEN_WITH_AUDIT`; a provider's `allowedHosts` applies before the shared status-list cache; concurrent
  logins share one download per URL and at most `helix.outbound.fetch.wallet.max-concurrent` (16, old name
  `helix.wallet.fetch.max-concurrent`) wallet fetches run at once;
  unparseable or oversized CRLs are not downloaded again for 60 s; cached CRLs count their parsed heap;
  `max-crl-bytes` is capped at 100 MB; stricter HTTP framing in the pinned client (conflicting `Content-Length`,
  `Content-Length` with `Transfer-Encoding`, signed numbers, obs-fold, protocol switch refused; non-ASCII paths
  percent-encoded; request headers validated before connecting); a stalled TLS fetch is abandoned at its deadline.
  Worst-case verification time per credential is about 25 s (`docs/eudi-wallet.md` §7.2).
- **refactor (EUDI wallet)** — The CWT (mdoc) form of a Status List Token is parsed by its own class, `StatusListCwt`;
  no behaviour change.
- **security (dependencies)** — Sandbox RP: `proxy-addr` pinned to 2.0.8 via an `overrides` entry (CVE-2026-90711,
  CRITICAL; express pulls it transitively at `~2.0.7`); `npm audit` is otherwise clean.
- **security (dependencies)** — Terraform provider: `golang.org/x/net` v0.58.0 → v0.60.0 (CVE-2026-78669 HIGH,
  CVE-2026-78663/CVE-2026-78660/CVE-2026-78659; all four trace to the same module/fix), pulling `golang.org/x/sys`
  and `golang.org/x/text` along via `go mod tidy`; `govulncheck` now reports no module-level vulnerabilities (only
  unrelated Go-toolchain/stdlib findings that need a newer local `go` binary, not a `go.mod` change).
- **security (dependencies)** — helix-iam-server (patch-level only, no framework major): Guava 33.7.2-jre,
  webauthn4j 0.31.11 (Dependabot's Maven minor/patch group); Jackson 2.21.4 → 2.21.7 (CVE-2026-89407,
  CVE-2026-89425, CVE-2026-68497, CVE-2026-91776, CVE-2026-91777), Netty 4.1.135 → 4.1.139.Final (CVE-2026-59901,
  CVE-2026-75595 CRITICAL), httpcore5/httpcore5-h2 5.3.6 → 5.4.4 (CVE-2026-54399, CVE-2026-54428), Tomcat
  10.1.55 → 10.1.61 (CVE-2026-65182 CRITICAL, CVE-2026-65905, CVE-2026-68525). CVE-2026-47884 / CVE-2026-47890
  (spring-webmvc) are closed by the Spring Boot 4 upgrade above.
- **images and manifests (dependencies)** — console image base bumped nginx 1.29-alpine → 1.31-alpine
  (Dependabot #33); `anchore/sbom-action` 0.24.2 → 0.24.3 in the release workflow (Dependabot #35).
- **security (dependencies)** — helix-dashboard: `npm audit fix` plus an explicit `vite`/`vitest` bump
  (5.4.8/2.1.2 → 8.3.4/5.0.4, dev-only tooling, not shipped in the nginx image) clears the critical `tinypool`
  RCE-via-prototype-pollution finding and the high `vite`/`esbuild` dev-server finding; build, `vitest run`
  (347 tests) and `build-storybook` all still pass. One moderate `uuid` finding remains (would need downgrading
  `@storybook/addon-essentials` to 7.0.6, a regression) and is left for a future Storybook major bump.
- **security (dependencies)** — repo-wide `trivy fs --scanners vuln --severity HIGH,CRITICAL .` (the same scanner
  CI's `security-scan.yml` runs) is clean across every ecosystem;
  `helix-mcp-demo` has no `package.json`/dependencies (Node built-ins only), so nothing to scan there.

## v1.0.0-rc.7 (security hotfix)

- **security** — Nimbus JOSE + JWT is pinned to **10.10** (CVE-2025-53864 / GHSA-xwmg-2g98-w7v9). Nimbus before
  10.0.2 (and before 9.37.4 on the 9.x line) has no bound on JSON nesting in a JWT claim set, so an attacker-supplied
  token with deeply nested arrays or objects can exhaust the stack (denial of service). This affected rc.6 and earlier:
  Spring Authorization Server 1.5.8 brings in the vulnerable 9.47, which it and Spring Security use to decode JWTs (for
  example `private_key_jwt` client assertions). Boot 3.5 does not manage Nimbus, so the version is now pinned in
  `helix-iam-server/pom.xml` `dependencyManagement`; the build resolves a single Nimbus.
  `NimbusNestedJsonRegressionTest` checks that a claim set nested 10 000 levels deep is refused with a
  `ParseException` (9.47 accepted it).

## Next release (after `v1.0.0-rc.5`)

- **feature (experimental)** — HelixIAM can now act as an OpenID4VP *Verifier* for EU Digital Identity Wallets:
  users present a PID credential (SD-JWT VC and/or ISO mdoc) instead of, or alongside, a password. New package
  `io.helixiam.authorization.federation.wallet`, one admin-managed identity-provider connection per realm
  (protocol `eudi-wallet`), same-device redirect and cross-device QR flows, Token Status List revocation
  checking, and a subject rule of "administrative number, else an explicit account link" (a PID without one
  cannot create an account by itself). Pure Java — no Kotlin, no vendored EUDI reference libraries — on top of
  Nimbus JOSE+JWT (now pinned at **10.10**, see the CVE item below), Jackson CBOR, BouncyCastle and ZXing, all
  already on the classpath. Full operator guide: `docs/eudi-wallet.md`; threat model: `helix-iam-server/
  SECURITY-REVIEW.md` Appendix B; known gaps: `helix-iam-server/DEFERRED-SECURITY-WORK.md`. **Experimental** —
  not yet run against the OpenID Foundation conformance suite or a real wallet (see `docs/FEATURES.md` and
  `ROADMAP.md`).

- **behaviour (all connectors)** — A federated login gets a new session id: `FederatedLoginCompleter` rotates it when
  the login completes and `FlowController` when a post-broker step-up completes (OIDC, SAML, eID, wallet). On the
  `queue` (PostgreSQL) session store `QueueIndexedSessionRepository.save` now deletes the pre-rotation row, so the old
  cookie no longer works after the rotation.
- **behaviour (all connectors)** — ID tokens carry `acr`. `BrokeredIdentity` gained a typed `levelOfAssurance`; the eID
  SAML connector sets it from the assertion's `AuthnContextClassRef` (only a value on that scheme's ladder) and the
  wallet sets `http://eidas.europa.eu/LoA/high`. It is bound into the authorization code like `sid`/`auth_time` and put
  on the ID token (kept across refresh, never on access tokens). A provider attribute named `loa` is never used, so an
  upstream OIDC IdP cannot set it. Every login completion clears a previous login's value; a step-up holds it on the
  flow state until that flow completes.
- **behaviour (all connectors)** — The broker start turns any provider error (and an alias unknown in the realm) into
  `/login?error=federation` with a WARN log, instead of an error page.
- **behaviour (admin, all connectors)** — Console/admin-API identity providers are live in every realm:
  `helix.federation.store.enabled` defaults to `true` (it was `false`, so that boot never called AMQP, which is gone);
  the startup load covers every realm (`helix.federation.store.realm` is removed); an admin write refreshes only its
  realm; the registry keys stored providers by (realm, alias), so realms may share an alias such as `eudi-wallet`; the
  login page, broker, wallet endpoints and account console resolve providers for the request's realm only. A stored
  config whose secrets cannot be read is skipped by id instead of failing the realm's (or every realm's) load.
- **audit (wallet)** — A wallet login that steps up (MFA, risk step) is audited when the step ends:
  `WALLET_LOGIN_SUCCESS` for the signed-in user, or `WALLET_LOGIN_FAILURE`; previously it was never audited.

CodeQL opened 19 alerts on code added in rc.5. Twelve are fixed below; the seven false positives are explained in
`helix-iam-server/CODEQL-TRIAGE.md` ("rc.5 scan").

- **security** — Nimbus JOSE + JWT is pinned to **10.10** (CVE-2025-53864 / GHSA-xwmg-2g98-w7v9). Nimbus before
  10.0.2 (and before 9.37.4 on the 9.x line) has no bound on JSON nesting in a JWT claim set, so an attacker-supplied
  token with deeply nested arrays or objects can exhaust the stack (denial of service). **This also affects the
  already-released versions:** Spring Authorization Server 1.5.8 brings in the vulnerable 9.47, which it and Spring
  Security use to decode JWTs (for example `private_key_jwt` client assertions). Boot 3.5 does not manage Nimbus, so the
  version is now pinned in `helix-iam-server/pom.xml` `dependencyManagement`; the build resolves a single Nimbus.
  `NimbusNestedJsonRegressionTest` checks that a claim set nested 10 000 levels deep is refused with a
  `ParseException` (9.47 accepted it). The EUDI Wallet verifier also uses Nimbus directly to parse wallet JWTs.

- **security** — Identity-provider secrets are encrypted at rest and never returned. The OIDC `clientSecret`, the eID
  SP private keys (`spDecryptionPrivateKey`, `spSigningPrivateKey`), the LDAP bind password and the coming EUDI Wallet
  keys (`accessCertificatePrivateKey`, `subjectPepper`) were stored in plain text in `identity_provider.config_json`
  and returned as is by `GET /admin/realms/{realm}/identity-providers` (list and by alias). They now live in a new
  column `secret_json`, encrypted with `DB_ENCRYPTION` (Flyway `V75`, and `schema.sql`); existing secrets are moved
  out of `config_json` by Flyway `V75.1`, or at startup on the `schema.sql` path (idempotent). The API returns
  `"<key>Set": true|false` instead of the value. Secrets are write-only, like the messaging provider's
  `secret` / `clearSecret`: an absent or blank value keeps the stored one, a value replaces it, and
  `"clear<Key>": "true"` (e.g. `clearClientSecret`) removes it; a value together with its clear flag is a 400. The realm
  export masks every one of these keys (also `subjectPepper` and `bindPw`, which the key-name rule missed), and a
  re-import without them keeps the stored secrets. The console shows "Set" / "Not set" with Replace and sends a secret
  only when one is typed. The list of secret keys per protocol is `ProviderSecretKeys`.

- **security** — `79b5bf4` No state change on a `GET` (CodeQL #258, #259). Opening `/required-actions` sent the
  verification email; the email is now sent in the sign-in `POST` that holds the user, and "send again" stays a
  `POST`. Opening the link that confirms a changed email address (`/account/email/verify`) confirmed it at once, so a
  mail scanner that prefetches links confirmed it without the user. The link now opens
  a confirmation page, and its button confirms (a `POST` with the CSRF token), like the C3 `/verify-email` link.
- **security** — `d98a5e2` Linear-time checks (CodeQL #253, #254). Turning `data-button` links into buttons in HTML
  emails was quadratic in the body length on many unclosed links (a template or a user value could slow down every
  email); it is now a one-pass scan. The plausibility check on a new email address no longer uses a backtracking regex.
- **security** — `d01b9f4` Logs (CodeQL #260–#264). An unreadable `HELIX_BOOTSTRAP_CLIENT_SECRET_FILE` is reported
  without its path; the federated-login and session-store logs pass the user id, principal name and exception
  messages through `LogSafe.sanitize`.
- **security** — `22a2942` After registering or verifying an address, the user is sent back to the pending sign-in by
  path only, never by the saved request's scheme and host, and a path that starts with `//` is refused (CodeQL #255,
  hardening: the saved request always came from the user's own session on this server).
- **rc.6 item 1** — The account console no longer signs the user out on the `queue` (PostgreSQL) session store. Every
  console form that redirects (password change, a wrong recovery code, …) leaves flash attributes in the session, and
  Spring's `FlashMap` holds its target parameters in `LinkedMultiValueMap` (a `MultiValueMapAdapter`), which the
  store's deserialisation allowlist rejected. The whole session was then silently read back as empty, so the next
  page asked for a sign-in; Redis was not affected. The allowlist now names exactly those two
  `org.springframework.util` classes, and a session the store has to drop is logged (WARN) with the rejected class
  name only, never its contents. The account-console and sign-in browser tests (password + TOTP to the relying party,
  MFA gate, registration) now also run on the queue store in CI (a second surefire run); the whole browser package
  passes on it with no dropped session.
- **rc.6 item 7b** — The account console lists every browser the user is signed in with in the realm, not only the
  ones that signed in to an application: browser and system ("Firefox on Windows"), when it signed in, when it was last
  used, and which apps it signed in to, with this browser first and marked. Each other browser has its own "Sign out"
  (its apps' tokens are revoked with a back-channel logout and its browser session ends; audit event
  `ACCOUNT_SESSION_SIGN_OUT`); "Sign out everywhere else" now also ends the other browser sessions at once. It works
  on both session stores: a new table `browser_session` (Flyway `V71`, and `schema.sql`) records each browser sign-in
  by its `sid` with its current HTTP session and a short device name (never the raw `User-Agent`), and the list checks
  every row against the session store. Only the user's own sessions can be signed out; any other `sid` gets "That
  session is already signed out." A browser test with four browsers covers it on Redis and on the queue store.
- **rc.6 session list, UI review** — Each row now leads with the device in bold, with "Signed in … · Last used …" on
  one line and the "You're here" badge on this browser (plus a side accent on phones). Every per-row "Sign out" names
  its device for screen readers ("Sign out Firefox on Windows"). "Sign out everywhere else" is shown only when there is
  another session, and is styled as a destructive action; with one session the list says it is the only one. Account
  console buttons are at least 44 px tall on phones, and its forms no longer carry the CSRF field twice.

Items 3–7 of the rc.5 review status (`docs/superpowers/specs/2026-09-27-monthfold-open-issues.md`):

- **Item 3** — Every email has a plain-text part with its link and, for registration and reset, its code. The HTML
  emails were sent as HTML only, so a provider or app that shows the text part showed "Open this email in an email
  app that shows HTML". SMTP now sends `multipart/alternative`, and the HTTP email driver adds a `text` field to its
  payload. The account emails (registration, reset, and the global-SMTP verification link) build their text part in
  the user's language; realm templates derive it from the HTML (`Label: URL` for links). The unedited default
  templates (code, magic link, verify email, email change) are sent in Dutch to Dutch users, with the expiry
  (`{{ttl}}`) in Dutch too.

- **Item 4** — Emails name the realm by its display name. `{{realm}}` in the realm's message templates (and in SMS
  and push) was the realm id, so the verify-email subject read "for monthfold". It is now the organization in
  context, else the realm's display name, else the id; `{{realmId}}` keeps the id. The registration and reset emails
  no longer say "HelixIAM" for a realm without a display name; they use its id.

- **Item 5** — The Helm chart runs without Redis. `redis.host` is required only when `config.sessionStore` or the new
  `config.tokenStore` (`HELIX_TOKEN_STORE`, default `queue`) is `redis`; otherwise the chart sets no `REDIS_HOST`
  and the NetworkPolicy opens no Redis port, and an unknown store name fails the render. `HELIX_TOKEN_STORE` is now
  mapped to `helix.iam.token-store` (the env var alone bound to nothing, so `HELIX_TOKEN_STORE=redis` had no effect
  while the health check assumed Redis was in use). The chart README lists what uses Redis (only those two stores)
  and what stays per replica (rate limits, SAML replay cache, QR / push / transaction-signing state).
  `e2e/helm-template-check.sh` checks the renders; `STORE=queue e2e/image-boot-smoke.sh` and
  `NO_REDIS=1 e2e/monthfold/k3d-helm.sh` boot without any Redis (k3d: readiness UP, 38/38 checks, 6/6 tokens).

- **Item 6** — Error pages of the sign-in endpoints are themed. An unknown `client_id`, an unregistered
  `redirect_uri`, an authorization request without `client_id` or a bare `GET /connect/logout` showed Spring's plain
  "Whitelabel" page; any 4xx of a realm endpoint that a browser (an `Accept` with `text/html`) receives is now the
  realm's themed `protocol-error` page, in the user's language, with a message from a fixed set, the standard OAuth
  error code and a logged reference; nothing from the request is shown. API clients keep the JSON body. The OIDC
  front-channel logout page is themed as well and lost its inline style and script; its `frame-src` now allows the
  clients' front-channel logout origins, which the pages' `frame-src 'none'` used to block, so the iframes never
  loaded.

- **Item 6, UI/UX review** — Every error page has a way back to a page of the realm ("Back to sign in" or "Go to
  your account", never the request's `redirect_uri`), its own title, message and hint per kind (unknown client,
  unregistered return address, incomplete request, sign-out link, 404, 403) in English and Dutch, the reference small
  and monospace, and the OAuth code under "Technical details"; the card no longer adds paragraph margins. The
  front-channel logout page states its two-second redirect in a `role="status"` line and explains its Continue
  button. An RP-initiated logout without a `post_logout_redirect_uri` now ends on the realm's themed "You're signed
  out" page (`/realms/{realm}/signed-out`) instead of the plain-text 404 at the server root.

- **Direct sign-in** — Signing in at `/realms/{realm}/login` itself, with no application waiting, no longer gets
  stuck on the login page. It ended with a redirect to `sp.base.url` (the admin console, another origin), which the
  sign-in pages' CSP `form-action 'self'` blocked, so the browser stayed on the form (with or without the two-step
  code; after TOTP enrolment the user was sent to the admin console). A user of a realm other than master now lands on
  the realm's account console (`/realms/{realm}/account`), after the password, the code, enrolment, the flow engine,
  a magic link or a federated sign-in. In master, the operator still lands on the admin console, and the master
  realm's sign-in pages (login, two-step, flow, required actions) now allow `sp.base.url`'s origin in `form-action`.
  The admin console's OIDC sign-in (`helix-console`) is unchanged.

- **Item 7a** — The theme validator checks muted text: `inkMuted` on `surface` and on `surfaceRaised`, light and
  dark, at least 4.5:1 (`contrast.inkMutedOnSurface.*`, `contrast.inkMutedOnSurfaceRaised.*`, same message format).
  So that themes which leave `inkMuted` unset keep passing, the palette adjusts HelixIAM's muted ink to the theme's
  surfaces when needed, and a derived dark `inkMuted` now also reaches 4.5:1 on the dark raised surface.

- **Email delivery, stage 1** — `62cd77a` Email goes through a transport SPI (`EmailTransport`, package
  `io.helixiam.authorization.messaging.email`) with one entry point, `EmailDelivery.deliver(realm, message)`: the
  realm's provider, else the global default, and a classified `DeliveryResult` (`ACCEPTED`, `QUEUED`,
  `PERMANENT_FAILURE`, `TRANSIENT_FAILURE`, a reason, the provider's message id and a diagnostic that never holds a
  secret or the body). Each email has a message id that stays the same across attempts (the SMTP `Message-ID`) and
  always a plain-text part with its links; the Cloudflare driver sends both parts. The old `EmailDriver` interface
  still works for a custom driver (deprecated).
  - **SMTP** — new `tlsMode`: `STARTTLS_REQUIRED` (default), `STARTTLS_OPTIONAL`, `IMPLICIT` (SMTPS, port 465 by
    default) and `NONE`, which is refused unless the server runs with the `dev` profile. The boolean `starttls` is
    deprecated: `true` means `STARTTLS_REQUIRED` (before, STARTTLS was used only when offered, so a server without it
    now fails instead of receiving the email in plain text) and `false` means `STARTTLS_OPTIONAL`. Certificates and
    the host name are always verified; `caBundle` adds CA certificates for a private relay. Also `connectTimeoutMs`,
    `readTimeoutMs` and `ehloName`. An SMTP 5xx reply is a permanent failure (on a recipient, a bounce); a 4xx reply,
    a connection, timeout or TLS error is transient.
  - **Cloudflare Email Service** — driver `CLOUDFLARE` (`accountId`, the API token as `secret`, optional `baseUrl`,
    https outside the dev profile, timeouts and `caBundle`) over HTTPS, through the egress guard, with the spec's
    classification. A refused token (401/403) counts in `helix_email_provider_auth_failures_total{realm,driver}`,
    logs a WARN ("ACTION NEEDED") and emits an `EMAIL_PROVIDER_AUTH_FAILED` audit event. Every attempt counts in
    `helix_email_send_total{realm,driver,result}`.
  - **Admin API** — `PUT /admin/realms/{realm}/messaging/providers` validates before saving (400
    `{message, fieldErrors}`): a known channel and driver (email: `SMTP`, `CLOUDFLARE`, `HTTP`, `LOG`), the from
    address, and each driver's required settings. A credential typed into `config` (`password`, `apiToken`) is
    moved to the encrypted, write-only `secret`. `POST …/messaging/providers/EMAIL/test` now answers with `result`,
    `reason`, `diagnostic` and `providerMessageId` next to `sent` and `message`.
  - **Global default** — `helix.notification.email.driver` (`smtp`, `cloudflare`, `log`) and `.from-address` /
    `.from-name`; `helix.notification.cloudflare.*` (`account-id`, `api-token`, `api-token-file`, `base-url`, timeouts,
    `ca-bundle-file`); for SMTP also `password-file`, `tls-mode`, timeouts, `ehlo-name` and `ca-bundle-file`. Secret
    files are read at every send, and realm providers are read at every send, so a rotated secret needs no restart.
  - **Helm** — `8cc0116` optional `email.*` values; the credentials are keys of the existing Secret, mounted as files.
  - Retries, bounce marking, the per-realm send rate cap, the remaining metrics and `docs/EMAIL.md` follow in stage 2.
- **security** — `3892c16` Password-reset codes expired never: a reset link from any time in the past still set a new
  password, and a code already used, expired or unknown still "succeeded" (the reset page redirected as if it had
  worked). Reset codes now expire after `helix.notification.reset-password.code-ttl` (default 1 hour) and the
  sign-up verification code after `helix.notification.signup.code-ttl` (default 24 hours); both are single-use,
  consumed atomically (`DELETE`, so two concurrent submits cannot both use one). A new request replaces an expired
  code. Opening an expired, used or unknown reset link shows the themed error "This link has expired or was already
  used" with a link to request a new one, and submitting it changes nothing. The code's expiry is stored
  (`notification_code.expires_at`, Flyway `V73` and `schema.sql`; codes issued before it expire their TTL after
  creation) and becomes the email's `expiresAt`, so a reset email is never retried after its code died. The other
  emailed codes and links were checked and already expire and work once: the email OTP (5 minutes, attempt-limited),
  the magic link, the verification link and the email-change link.
- **security** — The password-reset email went to whatever was typed on the reset page, not to the account's address:
  typing a username sent the link to that username as if it were an address, and an account whose username looks like
  an address (for example `old@example.org` with the stored email `new@example.com`) had its reset link sent to the
  typed address, possibly someone else's mailbox. The typed value now only finds the account in the realm (username or
  email); the link goes only to the account's stored email address, and an account without one gets nothing. The
  answer is the same for an existing account, an unknown one and one without an address; both lookups always run and
  the code is issued and the email sent off the request thread, so the timing does not tell them apart either. The
  link goes to the stored address whether or not it is verified or has bounced, as most identity providers do: it is
  the account's only address and the user needs a way back in.
- **security** — Emailed reset and sign-up codes are stored hashed: `notification_code.code` holds the hex
  SHA-256 of the code, like the magic-link tokens, and the plain code exists only in the email. Lookup and the atomic
  single-use consume go by the hash. The codes are random UUIDs (122 bits), so a plain hash is enough (no salt or slow
  KDF), and a database dump no longer hands out working reset links. Every request now issues a new code (a pending
  one cannot be re-sent, as its plain value is not kept); the new link replaces the older one.
  **Upgrade note:** Flyway `V74` (and `schema.sql`, idempotently) hashes the codes pending at the upgrade in place, so
  links already sent keep working until they expire; nobody has to request a new one.
- **Test a chosen provider** — `492d221` `POST /admin/realms/{r}/messaging/providers/{channel}/test` takes an optional
  `driver`: it tests the realm's provider with that driver even when it is disabled (to check it before switching),
  and without it the active provider as before. The answer now also names the tested `driver` (EMAIL). An unknown
  driver is a 400 with `fieldErrors.driver`; a known one the realm has not configured answers `sent: false`.
- **One active email provider per realm** — `059e73d` Saving an enabled `EMAIL` provider switches the realm to it:
  the realm's other email providers are disabled in the same transaction (serialised per realm), and logged. Saving a
  disabled provider changes no other, so a new provider can be prepared and tested before the switch. Delivery never
  has to choose between enabled providers any more. Realms that already had several enabled are repaired at startup:
  the most recently saved stays enabled, the others are disabled with a WARN line each.
- **Clear a provider secret** — `0bd926a` `PUT /admin/realms/{r}/messaging/providers` takes `"clearSecret": true` to
  remove the stored secret without deleting the provider. An absent, null or blank `secret` still keeps it, and a
  value replaces it; `clearSecret` with a `secret` is a 400 (`fieldErrors.clearSecret`). The Cloudflare API token is
  now required only to enable the provider (a disabled one may have none).
- **Helm** — `b2009bc` `email.retry.*` (`enabled`, `delays`, `maxAge`, `jitter`, `pollInterval`, `batchSize`,
  `lease`), `email.rateLimit.realmPerMinute` / `.globalPerMinute` and `email.codes.resetPasswordTtl` / `.signupTtl`;
  empty keeps the server default, `0` and `false` are passed through. `e2e/helm-template-check.sh` checks each.
- **Email delivery, stage 2** — `1e3b2c4` Callers send through `EmailOutbox`, around `EmailDelivery`. See
  `docs/EMAIL.md`.
  - **Retries** — The first attempt stays synchronous (the flow and the admin test endpoint get the real result). A
    `TRANSIENT_FAILURE` is stored in a new table `email_retry` (Flyway `V72`, and `schema.sql`) and sent again after
    30 s, 2 min, 10 min and 30 min (±20 % jitter), never later than 1 hour after the first attempt, with the same
    message id; a restart or another replica picks it up. The rendered message (recipient, subject, both parts) is
    stored encrypted with `DB_ENCRYPTION` and the row is deleted when the email is finished. Every replica polls;
    rows are claimed with `SELECT … FOR UPDATE SKIP LOCKED` and a lease, so two replicas never send the same retry.
    Settings `helix.notification.email.retry.*` (`enabled`, `delays`, `max-age`, `jitter`, `poll-interval`,
    `batch-size`, `lease`). A permanent failure, `NO_PROVIDER`, the admin test email and a rate-capped email are never
    retried.
  - **No dead links** — `EmailMessage` has an `expiresAt`: the one-time code (5 minutes), the magic link, the
    verification and email-change links (their lifetimes) and the password-reset email (1 hour) are never retried at
    or after it. `MessagingService.sendEmail(…, Duration validFor)` sets it.
  - **Bounces** — A permanent bounce marks the address on the realm's users who have it (`user_credentials`
    `email_bounced_at`, `email_bounced_address`; `V72`); the admin user API shows `emailBounced` and `emailBouncedAt`
    (epoch millis). The mark goes when the address changes and is cleared when it is verified again (verification or
    email-change link, signup code, an admin setting `emailVerified` to `true`). Counted in
    `helix_email_bounces_total{realm}` and audited (`EMAIL_BOUNCED`).
  - **Send rate cap** — per realm (`helix.notification.email.rate-limit.realm-per-minute`, default 120, or the realm
    provider's `config.sendLimitPerMinute`) and per server (`…global-per-minute`, default 600), per replica. An email
    over a cap is refused with `TRANSIENT_FAILURE / RATE_CAPPED` (new reason), not queued, counted in
    `helix_email_rate_capped_total{realm,scope}` and audited (`EMAIL_SEND_RATE_CAPPED`, once per realm and minute).
  - **Observability** — new `helix_email_send_duration_seconds{realm,driver,result}` (histogram),
    `helix_email_retry_total{realm,outcome}` and the gauge `helix_email_retry_queued`; audit event `EMAIL_SEND_FAILED`
    (permanent failures, retries given up or expired). No audit event or log line holds the body, subject, a code, a
    link or a secret.
  - **Idempotency** — the HTTP driver sends the message id as `Idempotency-Key`; SMTP already sends it as
    `Message-ID`. Cloudflare takes no idempotency key: delivery through it is at least once (documented).
  - **Realm import** validates messaging providers like the admin API: an invalid provider is not saved and the import
    result reports it with the same field messages; a credential typed into `config` is moved to the secret.
  - **Docs** — new `docs/EMAIL.md`: choosing a transport and hosting port blocks, SPF/DKIM/DMARC alignment, Cloudflare
    Email Service setup, SMTPS versus STARTTLS (and the STARTTLS-required behaviour change), every setting and the
    per-realm API with `curl` examples, retries, bounces, the rate cap, metrics, and troubleshooting by result code.

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
