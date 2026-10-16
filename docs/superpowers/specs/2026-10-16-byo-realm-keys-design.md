# Bring your own realm signing keys and certificates — design

Date: 2026-10-16. Base: `v1.0.0-rc.11`. Branch: `feat/byo-realm-keys`.

Customers can change the keys and certificates their realm signs with, for OIDC/JWS and SAML: import a key with a
CA-issued (or self-signed) certificate chain, or have HelixIAM generate a key and a PKCS#10 CSR (the private key never
leaves the server), stage the new key (published, not signing), and activate it when relying parties have picked it up.
The realm can sign with RS256 (RSA) or ES256 (EC P-256).

No human was available; every decision below was made by the implementer and is final for this change.

## Starting point (rc.11)

* `realm_key` rows (`RealmKey`), private key Base64 PKCS#8 encrypted with `AttributeEncryption` (`DB_ENCRYPTION`).
  `algorithm` holds the JCA key type `RSA`. Statuses ACTIVE / ROTATED / RETIRED.
* `KeyMaterialService` turns rows into Java keys; `ServiceProviderLocalAdapter` (in-process since the RabbitMQ strip)
  hands them to `RealmJwkSource` (JWKS + signing, 30 s cache) and `RealmSamlCredentialSource` (SAML, deterministic
  self-signed certificate around the active public key, 30 s cache).
* The JWK `kid` is derived from the RSA modulus (`base64(sha256(modulus))`), not the row id. Each RSA key is published
  twice: RS256 (`kid`) and PS256 (`kid-ps256`).
* Admin API `GET /keys`, `POST /keys/rotate`, `DELETE /keys/{keyId}`; console page "Realm keys".

## Decisions

### Data model (Flyway V86 + `schema.sql`)

| # | Decision |
|---|---|
| D1 | `realm_key.algorithm` now holds the **JWS algorithm** (`RS256` or `ES256`). V86 rewrites `RSA` → `RS256` and changes the column default to `RS256`. Code still reads a legacy `RSA` as RS256 (an rc.11 replica can still write one during a rolling upgrade). |
| D2 | New nullable columns: `certificate_chain_pem` (text, leaf first), `csr_pem` (text, the last CSR, public), `activated_date` (timestamp), `expiry_warned_on` (date, dedupes the daily expiry warning across replicas). New column `source` varchar(20) NOT NULL DEFAULT `GENERATED` (`GENERATED`, `IMPORTED`, `CSR`). Existing rows: RS256, no chain, `GENERATED`, status unchanged. |
| D3 | New status `PENDING`. No DB constraint on statuses (none existed). No partial unique index on "one ACTIVE per realm": existing databases may already hold duplicates from an old race and the migration must not fail; activation instead demotes **every** ACTIVE row of the realm in the same transaction. |
| D4 | Certificate facts (subject, issuer, validity, fingerprint) are derived from the stored chain when read, not stored twice. |

### Validation (import and attach)

| # | Decision |
|---|---|
| D5 | Private key PEM: PKCS#8 (`BEGIN PRIVATE KEY`), PKCS#1 (`BEGIN RSA PRIVATE KEY`), SEC1 (`BEGIN EC PRIVATE KEY`). Encrypted PEM is refused (decrypt it first). RSA must be ≥ 2048 bits; EC must name P-256 (checked on the encoded curve OID, so secp256k1/brainpool/explicit parameters are refused). Anything else → 400 on `privateKeyPem`. |
| D6 | Chain PEM: only `CERTIFICATE` blocks, at least one, leaf first; each certificate issued by the next (DN **and** signature). The leaf's public key must match the private key (sign/verify probe). **Every** certificate of the chain must be inside its validity window now (an expired intermediate breaks the chain for every SP, so it is refused too). If the leaf has a keyUsage extension it must include digitalSignature. A single self-signed certificate is allowed. → 400 on `certificateChainPem`. |
| D7 | The stored chain is what the admin sent (validated). `x5c` publishes it **without a trailing self-signed root** when the chain has more than one certificate (RFC 7517 allows it, but the anchor adds nothing a verifier can trust). |
| D8 | A public key that already exists in `realm_key` (any realm, any status) cannot be imported again: a key belongs to one realm, and the JWK `kid` is derived from the key, so a shared key would make two realms' JWKS indistinguishable. → 400 `privateKeyPem`. |
| D9 | Import and CSR need `DB_ENCRYPTION` outside the `dev` profile (same rule as the wallet verifier keys); refused with 400 on `privateKeyPem` / `algorithm`. Generated keys (`/rotate`) keep today's behaviour. |
| D10 | Errors are `400 {message, fieldErrors}` through the existing `ProviderValidationException` + `AdminValidationAdvice`. Messages never contain key or PEM content. |

### Lifecycle and API

| # | Decision |
|---|---|
| D11 | `POST /admin/realms/{realm}/keys/import` `{privateKeyPem, certificateChainPem}` → 201, key PENDING, `source=IMPORTED`. |
| D12 | `POST /keys/csr` `{algorithm: RS256\|ES256, subject, dnsNames?}` → 201 `{key, csrPem}`. Generates **RSA-2048** (same as generated keys, widest SP support) or EC P-256, stores it PENDING with `source=CSR`, and returns a PKCS#10 CSR signed with SHA256withRSA / SHA256withECDSA, carrying the subject DN, a keyUsage=digitalSignature extension request and, when given, a subjectAltName with the DNS names. `subject` must parse as an RFC 4514 DN with at least one attribute. `GET /keys/{keyId}/csr` returns the stored CSR again. |
| D13 | `PUT /keys/{keyId}/certificate` `{certificateChainPem}` → 200. Allowed for **PENDING** and **ACTIVE** keys (renewing the certificate of the active key is a real need and does not change tokens; SAML metadata changes immediately — documented). ROTATED/RETIRED → 409. The leaf must match the key (D6). |
| D14 | `POST /keys/{keyId}/activate` → 200: only a PENDING key; the realm's ACTIVE key(s) become ROTATED (still published) in the same transaction. Not PENDING → 409. |
| D15 | `POST /keys/rotate` with an optional body `{algorithm}` (default RS256) generates and activates at once, as today. |
| D16 | `DELETE /keys/{keyId}` retires. The ACTIVE key → **409** (it is the only key that signs). A PENDING key may be retired (discarding a staged key). |
| D17 | Every key-id route looks the key up **in the path realm**; a key of another realm is 404 (key ids are visible in the console of that other realm only, and JWKS kids are public anyway). |
| D18 | Caches: after every change the service publishes a `RealmKeysChangedEvent`; `RealmJwkSource` and `RealmSamlCredentialSource` drop that realm's cache entry. Other replicas still refresh within the 30 s TTL — harmless, because a key is published while PENDING long before it signs. |
| D19 | A key that has never been activated has no `rotatedAt`; `activatedAt` is set on activation (and on generate-active). |

### Publishing

| # | Decision |
|---|---|
| D20 | JWKS publishes ACTIVE + PENDING + ROTATED. Only the ACTIVE JWK carries the private part internally (so only it can be selected for signing); `/oauth2/jwks` serialises public parts only. |
| D21 | Every JWK has `kid`, `alg`, `use: sig`. Keys with a chain add `x5c` (standard Base64 DER, per RFC 7517 §4.7) and `x5t#S256` (base64url SHA-256 of the leaf DER). |
| D22 | `kid`: RSA keys keep today's modulus-derived kid (tokens issued by rc.11 keep verifying) and the PS256 twin `kid-ps256`. EC keys use the RFC 7638 JWK thumbprint (SHA-256, base64url). The console shows the kid next to the key so admins can match it to tokens. |
| D23 | SAML signs with the ACTIVE key and publishes its **leaf certificate** when it has a chain; otherwise the deterministic self-signed certificate of today (signed SHA256withRSA, or SHA256withECDSA for EC). |
| D24 | **PENDING SAML decision:** a PENDING key without a certificate is published in SAML metadata with the same deterministic self-signed fallback certificate. It is therefore never "unpublishable", and an SP that re-reads metadata can roll over to it either way. A PENDING key with a chain is published with its leaf. |
| D25 | Metadata lists `<KeyDescriptor use="signing">` for ACTIVE first, then PENDING, then ROTATED (each once). `<KeyDescriptor use="encryption">` carries the ACTIVE certificate only when it is RSA (SPs encrypt to the IdP with RSA-OAEP; there is no EC key transport in use). |
| D26 | With an EC ACTIVE key, assertions, responses, LogoutRequests and LogoutResponses are signed with `ecdsa-sha256`, whatever RSA algorithm an SP option asks for. Console and docs warn that many SPs only accept RSA. |

### ES256 and token signing

| # | Decision |
|---|---|
| D27 | The ACTIVE key decides the JWS `alg` of everything the realm signs. One decorator, `RealmAlgorithmJwtEncoder`, wraps the single `JwtEncoder` bean (`helixJwtEncoder`) that every signing path uses: SAS `JwtGenerator` (ID tokens, JWT access tokens), back-channel `logout_token`s, RFC 8693 delegation tokens, workload-identity tokens and JARM responses. If the requested `alg` does not fit the ACTIVE key type (RS*/PS* need RSA, ES256 needs EC) it is replaced by the ACTIVE key's algorithm. A client that asked for PS256 on an RSA realm still gets PS256. |
| D28 | Consequence (documented): a client that registered `id_token_signed_response_alg=RS256` gets ES256 ID tokens once the realm activates an EC key; SAS stores RS256 as every client's default, so "explicitly registered" cannot be told apart from the default. |
| D29 | Wallet verifier keys (`verifier_signing_key`, ES256 request objects) are a different key type and are not touched. FCM/APNs push JWTs use provider credentials and are not realm keys. |
| D30 | Discovery `id_token_signing_alg_values_supported` is computed per realm from the published keys: RSA → `RS256`, `PS256`; EC → `ES256`; the ACTIVE key's algorithm first. `dpop_signing_alg_values_supported` is about client keys and is unchanged. |
| D31 | Verifiers inside the product: SAS's own decoder (`OAuth2AuthorizationServerConfiguration.jwtDecoder`, used by delegation) accepts the RSA and EC families. The MCP demo verifier only accepted RS256 and fell back to the first JWK — fixed to accept RS256/PS256/ES256, require a kid match and refetch the JWKS on an unknown kid. The sandbox RP (openid-client 6) defaults to RS256 — it now takes the ID-token algorithm from discovery; its SAML SP accepts every signing certificate in the metadata, but node-saml's xml-crypto has no ECDSA support: documented as RSA-only. The console is a browser client of the admin session and verifies no tokens. |

### Certificate expiry

| # | Decision |
|---|---|
| D32 | Import and attach refuse expired (or not yet valid) certificates (D6). |
| D33 | `RealmKeyExpiryMonitor` scans ACTIVE and PENDING keys with a chain at start-up (+1 min) and every 6 h. A leaf that expires within 30 days (or has expired) raises one audit event per key per UTC day — `REALM_KEY_CERTIFICATE_EXPIRING` or `REALM_KEY_CERTIFICATE_EXPIRED` (category ADMIN, actor `system`, detail keyId/algorithm/fingerprint/notAfter) — and a WARN log. The day is claimed with a conditional `UPDATE … SET expiry_warned_on = today WHERE expiry_warned_on IS NULL OR expiry_warned_on < today`, so with several replicas only one warns. `helix.keys.expiry-check.enabled=false` switches the scan off. |
| D34 | **Expired ACTIVE certificate:** the realm keeps signing. JWS validity does not depend on the certificate, and stopping would take every login down. The WARN/audit repeats daily, the console shows a red "Expired" chip and a banner, and the health detail says so. SAML SPs that check certificate validity will reject assertions — the docs say so. |
| D35 | A `realmSigningKeys` health indicator reports **UP always**, with `expiringCertificates` / `expiredCertificates` counts from the last scan as details. It is added to the readiness group so operators see it there; it can never make readiness fail. |

### Audit

| # | Decision |
|---|---|
| D36 | `AuditEventMapper` maps `/keys` writes: `REALM_KEY_IMPORT`, `REALM_KEY_CSR`, `REALM_KEY_ROTATE`, `REALM_KEY_CERTIFICATE_ATTACH`, `REALM_KEY_ACTIVATE`, `REALM_KEY_RETIRE`; resource type `realm-key`. The controller attaches detail `keyId`, `algorithm`, `fingerprint` (SHA-256 of the leaf certificate DER, or of the public key SPKI when there is no certificate) — never key material. For `import`/`csr`/`rotate` the resource id is the new key id from the detail. |

### Export, upgrade, limits

| # | Decision |
|---|---|
| D37 | Realm export never contained keys, and still does not (no private keys, and no certificates either, since a certificate without its key is useless on import). An imported realm generates a fresh key; docs say to re-import your key and certificate on the target. |
| D38 | Rolling upgrade: rc.11 replicas ignore PENDING rows and read the `algorithm` column not at all, so RSA keys (generated, imported or CSR) work on both versions. An rc.11 replica cannot load an **EC** ACTIVE key: activate ES256 keys only once every replica runs this release (documented in the upgrade note). |
| D39 | Still unsupported (documented): HSM/KMS-held keys, scheduled automatic rotation, ACME, per-client signing keys, algorithms beyond RS256/PS256/ES256, encrypted private-key PEM. |

### Console

| # | Decision |
|---|---|
| D40 | Realm keys page: table (desktop) and cards (mobile) with a human label (certificate CN, else "RS256 key from 16 Oct 2026") — never the UUID; key id and kid only in a muted technical line. Columns: key, status chip (Pending / Active / Retained = ROTATED / Retired), algorithm, certificate subject/issuer, expiry with a warning chip under 30 days and a danger chip when expired, SHA-256 fingerprint. |
| D41 | Actions: "Import key and certificate" (two PEM textareas), "Create CSR" (algorithm, subject, DNS names; then copy/download the CSR), "Upload signed certificate" (PENDING/ACTIVE rows), "Activate" (PENDING rows, confirmation explaining the effect and the SAML note for SPs that pin certificates; extra warning for EC), "Rotate (generate)" (algorithm choice), "Retire" (non-ACTIVE rows). |
| D42 | Each form's validation is a pure function in `pages/realmKeys.ts` (TDD, `realmKeys.test.ts`): required fields, PEM block shape, DN shape, DNS-name shape. Server `fieldErrors` are shown inline on the matching field. EN + NL strings; zero inline styles. |

## Revision 1 — security review and UI review (2026-10-16)

The first reviews changed these decisions. Where a decision above conflicts with this section, this section wins.

| # | Decision |
|---|---|
| R1 | **Key writes need `realm-admin`** (`/keys/**` POST/PUT/DELETE); reads keep `manage-realm`. Importing or activating a key is the power to mint any realm token, admin service-account tokens included. The controller checks it too (`AdminAuthorizationManager.permits`), and `GET /keys/access` tells the console whether to show write actions. |
| R2 | **Admin authorization on the decoded path** (found while reviewing; predates this branch, recorded as H4 in `helix-iam-server/SECURITY-REVIEW.md`): the permission resolver read the raw URI while Spring MVC routes on the decoded one (`k%65ys`). Now: `AdminPathEncodingFilter` refuses `%` in the realm/route segments of `/admin` paths (deeper id segments such as SAML entity ids may stay encoded — they never decide the permission) and `%25` anywhere; the resolver reads the decoded, `;`-free path and matches segments exactly; unknown route groups fail closed to `realm-admin` (the groups that used the old `manage-realm` default are listed explicitly). |
| R3 | **One ACTIVE key per family, RS256 always** (replaces D14/D16/D27/D28/D30): every realm keeps one ACTIVE RSA key; at most one ACTIVE EC key may sit beside it and can only be activated while an RSA key is active (409 naming the reason). Activation and rotation demote only the same family. The ACTIVE RSA key cannot be retired; the ACTIVE EC key can, unless the signing settings choose ES256 (409). |
| R4 | **Algorithm per token** (replaces D27/D28): ID tokens use the client's `id_token_signed_response_alg` (default RS256), refused at client create/update (400 on `idTokenSignatureAlg`) when the realm has no ACTIVE key for it, and falling back to RS256 with a WARN at issue time. Access, logout, delegation and workload-identity tokens and JARM use the realm's `signing.defaultAlg` (RS256 default) through the `RealmAlgorithmJwtEncoder.REALM_DEFAULT` marker. No per-client override for those (not trivial; deferred). |
| R5 | **Signing settings** live in a new optional table `realm_signing_settings` (`default_alg`, `saml_alg`; V86 + `schema.sql`), not in the positional `RealmSettingsDto`, exposed as `GET/PUT /admin/realms/{realm}/settings/signing` and the console's Realm settings → Tokens → Signing section. Choosing ES256 needs an ACTIVE EC key. Not part of realm export yet (documented). |
| R6 | **Discovery** advertises exactly the ACTIVE keys' algorithms, RS256 first (replaces D30; PENDING and ROTATED are excluded). |
| R7 | **SAML** signs with the ACTIVE RSA key unless `samlAlg=ES256` and an EC key is active (replaces D23/D26). The encryption KeyDescriptor appears only for an RSA certificate whose keyUsage allows keyEncipherment or has none (refines D25). |
| R8 | **Serialised transitions**: activate, rotate, retire, attach, import, CSR and the first-use generation run in one transaction holding `pg_advisory_xact_lock(hashtextextended('helix.realm_key:'||realm, 0))` (PostgreSQL is the only supported database, both for Flyway and sql-init). Backstop: if the published set ever holds two ACTIVE keys of one family, the newest by activation signs, the other is published as verification-only, an ERROR is logged and `REALM_KEY_DUPLICATE_ACTIVE` audited once — signing never fails. |
| R9 | **Minimum staging time** `helix.keys.min-staging` (PT5M): activation before it is `409 {"error":"staging"}` unless `?force=true`, audited `forced=true`. `POST /rotate` stays immediate (no staging), documented. Views carry `activatableAt`. |
| R10 | **The encoder signs against one key-set snapshot** per token (`RealmJwkSource.snapshot()` + a fixed source), so a cache eviction mid-encode cannot fail a request. |
| R11 | **Stricter imports**: one PEM object and nothing else; RSA 2048–4096 bits with an odd exponent ≥ 65537 and ≤ 32 bits; the leaf must not be CA:true; chain certificates 2..n must be CA:true (and keyCertSign if keyUsage is present). CSR subjects allow CN, O, OU, C, L, ST, emailAddress, SERIALNUMBER, DC, UID only, values are built as typed ASN.1 strings (UTF8String; PrintableString for C/SERIALNUMBER; IA5String for emailAddress/DC), so no `#hex` value ever becomes raw DER. |
| R12 | **Unique public key**: a unique index on `realm_key.public_key` (V86 + `schema.sql`) backs D8. |
| R13 | **Console**: read-only Realm keys page without realm-admin; activate dialog states the key's current state, warns about an expired certificate and the staging time with a confirmed force option; a separate retire message for pending keys; short fingerprint with copy; kit-wide Modal focus management (focus in, Tab trap, focus back), wrapping page-header actions, RowMenu flips above near the viewport bottom. |

## Revision 2 — H5 (admin escalation, present in rc.11)

| # | Decision |
|---|---|
| R14 | **No admin grants admin permissions they do not hold** (`AdminGrantGuard`): assigning or removing a role (user, group role, group membership, service-account realm role, SCIM, realm import) needs the role's admin permissions (its RBAC grants; `realm-admin` for the role named `admin`) to be the caller's own; admin grants need `realm-admin`; a role with admin permissions cannot be the default role (existing ones are reported at start-up, not changed, and no longer handed to new users). |
| R15 | **No admin acts on a more privileged principal** (`PrivilegedPrincipalGuard`, in `PrivilegedPrincipalInterceptor` on `/admin/realms/{r}/users/{id}/**` and `/clients/{id}/**` and in `UserAdminService`, `ClientAdminService`, `ImpersonationService`): password, credentials, impersonation, profile, status, required actions, GDPR erasure and deletion of users; secret reveal/set/rotate, update and deletion of clients (by their service account's realm roles). Session revocation stays allowed. Secret reveal needs `manage-clients`. IdP logins never auto-link by e-mail to an administrator. A `CLIENT` service-account role needs its client. |
| R16 | **The acting principal is declared, never inferred from the URI** (`AdminActor`): `AdminAuthorizationManager` declares `ADMIN` (with the authenticated principal) on the request where it authorises an admin route (`DEV_OPEN` in dev-open mode); SCIM and DCR declare `UNPRIVILEGED` after authenticating their caller; self-service declares `SELF` (may act on that one user only); internal work runs in `AdminActor.asSystem(why, …)`. Without an actor, any action that confers or touches admin permissions is refused. |
| R17 | **Target privilege across realms.** Users are per realm (`UserCredentials.realmId`), but one user can be a member of several realms through `tenant_user` links — a realm's creator is linked to it — and session authorities are the `<role>_<realm>` names of all its roles in every realm. Master admins administer every realm through the `admin_master` authority (`RealmAdminAuthorities.isMasterAdmin`); there is no other cross-realm grant. The guard evaluates a target's authorities exactly like `AdminAuthorizationManager` (`AdminGrantGuard.permissionsOfAuthorities`: `admin_master` or `admin_<realm>` is `realm-admin`, otherwise the realm's RBAC grants), unioned with role-by-role grants and group roles. |
| R18 | **Publisher/subscriber split.** Since the RabbitMQ strip every admin publisher is an in-process adapter (`*LocalAdapter`), called on the request thread; no admin call crosses a queue. The guards enforce in the services on that thread, with the request's declared actor; work handed to another thread has no actor and is refused unless it runs in `asSystem`. |

**`AdminActor.asSystem()` callers** (each reviewed):

| Caller | Why it is internal |
|---|---|
| `BootstrapServiceAccountService` | The operator-configured bootstrap service account receives the `admin` role at start-up. |
| `RealmConfigFolderLoader` | Realm-config files from the operator's folder are applied at start-up. |
| `WalletLoginCompleter` | A wallet JIT login that lost a race removes the account it created a moment before. |

Self-service runs as `SELF` (account profile update and account deletion, the UPDATE_PASSWORD required action), SCIM and DCR as `UNPRIVILEGED`.

## Revision 3 — sign-in surface inventory (security review round 6, 2026-10-16)

Instead of fixing escalations one at a time, every admin write endpoint, every realm-import slice and every SCIM and
DCR write was listed and classified by what it can reach:

- **a** — the credentials, identity, links or status of a privileged principal;
- **b** — how a privileged principal signs in, or which tokens it gets: the sign-in clients and their Applications,
  the flows bound to them, the realm's browser flow, identity providers that administrators are linked to, mappers and
  resources of the sign-in clients, the realm's MFA and sign-in policy, and the channels that deliver codes and links;
- **c** — what trusts a privileged principal: workload identity, agents, signing keys, identity-provider issuers and
  JWKS, trusted lists;
- **d** — the roles or permissions that tokens carry.

**Default rule:** anything in a, b, c or d needs the subset rule (`requireMayGrant` / `requireMayActOnUser` /
`requireMayActOnClient`) or realm-admin. The check sits in the **service** layer, so the REST API and realm import go
through the same code. A row without a guard gives its reason.

| # | Decision |
|---|---|
| R19 | **Identity providers that administrators sign in through.** Changing (issuer, endpoints, JWKS, client id and secret, mappers, trust settings, enabled, and alias, since a new alias with old links counts) or deleting an identity provider needs the admin permissions of every user of the realm linked to it. `PrivilegedPrincipalGuard.requireMayChangeIdentityProvider` runs in `IdentityProviderConfigService.saveOrUpdate/delete`. Changing a trusted list needs the same for every provider that uses it (`TrustedListService.update`). Deleting a list is already refused while a provider uses it. |
| R20 | **Link provenance.** `federated_link.created_via` (V86 + `schema.sql`) records how a link was made: `JIT` (the sign-in created the account), `AUTO` (matched by a verified e-mail address), `SELF` (account console) or `WALLET` (the account console's wallet linking). The broker signs an administrator in through an existing link only when it is `JIT`, `SELF` or `WALLET`. An `AUTO` link, or one of unknown origin, is refused with a WARN, so an identity linked by e-mail before its owner became an administrator cannot sign in as that administrator. No admin API creates links. **Backfill:** links of a wallet provider are `WALLET`; a link made within 120 seconds of its user is `JIT`; everything else is `AUTO`. An administrator who used an `AUTO` link signs in with local credentials (or a wallet) instead. |
| R21 | **Applications of sign-in clients.** Changing the subject claim, flow or enabled flag of an Application that holds `helix-console` or `helix-cli` needs realm-admin. Its display name and description do not. Deleting such an Application needs realm-admin, and deleting any Application needs `requireMayActOnClient` for each child client it soft-deletes (`ApplicationConfigService`). |
| R22 | **Built-in sign-in client ids.** Creating a client named `helix-console` or `helix-cli` needs realm-admin, or the system bootstrap (`ClientAdminService.create`). `helix-cli` is now seeded with every new realm, next to the console, so it cannot be squatted. On every start, `CliClientBootstrapService` resets the settings that decide where the CLI's codes and tokens go: public client, no secret, the built-in grant types and the loopback redirect URIs. If any of them differed, it logs a WARN and audits `SIGN_IN_CLIENT_RECONCILED` with the field names. The client's other settings are kept. **Chosen over refusing the client for sign-in:** refusing would lock out a legitimate CLI, while resetting the fields keeps the CLI working and removes the takeover. The console's redirect URIs were already reconciled this way. |
| R23 | **Sub-resources of sign-in clients in the services.** `ClientMapperAdminService` (create, update and delete) and `ResourceIndicatorService.updateAllowedResources` call `requireMayChangeSignInClient`. This also covers import, which did not pass through the interceptor. |
| R24 | **Protected flows.** Saving, creating, renaming (old or new name) or deleting the realm's `browser` flow, or the flow of a sign-in client or of its Application, needs realm-admin (`FlowAdminService`, via `PrivilegedPrincipalGuard.protectedFlows`). Binding a flow to a sign-in client was already a non-cosmetic change. |
| R25 | **manage-X includes view-X on routes.** `AdminAuthorizationManager` applies the same inclusion as the grant guard: manage-users, manage-clients, manage-identity-providers and manage-events satisfy their view-X routes. |
| R26 | **Credential delivery and sign-in policy** (found by the inventory). The following need realm-admin: messaging providers and templates (`MessagingAdminService`, since they carry codes, reset and magic links to administrators), the MFA policy (`MfaPolicyService.update`), switching magic links on or off (`MagicLinkService.setEnabled`), changing the realm's subject claim (`ClaimScopeAdminService.setSubjectClaim`), and changing any realm setting outside display name, legacy branding and self-registration (`RealmAdminService.save`: issuer, token and session lifetimes, MFA, lockout, password policy, CAPTCHA, session limits, risk policy, enabled). Registering a push device for a user needs that user's permissions (`DevicePushTokenService.register`), because the device receives their sign-in approvals. |
| R27 | **Taking permissions away.** Deleting a group needs the grants of the whole group tree; moving a group to another parent needs the grants of the group and of the new parent (`GroupAdminService`). Deleting a role needs its grants (`RoleAdminService.delete`). |

**Coordinator rulings after the final verification (supersede R20 and R22 where they differ):**

| # | Decision |
|---|---|
| R28 | **Grandfathered links, no lockout.** V86 marks every existing link `LEGACY` (wallet links `WALLET`); the 120-second JIT heuristic is dropped. `LEGACY` is trusted for sign-in: these links worked in rc.11, and the real attack (re-pointing the provider) is guarded by R19. `PrivilegedLegacyLinkReport` reports each administrator with a `LEGACY` link at start-up (WARN + `PRIVILEGED_LEGACY_LINK`: realm, username, alias; never blocks). Trusted provenances: `JIT`, `SELF`, `WALLET`, `ADMIN_CONFIRMED`, `LEGACY`; refused for administrators: `AUTO` and unknown. |
| R29 | **Self-link flow.** The account console's Connected accounts has a Link action per sign-in capable OIDC, SAML or social provider of the realm (server console form and the React account app). It needs a fresh sign-in (`AccountStepUp`, the `max_age` window; otherwise `/account/reauth?next=identity-link`, which then continues the link). `AccountIdentityLinkFlow` stores a link intent (realm, user, alias, random token, ten minutes) in the session; the broker start with `?link=<token>` binds the intent to the `state` it mints, and only the callback of that login consumes it. The callback links the validated identity to the intent's user, if the session still belongs to them, as `SELF`; it refuses an identity linked to someone else and is never a sign-in. Audited as `ACCOUNT_IDENTITY_LINK`. |
| R30 | **Admin confirm and revoke trust.** `POST /admin/realms/{realm}/users/{id}/federated-identities/{alias}/confirm` (`ADMIN_CONFIRMED`) and `.../revoke-trust` (`AUTO`: still works for an ordinary user, never for an administrator). Both need realm-admin (route and controller) and are audited (`FEDERATED_LINK_CONFIRMED`, `FEDERATED_LINK_TRUST_REVOKED`); `GET .../federated-identities` lists links with their provenance and `canManageTrust`. Console: user → Linked identities, with Confirm link / Revoke trust for realm admins only. |
| R31 | **Refusals are audited:** `PRIVILEGED_LINK_REFUSED` (realm, user id and name, alias, reason `email-match` or `untrusted-link`). |
| R33 | **Realm-scoped links** (review of R30): `federated_link.realm_id` (V86 + `schema.sql`), key `(realm_id, idp_alias, external_subject)`. Backfill: the realm whose `identity_provider` owns the alias when exactly one does, else the user's home realm, else their only membership; V86 warns about aliases used in several realms and rows left without a realm (those sign no one in and are logged at start-up). Every lookup, insert, update, provenance change and delete names the realm (broker, linking, unlinking, trust changes, start-up report, GDPR export and erasure, admin listing). Confirm and revoke-trust also run `requireMayActOnUserEverywhere`: the caller must hold, in every realm the user belongs to (master included), the user's admin permissions there. In `claim`, an owner is stale only when the user no longer exists. |
| R34 | **One source for a target's privilege** (review of R33): `PrivilegedPrincipalGuard.effectivePrivilegesEverywhere(userId)` (realm → permissions, over the user's memberships, the realms of their roles and group roles, and master) is the only way a target user's privilege is read. `requireMayActOnUser` (every user action, impersonation, push devices, trust changes), `isAdmin` (the broker), `requireMayChangeIdentityProvider` (each linked user) and the start-up report use it, so an administrator of another realm or of master is protected in every realm. **Ambiguous backfill:** a link V86 places by a fallback (alias in several realms or in none) is `realm_ambiguous` and `AUTO`, so it signs no administrator in until a realm admin confirms it; the report lists it as `AMBIGUOUS` (`PRIVILEGED_AMBIGUOUS_LINK`). The report lists a link when its user is an admin anywhere, with the link's realm and the admin realms. |
| R32 | **helix-cli reconcile corrects widening only** (replaces the reset in R22): non-loopback redirect URIs are dropped (the built-in ones if none is left), grant types outside the built-in set are dropped, a secret is removed and the client made public. Dropping `device_code` or a custom loopback port or path is kept. |

**Inventory size:** 141 write endpoints. 77 are guarded and 64 need no guard (reasons below). There are 25 import slices: 15 are guarded through their services and 10 need none. Each newly guarded row has an E2E test in
`SignInSurfaceE2eTest` (lower admin 403, realm admin of the realm 2xx, import leaves the protected value unchanged).
Rows guarded in earlier rounds keep their tests in `AdminGrantEscalationE2eTest`, `PrivilegedPrincipalE2eTest`,
`TrustBindingE2eTest` and `RealmKeyPermissionsE2eTest`. The trusted-list row reuses the identity-provider check and is
covered at that level.

### Admin write endpoints

| # | Method | Path | Class | Guard / reason |
|---|---|---|---|---|
| 1 | PUT | `…/admin-roles/{roleId}` | d | **Guarded:** route `realm-admin` |
| 2 | POST | `…/agents` | c,d | **Guarded:** `requireMayActOnAgent` / `requireMayGrant` of the agent roles and bound client (AgentIdentityAdminService) |
| 3 | DELETE | `…/agents/{id}` | c,d | **Guarded:** `requireMayActOnAgent` / `requireMayGrant` of the agent roles and bound client (AgentIdentityAdminService) |
| 4 | PUT | `…/agents/{id}` | c,d | **Guarded:** `requireMayActOnAgent` / `requireMayGrant` of the agent roles and bound client (AgentIdentityAdminService) |
| 5 | POST | `…/agents/{id}/activate` | c,d | **Guarded:** `requireMayActOnAgent` / `requireMayGrant` of the agent roles and bound client (AgentIdentityAdminService) |
| 6 | POST | `…/agents/{id}/revoke` | c,d | **Guarded:** `requireMayActOnAgent` / `requireMayGrant` of the agent roles and bound client (AgentIdentityAdminService) |
| 7 | POST | `…/agents/{id}/suspend` | c,d | **Guarded:** `requireMayActOnAgent` / `requireMayGrant` of the agent roles and bound client (AgentIdentityAdminService) |
| 8 | POST | `…/applications` | b | **Guarded:** `requireMayChangeApplication` (realm-admin for the parent of a sign-in client, displayName/description excepted); delete also `requireMayActOnClient` per child (ApplicationConfigService) |
| 9 | DELETE | `…/applications/{name}` | b | **Guarded:** `requireMayChangeApplication` (realm-admin for the parent of a sign-in client, displayName/description excepted); delete also `requireMayActOnClient` per child (ApplicationConfigService) |
| 10 | PUT | `…/applications/{name}` | b | **Guarded:** `requireMayChangeApplication` (realm-admin for the parent of a sign-in client, displayName/description excepted); delete also `requireMayActOnClient` per child (ApplicationConfigService) |
| 11 | POST | `…/claims` | - | None needed: reserved identity/authority claims (`ReservedClaims`: sub, iss, aud, roles, realm_access, act, ...) can never be written by a claim, scope or mapper; custom claims confer no admin permission |
| 12 | DELETE | `…/claims/{claimId}` | - | None needed: reserved identity/authority claims (`ReservedClaims`: sub, iss, aud, roles, realm_access, act, ...) can never be written by a claim, scope or mapper; custom claims confer no admin permission |
| 13 | PUT | `…/claims/{claimId}` | - | None needed: reserved identity/authority claims (`ReservedClaims`: sub, iss, aud, roles, realm_access, act, ...) can never be written by a claim, scope or mapper; custom claims confer no admin permission |
| 14 | POST | `…/client-scopes` | - | None needed: reserved identity/authority claims (`ReservedClaims`: sub, iss, aud, roles, realm_access, act, ...) can never be written by a claim, scope or mapper; custom claims confer no admin permission |
| 15 | DELETE | `…/client-scopes/{scopeId}` | - | None needed: reserved identity/authority claims (`ReservedClaims`: sub, iss, aud, roles, realm_access, act, ...) can never be written by a claim, scope or mapper; custom claims confer no admin permission |
| 16 | DELETE | `…/client-scopes/{scopeId}/claims/{claimId}` | - | None needed: reserved identity/authority claims (`ReservedClaims`: sub, iss, aud, roles, realm_access, act, ...) can never be written by a claim, scope or mapper; custom claims confer no admin permission |
| 17 | PUT | `…/client-scopes/{scopeId}/claims/{claimId}` | - | None needed: reserved identity/authority claims (`ReservedClaims`: sub, iss, aud, roles, realm_access, act, ...) can never be written by a claim, scope or mapper; custom claims confer no admin permission |
| 18 | POST | `…/clients` | b | **Guarded:** `SIGN_IN_CLIENTS` ids need realm-admin (ClientAdminService.create); the bootstrap seeds and reconciles them |
| 19 | PUT | `…/clients/{clientId}/allowed-resources` | b | **Guarded:** `requireMayChangeSignInClient` (ResourceIndicatorService) + interceptor |
| 20 | POST | `…/clients/{clientId}/authz/evaluate` | - | None needed: read-only evaluation |
| 21 | POST | `…/clients/{clientId}/authz/permissions` | - | None needed: resource-server policies of the client's own API, not admin permissions; sign-in and privileged clients still need realm-admin / their permissions (PrivilegedPrincipalInterceptor) |
| 22 | DELETE | `…/clients/{clientId}/authz/permissions/{name}` | - | None needed: resource-server policies of the client's own API, not admin permissions; sign-in and privileged clients still need realm-admin / their permissions (PrivilegedPrincipalInterceptor) |
| 23 | POST | `…/clients/{clientId}/authz/policies` | - | None needed: resource-server policies of the client's own API, not admin permissions; sign-in and privileged clients still need realm-admin / their permissions (PrivilegedPrincipalInterceptor) |
| 24 | DELETE | `…/clients/{clientId}/authz/policies/{name}` | - | None needed: resource-server policies of the client's own API, not admin permissions; sign-in and privileged clients still need realm-admin / their permissions (PrivilegedPrincipalInterceptor) |
| 25 | POST | `…/clients/{clientId}/authz/resources` | - | None needed: resource-server policies of the client's own API, not admin permissions; sign-in and privileged clients still need realm-admin / their permissions (PrivilegedPrincipalInterceptor) |
| 26 | DELETE | `…/clients/{clientId}/authz/resources/{name}` | - | None needed: resource-server policies of the client's own API, not admin permissions; sign-in and privileged clients still need realm-admin / their permissions (PrivilegedPrincipalInterceptor) |
| 27 | POST | `…/clients/{clientId}/authz/scopes` | - | None needed: resource-server policies of the client's own API, not admin permissions; sign-in and privileged clients still need realm-admin / their permissions (PrivilegedPrincipalInterceptor) |
| 28 | DELETE | `…/clients/{clientId}/authz/scopes/{name}` | - | None needed: resource-server policies of the client's own API, not admin permissions; sign-in and privileged clients still need realm-admin / their permissions (PrivilegedPrincipalInterceptor) |
| 29 | PUT | `…/clients/{clientId}/authz/settings` | - | None needed: resource-server policies of the client's own API, not admin permissions; sign-in and privileged clients still need realm-admin / their permissions (PrivilegedPrincipalInterceptor) |
| 30 | POST | `…/clients/{clientId}/mappers` | b | **Guarded:** `requireMayChangeSignInClient` (ClientMapperAdminService) + interceptor; reserved claims refused |
| 31 | DELETE | `…/clients/{clientId}/mappers/{mapperId}` | b | **Guarded:** `requireMayChangeSignInClient` (ClientMapperAdminService) + interceptor; reserved claims refused |
| 32 | PUT | `…/clients/{clientId}/mappers/{mapperId}` | b | **Guarded:** `requireMayChangeSignInClient` (ClientMapperAdminService) + interceptor; reserved claims refused |
| 33 | POST | `…/clients/{clientId}/roles` | d | **Guarded:** interceptor (`requireMayActOnClient`; sign-in client needs realm-admin); client roles never confer admin permissions |
| 34 | DELETE | `…/clients/{clientId}/roles/{name}` | d | **Guarded:** interceptor (`requireMayActOnClient`; sign-in client needs realm-admin); client roles never confer admin permissions |
| 35 | DELETE | `…/clients/{clientId}/service-account/roles` | d | **Guarded:** `requireMayGrant` of the role (ClientRoleAdminService) |
| 36 | POST | `…/clients/{clientId}/service-account/roles` | d | **Guarded:** `requireMayGrant` of the role (ClientRoleAdminService) |
| 37 | PUT | `…/clients/{clientId}/token-exchange` | b | **Guarded:** interceptor: sign-in clients need realm-admin, privileged clients their permissions |
| 38 | DELETE | `…/clients/{id}` | a,b | **Guarded:** `requireMayActOnClient` + sign-in client non-cosmetic changes need realm-admin (ClientAdminService) |
| 39 | PUT | `…/clients/{id}` | a,b | **Guarded:** `requireMayActOnClient` + sign-in client non-cosmetic changes need realm-admin (ClientAdminService) |
| 40 | POST | `…/clients/{id}/secret` | a,b | **Guarded:** `requireMayActOnClient` + sign-in client non-cosmetic changes need realm-admin (ClientAdminService) |
| 41 | PUT | `…/flow` | b | **Guarded:** `requireMayChangeFlow`: browser flow and flows of the sign-in clients / their Applications need realm-admin (old and new name on rename) |
| 42 | POST | `…/flows` | b | **Guarded:** `requireMayChangeFlow` on the new alias (FlowAdminService.create) |
| 43 | DELETE | `…/flows/{alias}` | b | **Guarded:** `requireMayChangeFlow`: browser flow and flows of the sign-in clients / their Applications need realm-admin (old and new name on rename) |
| 44 | PATCH | `…/flows/{alias}` | b | **Guarded:** `requireMayChangeFlow`: browser flow and flows of the sign-in clients / their Applications need realm-admin (old and new name on rename) |
| 45 | PUT | `…/flows/{alias}` | b | **Guarded:** `requireMayChangeFlow`: browser flow and flows of the sign-in clients / their Applications need realm-admin (old and new name on rename) |
| 46 | POST | `…/groups` | - | None needed: a new group has no roles |
| 47 | DELETE | `…/groups/{groupId}` | a,d | **Guarded:** `requireMayGrant` of the grants of the group tree (GroupAdminService.delete) |
| 48 | PUT | `…/groups/{groupId}` | d | **Guarded:** moving a group: `requireMayGrant` of its and the new parent's grants |
| 49 | DELETE | `…/groups/{groupId}/members/{userId}` | d | **Guarded:** `requireMayGrant` of the group's grants (GroupAdminService) |
| 50 | PUT | `…/groups/{groupId}/members/{userId}` | d | **Guarded:** `requireMayGrant` of the group's grants (GroupAdminService) |
| 51 | DELETE | `…/groups/{groupId}/roles/{roleId}` | d | **Guarded:** `requireMayGrant` of the role's grants |
| 52 | PUT | `…/groups/{groupId}/roles/{roleId}` | d | **Guarded:** `requireMayGrant` of the role's grants |
| 53 | POST | `…/identity-providers` | b,c | **Guarded:** `requireMayChangeIdentityProvider`: permissions of every linked administrator (IdentityProviderConfigService save/delete) |
| 54 | DELETE | `…/identity-providers/{alias}` | b,c | **Guarded:** `requireMayChangeIdentityProvider`: permissions of every linked administrator (IdentityProviderConfigService save/delete) |
| 55 | PUT | `…/identity-providers/{alias}` | b,c | **Guarded:** `requireMayChangeIdentityProvider`: permissions of every linked administrator (IdentityProviderConfigService save/delete) |
| 56 | POST | `…/import` | a-d | **Guarded:** each slice runs through the guarded services (see the import table) |
| 57 | POST | `…/import/keycloak` | a-d | **Guarded:** each slice runs through the guarded services (see the import table) |
| 58 | POST | `…/keys/csr` | c | **Guarded:** route `realm-admin` |
| 59 | POST | `…/keys/import` | c | **Guarded:** route `realm-admin` |
| 60 | POST | `…/keys/rotate` | c | **Guarded:** route `realm-admin` |
| 61 | DELETE | `…/keys/{keyId}` | c | **Guarded:** route `realm-admin` |
| 62 | POST | `…/keys/{keyId}/activate` | c | **Guarded:** route `realm-admin` |
| 63 | PUT | `…/keys/{keyId}/certificate` | c | **Guarded:** route `realm-admin` |
| 64 | PUT | `…/messaging/providers` | a | **Guarded:** realm-admin (MessagingAdminService): providers deliver codes, reset and magic links to administrators |
| 65 | POST | `…/messaging/providers/{channel}/test` | - | None needed: sends one test message through the stored provider; changes nothing |
| 66 | DELETE | `…/messaging/providers/{channel}/{driver}` | a | **Guarded:** realm-admin (MessagingAdminService): providers deliver codes, reset and magic links to administrators |
| 67 | POST | `…/messaging/push-tokens` | a | **Guarded:** `requireMayActOnUser` (DevicePushTokenService): a push device receives the user's sign-in approvals |
| 68 | PUT | `…/messaging/templates` | a | **Guarded:** realm-admin (MessagingAdminService.saveTemplate): a template could carry codes or links elsewhere |
| 69 | POST | `…/messaging/templates/preview` | - | None needed: renders a preview; stores nothing |
| 70 | POST | `…/organizations` | - | None needed: organization membership and settings confer no admin permission and are not an admin authority in tokens |
| 71 | DELETE | `…/organizations/{orgId}` | - | None needed: organization membership and settings confer no admin permission and are not an admin authority in tokens |
| 72 | PUT | `…/organizations/{orgId}` | - | None needed: organization membership and settings confer no admin permission and are not an admin authority in tokens |
| 73 | PUT | `…/organizations/{orgId}/branding` | - | None needed: cosmetic; custom CSS is validated (no external url(), @import, expression) |
| 74 | DELETE | `…/organizations/{orgId}/members/{userId}` | - | None needed: organization membership and settings confer no admin permission and are not an admin authority in tokens |
| 75 | PUT | `…/organizations/{orgId}/members/{userId}` | - | None needed: organization membership and settings confer no admin permission and are not an admin authority in tokens |
| 76 | PUT | `…/organizations/{orgId}/theme` | - | None needed: cosmetic; custom CSS is validated (no external url(), @import, expression) |
| 77 | PUT | `…/provisioning` | - | None needed: DCR settings/tokens: DCR acts UNPRIVILEGED (no admin roles, no sign-in client ids) |
| 78 | POST | `…/provisioning/initial-access-tokens` | - | None needed: DCR settings/tokens: DCR acts UNPRIVILEGED (no admin roles, no sign-in client ids) |
| 79 | POST | `…/roles` | - | None needed: a new role has no grants |
| 80 | DELETE | `…/roles/{roleId}` | a,d | **Guarded:** `requireMayGrant` of the role's grants (RoleAdminService.delete) |
| 81 | PUT | `…/roles/{roleId}/default` | d | **Guarded:** `requireNotAdminDefault` |
| 82 | POST | `…/saml-clients` | - | None needed: SAML relying parties: administrators never sign in to Helix through one; assertions carry no Helix admin authority |
| 83 | POST | `…/saml-clients/import` | - | None needed: SAML relying parties: administrators never sign in to Helix through one; assertions carry no Helix admin authority |
| 84 | POST | `…/saml-clients/import-url` | - | None needed: SAML relying parties: administrators never sign in to Helix through one; assertions carry no Helix admin authority |
| 85 | DELETE | `…/saml-clients/{entityId}` | - | None needed: SAML relying parties: administrators never sign in to Helix through one; assertions carry no Helix admin authority |
| 86 | PUT | `…/saml-clients/{entityId}` | - | None needed: SAML relying parties: administrators never sign in to Helix through one; assertions carry no Helix admin authority |
| 87 | POST | `…/scim-targets` | - | None needed: outbound only (push to a target); no inbound trust, no credentials of administrators |
| 88 | DELETE | `…/scim-targets/{id}` | - | None needed: outbound only (push to a target); no inbound trust, no credentials of administrators |
| 89 | PUT | `…/scim-targets/{id}` | - | None needed: outbound only (push to a target); no inbound trust, no credentials of administrators |
| 90 | DELETE | `…/sessions/{id}` | - | None needed: ends sessions only; cannot grant access |
| 91 | PUT | `…/settings` | b | **Guarded:** sign-in policy fields need realm-admin; display name, legacy branding, registration stay manage-realm (RealmAdminService.save) |
| 92 | PUT | `…/settings/account-console` | - | None needed: end-user self-service settings; attributes cannot reach reserved claims, admin permissions never come from attributes, the default role is guarded |
| 93 | PUT | `…/settings/magic-link` | b | **Guarded:** realm-admin on a change (MagicLinkService.setEnabled) |
| 94 | PUT | `…/settings/mfa` | b | **Guarded:** realm-admin (MfaPolicyService.update) |
| 95 | PUT | `…/settings/registration` | - | None needed: end-user self-service settings; attributes cannot reach reserved claims, admin permissions never come from attributes, the default role is guarded |
| 96 | PUT | `…/settings/self-editable-attributes` | - | None needed: end-user self-service settings; attributes cannot reach reserved claims, admin permissions never come from attributes, the default role is guarded |
| 97 | PUT | `…/settings/signing` | c | **Guarded:** route `realm-admin` |
| 98 | PUT | `…/settings/verify-email` | - | None needed: end-user self-service settings; attributes cannot reach reserved claims, admin permissions never come from attributes, the default role is guarded |
| 99 | PUT | `…/subject-claim` | d | **Guarded:** realm-admin on a change (ClaimScopeAdminService.setSubjectClaim): decides who every token names |
| 100 | PUT | `…/theme` | - | None needed: cosmetic; custom CSS validated (no external url(), @import, expression) |
| 101 | POST | `…/theme/assets` | - | None needed: cosmetic; custom CSS validated (no external url(), @import, expression) |
| 102 | DELETE | `…/theme/assets/{assetId}` | - | None needed: cosmetic; custom CSS validated (no external url(), @import, expression) |
| 103 | PUT | `…/theme/base` | - | None needed: cosmetic; custom CSS validated (no external url(), @import, expression) |
| 104 | POST | `…/theme/preview` | - | None needed: renders a preview; stores nothing |
| 105 | POST | `…/trusted-lists` | - | None needed: a new list is used by no provider |
| 106 | DELETE | `…/trusted-lists/{id}` | - | None needed: refused while any provider uses the list |
| 107 | PUT | `…/trusted-lists/{id}` | c | **Guarded:** `requireMayChangeIdentityProvider` for every provider using the list (TrustedListService.update) |
| 108 | POST | `…/trusted-lists/{id}/refresh` | - | None needed: re-fetches the configured source; the source and signer pinning are unchanged |
| 109 | POST | `…/user-federation/{alias}/sync` | - | None needed: runs the configured provider; its configuration is guarded as an identity provider |
| 110 | POST | `…/users` | - | None needed: a new user has no roles (the default role cannot confer admin permissions) |
| 111 | POST | `…/users/import` | - | None needed: a new user has no roles (the default role cannot confer admin permissions) |
| 112 | DELETE | `…/users/{userId}` | a | **Guarded:** `requireMayActOnUser` (UserAdminService / PrivilegedPrincipalInterceptor) |
| 113 | PUT | `…/users/{userId}` | a | **Guarded:** `requireMayActOnUser` (UserAdminService / PrivilegedPrincipalInterceptor) |
| 114 | DELETE | `…/users/{userId}/credentials/{type}/{id}` | a | **Guarded:** `requireMayActOnUser` (UserAdminService / PrivilegedPrincipalInterceptor) |
| 115 | DELETE | `…/users/{userId}/gdpr` | a | **Guarded:** `requireMayActOnUser` (UserAdminService / PrivilegedPrincipalInterceptor) |
| 116 | POST | `…/users/{userId}/impersonate` | a | **Guarded:** `requireMayActOnUser` (ImpersonationService) |
| 117 | PUT | `…/users/{userId}/password` | a | **Guarded:** `requireMayActOnUser` (UserAdminService / PrivilegedPrincipalInterceptor) |
| 118 | PUT | `…/users/{userId}/required-actions` | a | **Guarded:** `requireMayActOnUser` (UserAdminService / PrivilegedPrincipalInterceptor) |
| 119 | POST | `…/users/{userId}/roles` | d | **Guarded:** `requireMayGrant` of the role (RoleAdminService assign/unassign) |
| 120 | DELETE | `…/users/{userId}/roles/{roleId}` | d | **Guarded:** `requireMayGrant` of the role (RoleAdminService assign/unassign) |
| 121 | POST | `…/users/{userId}/send-verification-email` | - | None needed: mails the address on file; changes nothing |
| 122 | DELETE | `…/users/{userId}/sessions` | - | None needed: ends sessions only; cannot grant access |
| 123 | POST | `…/verifier-keys` | - | None needed: outbound verifier access keys / a certificate preview; no inbound trust |
| 124 | POST | `…/wallet/certificates/preview` | - | None needed: renders a preview; stores nothing |
| 125 | POST | `…/webhooks` | - | None needed: outbound only (push to a target); no inbound trust, no credentials of administrators |
| 126 | DELETE | `…/webhooks/{id}` | - | None needed: outbound only (push to a target); no inbound trust, no credentials of administrators |
| 127 | PUT | `…/webhooks/{id}` | - | None needed: outbound only (push to a target); no inbound trust, no credentials of administrators |
| 128 | POST | `…/workload-identity` | c | **Guarded:** `requireMayActOnClient` of the bound client (WorkloadIdentityCredentialAdminService) |
| 129 | DELETE | `…/workload-identity/{id}` | c | **Guarded:** `requireMayActOnClient` of the bound client (WorkloadIdentityCredentialAdminService) |
| 130 | PUT | `…/workload-identity/{id}` | c | **Guarded:** `requireMayActOnClient` of the bound client (WorkloadIdentityCredentialAdminService) |
| 131 | POST | `/connect/register` | - | None needed: acts UNPRIVILEGED, only on clients it registered; client ids are generated (`dcr-<uuid>`), so never a sign-in client id; cannot assign admin roles |
| 132 | DELETE | `/connect/register/{clientInternalId}` | - | None needed: acts UNPRIVILEGED, only on clients it registered; client ids are generated (`dcr-<uuid>`), so never a sign-in client id; cannot assign admin roles |
| 133 | PUT | `/connect/register/{clientInternalId}` | - | None needed: acts UNPRIVILEGED, only on clients it registered; client ids are generated (`dcr-<uuid>`), so never a sign-in client id; cannot assign admin roles |
| 134 | POST | `/scim/v2/Groups` | d | **Guarded:** UNPRIVILEGED actor: groups granting admin permissions refused (`requireMayGrant`) |
| 135 | DELETE | `/scim/v2/Groups/{id}` | d | **Guarded:** UNPRIVILEGED actor: groups granting admin permissions refused (`requireMayGrant`) |
| 136 | PATCH | `/scim/v2/Groups/{id}` | d | **Guarded:** UNPRIVILEGED actor: groups granting admin permissions refused (`requireMayGrant`) |
| 137 | PUT | `/scim/v2/Groups/{id}` | d | **Guarded:** UNPRIVILEGED actor: groups granting admin permissions refused (`requireMayGrant`) |
| 138 | POST | `/scim/v2/Users` | a,d | **Guarded:** UNPRIVILEGED actor: privileged users refused (`requireMayActOnUser`) |
| 139 | DELETE | `/scim/v2/Users/{id}` | a,d | **Guarded:** UNPRIVILEGED actor: privileged users refused (`requireMayActOnUser`) |
| 140 | PATCH | `/scim/v2/Users/{id}` | a,d | **Guarded:** UNPRIVILEGED actor: privileged users refused (`requireMayActOnUser`) |
| 141 | PUT | `/scim/v2/Users/{id}` | a,d | **Guarded:** UNPRIVILEGED actor: privileged users refused (`requireMayActOnUser`) |

### Realm-import slices

| Slice | Class | Guard / reason |
|---|---|---|
| importRealm | b | **Guarded:** `RealmAdminService.save` — sign-in policy fields need realm-admin |
| importAccountConsole | - | None needed: end-user self-service settings |
| importTheme | - | None needed: cosmetic; custom CSS validated |
| importOrganizationThemes | - | None needed: cosmetic; custom CSS validated |
| importRoles | - | None needed: creates roles without grants (grants come only through importAdminRoles) |
| importScopes | - | None needed: reserved claims cannot be written; `setSubjectClaim` is guarded where the slice sets it |
| importClients | a,b | **Guarded:** `ClientAdminService.create/update` — sign-in client ids and non-cosmetic sign-in changes need realm-admin, privileged clients their permissions |
| importSaml | - | None needed: SAML relying parties are no sign-in surface of administrators |
| importIdps | b,c | **Guarded:** `IdentityProviderConfigService.saveOrUpdate` — linked administrators' permissions |
| importFlows | b | **Guarded:** `FlowAdminService.create/save` — protected flows need realm-admin |
| importOrgs | - | None needed: organizations confer no admin permission |
| importApplications | b | **Guarded:** `ApplicationConfigService.saveOrUpdate` — parent of a sign-in client needs realm-admin |
| importAgents | c,d | **Guarded:** `AgentIdentityAdminService.save` — agent roles and bound client |
| importWebhooks | - | None needed: outbound only |
| importScim | - | None needed: outbound SCIM targets |
| importWorkload | c | **Guarded:** `WorkloadIdentityCredentialAdminService.save` — bound client's permissions |
| importMessaging | a | **Guarded:** `MessagingAdminService.saveProvider` — realm-admin |
| importTemplates | a | **Guarded:** `MessagingAdminService.saveTemplate` — realm-admin |
| importAdminRoles | d | **Guarded:** pre-check `requireMayGrant` + `AdminRbacService` (realm-admin route for the import itself is not needed: the grants are checked) |
| importGroups | d | **Guarded:** `GroupAdminService` — role assignment, move and membership need the grants |
| importUsers | a,d | **Guarded:** existing users through `UserAdminService.update` (`requireMayActOnUser`); their roles through `RoleAdminService.assign` (`requireMayGrant`) |
| importClientProtocolMappers | b | **Guarded:** `ClientMapperAdminService` — `requireMayChangeSignInClient` |
| importClientRoles | d | **Guarded:** `ClientRoleAdminService` — CLIENT roles need `roleClientId`, service-account roles `requireMayGrant` |
| importResourceIndicators | b | **Guarded:** `ResourceIndicatorService.updateAllowedResources` — `requireMayChangeSignInClient` |
| importAuthorizationServices | - | None needed: resource-server policies of the client's own API; no admin permissions |
