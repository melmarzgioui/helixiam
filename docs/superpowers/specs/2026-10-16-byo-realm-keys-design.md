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
