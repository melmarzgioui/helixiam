# EUDI Wallet (OpenID4VP verifier) — Phase 2 summary

Phase 2 ("Login flow end to end") of `docs/superpowers/specs/2026-10-09-eudi-wallet-openid4vp.md` is complete:
Tasks 1–23 are done and green on `feature/eudi-wallet`. This stands in for the Phase 2 pull-request description
(standing ruling: no push, no PR is opened from this branch yet — see "Process" below).

## 1. Library decisions

Pure Java throughout — no Kotlin, no `kotlin-stdlib` (spec §16 Q3, decided 2026-10-09). The EUDI reference libraries
(`eudi-lib-jvm-sdjwt-kt`, `org.multipaz`) are Kotlin, so the wallet verifier has its own small SD-JWT parser and
mdoc/COSE/CBOR reader built on four libraries already on the classpath, with nothing vendored:

| Need | Library | Version | Where |
|---|---|---|---|
| JOSE (JWS/JWE/JWK) | Nimbus JOSE+JWT | **10.10**, pinned in `dependencyManagement` | SD-JWT issuer JWT / KB-JWT verification, JWE `ECDH-ES` response decryption, JWK thumbprints. Was only transitive before (via Spring Authorization Server); pinned above SAS's own 9.47 for CVE-2025-53864 (unbounded JSON nesting), guarded by `NimbusNestedJsonRegressionTest`. |
| CBOR | Jackson `jackson-dataformat-cbor` | Spring Boot's Jackson BOM (2.21.4) | `wallet.mdoc.StrictCbor` — the only CBOR entry point for wallet input, used only through token-streaming (`CBORParser`) with Helix's own depth/item/byte limits, never `readTree`. |
| X.509 path validation | BouncyCastle (`bcprov`/`bcpkix-jdk18on`) | **1.86** | `IssuerTrustValidator` / `TrustAnchors` — PKIX chain building and validation against the provider's configured PID trust anchors. |
| QR code | ZXing (`com.google.zxing:javase`) | 3.5.4 (already a dependency, reused) | The wallet page's cross-device invocation QR (server-side SVG). |

Full rationale and licence notes are in `helix-iam-server/VENDOR-MAP.md` ("EUDI Wallet verifier: direct third-party
libraries", Task 6). mdoc/COSE (RFC 9052 COSE_Sign1 with x5chain, ISO 18013-5 structures) is Helix's own code on top
of Jackson CBOR, not a COSE library — the candidates evaluated (`com.authlete:cbor`, `COSE-JAVA`, `org.multipaz`)
were either Kotlin, a poor fit for the exact structures needed, or not worth the dependency for the bounded set of
COSE features a verifier needs (COSE_Sign1 decode + ES256/384/512 verify only, no COSE encrypt/MAC).

## 2. Spec versions pinned (from `docs/eudi-wallet-spec-notes.md` §0, fetched 2026-10-11)

| Spec | Version / status | Date |
|---|---|---|
| OpenID for Verifiable Presentations 1.0 | Final | 9 July 2025 |
| OpenID4VC High Assurance Interoperability Profile (HAIP) 1.0 | Final | 24 December 2025 |
| Selective Disclosure for JWTs | RFC 9901 | November 2025 |
| SD-JWT-based Verifiable Credentials (SD-JWT VC) | `draft-ietf-oauth-sd-jwt-vc-19` | 31 August 2026 |
| Token Status List (TSL) | `draft-ietf-oauth-status-list-21` | 21 June 2026 |
| ISO/IEC 18013-5 (mdoc) | 2021 edition paywalled, not read; structures taken from OpenID4VP Annex B and the public 2nd-edition working draft | 2025-09-14 |
| ARF | v3.0.0 | 2026-07-23 |
| ARF Annex 3.01 PID Rulebook | v1.7 (catalog commit `6d8f7f84`) | 17 July 2026 |

**Noted version-pinning conflict:** HAIP 1.0 §9.4 pins older drafts (SD-JWT VC -13, TSL -14) than the ones actually
read (-19, -21), and says implementers should prefer the HAIP-pinned versions if a breaking change occurs. The
format identifiers and `status.status_list` shape are identical across both version pairs per their change logs, but
this was not diffed line-by-line — flagged **UNVERIFIED** in the spec notes, not re-litigated here.

## 3. Plan conflicts and rulings (from `.superpowers/sdd/2026-10-09-eudi-wallet-openid4vp/progress.md`)

The pre-recorded conflicts in `constraints.md` (KMS abstraction, `acr` propagation, session-id rotation, provider
secret encryption, weak-subject linking, IdP-registry realm scoping, DCO-only commits) all stand as shipped. Beyond
those, ~100 further rulings were made task-by-task; grouped by topic:

**Protocol mechanics.** `client_id` supports both `x509_hash` (HAIP default) and `x509_san_dns`; the invocation
scheme defaults to `haip-vp` (configurable); `sd_hash` uses the credential's own `_sd_alg`, never a fixed SHA-256;
the JWE response-encryption set is the constant `{A128GCM, A256GCM}` (HAIP requires both); the request object's
`state` is `base64url(SHA-256(transactionId))`, deterministic and never the broker's own anti-CSRF `helixState`
(which must never reach the wallet).

**Trust and revocation.** Status-list policy is asymmetric: anything that proves the list itself cannot be trusted
(bad signature, untrusted/expired chain, wrong `typ`/`alg`, `sub` ≠ `uri`) fails **closed** always, even under
fail-open; only genuinely transient unavailability (connect/read/TLS/timeout/5xx/DNS failure, and — ruled
separately — thread interruption) is eligible to fail open, and only when the operator's `StatusPolicy` says so. A
non-https `status_list.uri`, or one blocked by `OutboundUrlGuard`/not in the configured allow-list, is refused by
policy before any fetch — always treated as unavailable, never fetched, regardless of fail-open. CA trust anchors
without a `KeyUsage` extension are accepted (RFC 5280: absent KU is unrestricted); `basicConstraints` CA is still
required. The ISO §6.5 mdoc status-list-signer rule is enforced on the PKIX-*validated* chain and anchor, never the
raw presented `x5chain`: the list signer must chain to the MSO signer's own issuing CA, not merely share a root.

**mdoc verification specifics.** A DeviceAuth mismatch against the expected SessionTranscript (wrong nonce, wrong
`client_id`, wrong `response_uri`) is always `HOLDER_BINDING_INVALID`, never `NONCE_MISMATCH`/`AUDIENCE_MISMATCH` —
the transcript is hashed inside a detached signature, so the verifier cannot tell which input differed, and a
guessed code would mislead operators (confirmed again, independently, by `WalletAcceptanceE2eTest`'s real-HTTP mdoc
rejection tests in Task 23). `DeviceResponse` version `"1.x"` is accepted (ISO 2nd-edition minor bumps); an MSO
whose validity window falls outside its signing certificate's own validity is `INVALID_RESPONSE` (inconsistent
issuer data, not a trust failure).

**Claims and identity.** `age_over_18` is dropped from the default PID mapping (no longer a PID attribute per the
Rulebook). Every requested claim is required by default (DCQL `claim_sets` is reserved for the subject's optional
`personal_administrative_number`/`issuing_country`). When a wallet answers with both formats, `given_name`,
`family_name` and `birthdate` must agree after normalisation or the login is refused (`INVALID_RESPONSE`, no
dedicated code exists); the SD-JWT presentation is authoritative for every other attribute.

**Transaction and session security.** The browser binding is `SHA-256` of a random per-login secret kept as an HTTP
session *attribute* (not the session id, which rotates — Task 2's own fix). `response_code` and request ids are
stored hashed, never raw, in the Redis index. A cross-device code is issued only once, atomically
(`issueResponseCode`), by a `VERIFIED` transaction with a matching binding; a same-device code travels only through
`complete()`. Redemption never "burns" a transaction on a mismatch (burning on mismatch would let a code-holder
cancel the victim's login instead of their own). A weak (attribute-tuple) subject match that would *upgrade* an
existing link is held as a `PendingLink` and committed only after the whole login has actually succeeded.

**Realm/key scoping.** A stored wallet provider is bound to its own realm (`start()` refuses otherwise); a YAML
provider signs with the master-realm key and serves any realm. `WalletIdentityProviders`/Task 18 re-check
`transaction.realmId` against the request realm on every wallet endpoint (constraints.md conflict #6, reconfirmed
several times across tasks).

**EU-wallet conformance tension (flagged to the maintainer, not resolved here).** The spec requires cross-device QR
(§2.1.3); ARF guidance (OIA_08c) says EU wallets *should not* support redirect-based cross-device at all. Both are
kept as documented in the spec notes; the W3C Digital Credentials API is the strategic cross-device path, scheduled
for Phase 4, and its priority rises if conformant EU wallets turn out not to support the QR flow in practice.

**Process.** No PR is opened and the branch is not pushed (owner has not authorised pushing it yet) — this document
stands in for the Phase 2 PR description; the branch is presented at the end via `finishing-a-development-branch`.
Documentation (`docs/eudi-wallet.md`, `docs/FEATURES.md`, `CHANGELOG.md`, `VENDOR-MAP.md` operator-facing additions,
`SECURITY-REVIEW.md`) is Task 26, in Phase 3 — not yet written; this is by the plan's own task split, not a Phase 2
gap. CodeQL: the CLI is not installed locally; `helix-iam-server/CODEQL-TRIAGE.md` carries a note for the pending
GitHub run.

## 4. Open questions

1. **Cross-device QR vs ARF OIA_08c.** Spec §2.1.3 requires cross-device QR; ARF guidance recommends against
   redirect-based cross-device for EU wallets. Kept both as documented tension (see above); needs a maintainer call
   once a real EU wallet is tested against it in Phase 4.
2. **SD-JWT VC / Token Status List draft versions.** HAIP 1.0 pins drafts -13/-14; this implementation reads -19/-21.
   Not diffed line-by-line for verifier-relevant breaking changes — flagged **UNVERIFIED** in the spec notes.
3. **mdoc test vectors against ISO 18013-5 2021 directly.** The paywalled 2021 edition was not read; structures come
   from OpenID4VP Annex B and the public 2nd-edition working draft only. A Phase 4 conformance run is the place to
   catch any gap this leaves.
4. **Shared-root status-list anchors.** Parked to final triage/Task 26 docs: an issuer whose status-list signer
   chains to a *shared* root that also issues the MSO signer (rather than to a dedicated list CA under it) passes
   §6.5 as written; this is standard for per-issuer IACA anchors but is worth a line in `SECURITY-REVIEW.md`.

## 5. Four pre-existing security findings outside the wallet (unrelated to this feature, surfaced during this work)

Found while reading the surrounding codebase for this feature; none were introduced by the wallet work and none are
fixed by it. Recorded here for visibility, not remediated under Task 23:

1. **Federated logins skip the MFA step-up.** A login completed through a federated identity provider does not go
   through the same MFA gate a local password login does.
2. **`EidLevelOfAssurance.meetsMinimum` treats an unknown minimum as met.** An eIDAS LoA rung string that
   `EidLevelOfAssurance.rung(...)` does not recognise resolves to `0`, the same value a blank/absent minimum gets —
   so an unreachable or garbage `minimumLoa` is silently treated as satisfied rather than refused. (The wallet's own
   `WalletAttributeMapper.satisfiesMinimumLoa` was written defensively against exactly this, per its javadoc, even
   though `WalletConfigValidator` is believed to make it unreachable for wallet providers today.)
3. **`AttributeEncryption` falls back to plaintext.** Outside the `dev` profile the wallet access-key import path
   refuses to run without `DB_ENCRYPTION` configured (confirmed by `RealmSigningKeysTest`/Task 4's ruling), but the
   underlying `AttributeEncryption` component itself falls back to storing plaintext when encryption is not
   configured, rather than refusing — a latent risk for any other caller that does not add its own guard.
4. **`RateLimitFilter` trusts `X-Forwarded-For`.** The per-IP login/token/wallet rate limiters key off
   `X-Forwarded-For` without restricting it to a configured trusted-proxy source, so a client behind no proxy (or an
   untrusted one) can forge a different IP per request and evade the limiter. Flagged again during Task 18's review
   (`#10`, parked to final triage) because the wallet's own `wallet`/`wallet-start` buckets share this filter.
