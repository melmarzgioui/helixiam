# SDD ledger — plan: docs/superpowers/plans/2026-10-09-eudi-wallet-openid4vp.md

Spec: docs/superpowers/specs/2026-10-09-eudi-wallet-openid4vp.md (reachable). Worktree: <local> branch feature/eudi-wallet, base 0a867c3.
Commit rule: `git commit -s` (DCO), NO AI attribution trailers (owner rule overrides harness reminder).

## Pre-flight scan

| Pair / task | Produces → consumes | Finding |
|---|---|---|
| T6 ↔ T7, T10 | T6 VerificationContext uses TrustAnchors (T7), StatusPolicy (T10) | Order conflict: T6 compiles only if they exist |
| T9 ↔ T10 | T9 defines StatusEvaluator; T10 implements | OK (T9 before T10) |
| T11 ↔ T10 | MSO uses StatusReference (T10) | OK (T10 before T11) |
| T12 ↔ T1 | SessionTranscript structure from notes | OK |
| T14 ↔ T15 | DcqlQueryBuilder takes WalletProviderConfig.Pid (T15) | Order conflict |
| T16 ↔ T17/T18 | two request ids, Flow | consistent |
| T17 ↔ T5 | SigningKeyHandle | OK |
| T18 ↔ T19 | T18 e2e drives full flow; needs T19 provider/factory + AuthnRequestContext 4-arg | Order conflict |
| T18 ↔ T20, T21 | response endpoint maps + resolves subject | Order conflict |
| T21 ↔ T18 | link flow (account console) needs wallet endpoints | circular with above |
| T3 ↔ T20 | T20 sets `loa`, T3 turns it into acr | OK |
| T4 ↔ T15 | secret keys incl. wallet keys | OK |
| Each task self-consistency | T1 docs-only; T2–T5 tests match code described; T6 placeholders note conflicts with No-placeholders → resolved by ruling below; others consistent | — |

Ruling: T6 creates `TrustAnchors` (record fields only, `fromPem` added in T7) and `StatusPolicy`/`StatusReference` records (T10 adds behaviour) — so T6 compiles without placeholders — cost if wrong: small refactor in T7/T10.
Ruling: T14's builder takes a new record `PidQuerySpec(List<String> sdJwtVcts, String mdocDoctype, List<String> requestedClaims)`; T15's `WalletProviderConfig.Pid` provides `toQuerySpec()` — cost if wrong: one adapter method.
Ruling: execution order 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,19,20,21a,18,21b,22,23,24,25,26 — T19 (provider/factory, AuthnRequestContext 4-arg) and T20/T21a (mapping + subject resolver, no UI) before T18 (endpoints + e2e); T21b (account-console wallet linking flow + browser test) after T18 — cost if wrong: re-ordering only.

## Progress
Task 1: dispatched (base 0a867c3, implementer opus)
Task 1: implementer DONE_WITH_CONCERNS (554e833); 30 plan/spec deviations vs final texts in task-1-report.md; review dispatched (opus)
Ruling: client_id — support BOTH `x509_hash` (HAIP-required, DEFAULT) and `x509_san_dns`; access cert must not be self-signed (validator) — spec §2.1.7 said san_dns required, final HAIP says x509_hash; spec defers to final texts — cost if wrong: config default flip.
Ruling: invocation scheme default `haip-vp`, configurable (openid4vp, eudi-openid4vp, custom) — notes; cost: default change only.
Ruling: sd_hash uses the `_sd_alg` hash (not fixed SHA-256); SD-JWT VC `iss` optional (not required) — follow RFC/draft over plan text — cost: none if notes right.
Ruling: `pid.sdJwtVcts` stays a LIST and also honours `aka_vcts`/national PID vcts as configured; default list = values recorded in notes — cost: admins add national vct.
Ruling: mdoc revocation via CWT status list (and identifier list if notes require) — Task 10 gains CWT form; Task 11/12 read status from where notes place it (DeviceResponse-level `status`, MSO status ref) — cost: Task 10 grows.
Ruling: `statusList.required` DEFAULT false (spec §9 example says true) — final texts allow short-lived PIDs without status; required=true would reject valid PIDs; operator can set true — cost if wrong: PIDs w/o status accepted by default (still validity-checked).
Ruling: drop `age_over_18` from the default PID mapping (not a PID attribute anymore) — cost: none.
Ruling: keep cross-device QR (spec §2.1.3 requires it) despite ARF OIA_08c (EU wallets SHOULD NOT support redirect-based cross-device); flag to owner; W3C Digital Credentials API (Phase 4) is the strategic cross-device path — cost if wrong: QR flow unusable with conformant EU wallets → Phase 4 priority rises.
Task 1: review — spec ✅, quality Needs fixes (Important: SOURCES.md missing IETF Revised BSD notice for extracted Code Components; OIDF files field-of-use)
Ruling: include reviewer Minor "ISO 2nd-ed draft CDDL quoted verbatim (~170 lines, repo licence null)" in the fix round — same licence class as the Important finding; shipping unlicensed third-party text in an Apache repo is a compliance defect — cost if wrong: notes §6 slightly less convenient (field names + section refs instead of verbatim).
Task 1: minor (deferred): x509_hash padding UNVERIFIED is settled by OpenID4VP §1.2 (no padding) — fold into fix round as trivial
Task 1: minor (deferred): status-list-21-C.*.json lack `source` field; ARF VCR_12/13 quote wrapping
Task 1: fix round 1/5 (4 addressed, 0 open; commits 554e833..5eba721)
Task 1: complete (commits 0a867c3..5eba721, review clean)
Task 2: dispatched (base 5eba721, implementer sonnet)
Task 2: review — spec ✅, quality Needs fixes (Important: queue session store keeps the pre-rotation id valid — QueueIndexedSessionRepository.save ignores getOriginalId(); test only asserts cookie changed)
Task 2: minor (deferred): test names promise rotate-BEFORE-persist ordering but don't assert it (FederatedLoginCompleterTest:131, FlowControllerTest:54)
Task 2: minor (deferred): stale copied comment FederatedLoginCompleterTest:135 + duplicated stubbing
Task 2: minor (deferred): password+MFA logins rotate twice (harmless once #1 fixed)
Task 2: minor (deferred): FlowControllerTest outside fast filter
Task 2: fix round 1/5 (1 addressed, 0 open; commits 96d53ff..b643453)
Task 2: complete (commits 5eba721..b643453, review clean)
Task 3: dispatched (base b643453, implementer sonnet)
Task 3: review — spec ✅, quality Needs fixes (Critical: acr taken from generic attribute 'loa' that any OIDC IdP fills from its id_token → forged eIDAS LoA; Important: HELIX_ACR never cleared → stale/cross-user acr on later password login / abandoned challenge)
Ruling: LoA travels in a dedicated typed component on BrokeredIdentity (`levelOfAssurance`), with a 5-arg compatibility constructor (null) so existing providers/tests compile unchanged; only EidSamlIdentityProvider (and later the wallet provider) set it, and only values with EidLevelOfAssurance.rung(scheme, v) > 0 — spec §5.1 prefers backward-compatible SPI additions; a record component + compat constructor is that — cost if wrong: one SPI field to rename later.
Task 3: minor (deferred): duplicated stash block + FQCNs in FederatedLoginCompleter/tests; helix_acr key naming vs dotted siblings (brief-mandated); acr-only binding guard untested
Task 3: fix round 1/5 (2 addressed, 0 open; commits 0934fe6..47f853f)
Task 3: minor (deferred, SECURITY-ish — final review should triage): FlowController.submitChallenge doesn't check state.userId() == authenticated principal; abandoned flow state survives non-flow logins → stale pendingAcr (and stale flow) completable under another principal (FlowController.java:116-122; pre-existing gap)
Task 3: minor (deferred): e2e stub passes loa directly, so e2e skips the typed levelOfAssurance/eID ladder path (unit-covered)
Task 3: complete (commits b643453..47f853f, review clean)
Task 4: dispatched (base 47f853f, implementer opus)
Task 4: review — spec ✅, quality Approved
Ruling: accept the fromStored+start() substitute for 'login still works via the stub' (federation store off in e2e; real upstream token exchange covered by existing OIDC tests) — cost if wrong: a kept-secret regression in the token exchange would surface only in Phase 2 e2e.
Ruling: the console Set/Replace secret inputs added in Task 4 get their Playwright UI/UX review together with Task 24 (same Connection screens), before merge — frontend rule satisfied before shipping — cost if wrong: one more visual fix round in Phase 3.
Task 4: minor (deferred): PUT changing protocol keeps old protocol's secrets (IdentityProviderConfigService:1355-1371)
Task 4: minor (deferred): IdentityProviderConfig record toString() prints merged secrets — override to redact
Task 4: minor (deferred, user-visible): LDAP detail page binds bindPassword but wizard/backend use bindPw → badge shows Not set (ConnectionDetailPage.tsx:419)
Task 4: minor (deferred): backfill SELECT-then-UPDATE without lock; duplicate AttributeEncryption instances → repeated WARN banner; e2e hardcodes DB key
Task 4: complete (commits 47f853f..cf9b4bf, review clean)
Task 5: dispatched (base cf9b4bf, implementer opus)
Task 5: review — spec ✅, quality Needs fixes (Important: HAIP not-self-signed check bypassable via different issuer DN)
Ruling: confirmed ⚠️ gap — importKey refuses (IllegalArgumentException, clear message) when AttributeEncryption is disabled (no DB_ENCRYPTION) outside the dev profile — plan conflict #4 says the wallet access key must not repeat plaintext storage — cost if wrong: operators must set DB_ENCRYPTION before uploading a verifier key (they must in prod anyway).
Ruling: include reviewer Minor 2 (curve identity via Nimbus Curve.forECParameterSpec, allow only P-256/384/521) and Minor 1 (parseChain runtime exceptions → IllegalArgumentException) in this round — both make the import contract exact, cheap — cost if wrong: none.
Task 5: minor (deferred): realmId length / PEM size caps not validated (→ DataIntegrityViolation); weak toString assertion
Task 5: fix round 1/5 (4 addressed, 0 open; commits 29b69f7..f381322)
Task 5: minor (deferred): field/local name collision 'encrypted' in SoftwareRealmSigningKeys.importKey; parseChain RuntimeException branch structurally uncovered (BC wraps today)
Task 5: complete (commits cf9b4bf..f381322, review clean)
Phase 0: gate running (full suite + sql-init) on f381322
Phase 0: gate GREEN on f381322 (full 2590+34, sql-init 248, console 304)
Ruling: plan says 'one PR per phase' — no push/PR is opened (owner hasn't authorised pushing this branch); phases are gated locally and the branch is presented at the end via finishing-a-development-branch — cost if wrong: owner opens per-phase PRs from the commit ranges in this ledger.
Task 6: dispatched (base f381322, implementer opus)
Ruling: nimbus-jose-jwt pinned in dependencyManagement at 9.47 (Boot doesn't manage it; same version SAS already pulls) — plan said 'without a version (Boot-managed)' which is false; cost if wrong: version bump in one place
Task 6: review — spec ✅, quality Needs fixes (Important: nimbus-jose-jwt 9.47 affected by CVE-2025-53864 / GHSA-xwmg-2g98-w7v9; patched 9.37.4 / 10.0.2; reachable via SAS token parsing too — ALSO affects released master/rc.6)
Ruling: bump nimbus-jose-jwt to the latest 10.x that the full suite (SAS/OIDC/JWK tests) accepts; if 10.x breaks SAS 1.5.8 APIs, fall back to 9.37.4 and run the suite — security fix, version choice is reversible — cost if wrong: one more version change.
Task 6: minor (deferred): StrictCbor budget per call not per document (mdoc task must only decode tag 24 at spec positions or share budget); head-byte defensive check untested in isolation; self-made DeviceResponse vector (need real interop vector before/at Task 12); VerificationContext byte[] equals
Task 6: fix round 1/5 (1 addressed, 0 open; commits 1544b53..86239b1)
Task 6: complete (commits f381322..86239b1, review clean)
OPEN QUESTION to owner: hotfix Nimbus 10.10 on master + tag v1.0.0-rc.7 (released rc.6 affected by CVE-2025-53864) — awaiting answer; NOT pushed
Task 7: dispatched (base 86239b1, implementer opus)
Task 7: review — spec ✅, quality Needs fixes (Important: JDK OCSP/CRL timeouts default 15s on sync login path)
Ruling: rule reviewer Minor 2 (anchors must be CA certs: basicConstraints>=0, keyCertSign if KU present, key strength) and Minor 3 (null revocation → SOFT_FAIL per spec §7.5 default) into fix round 1 — both are spec-text mismatches (§7.5 'PEM CA certificates', default SOFT_FAIL) — cost if wrong: an admin-supplied non-CA anchor gets a 400 instead of being accepted.
Task 7: minor (deferred): SOFT_FAIL with ≥2 intermediates can accept revoked lower CA (per-cert check would fix); test leaks JVM system properties; one blocked revocation URL skips revocation for whole chain under SOFT_FAIL (→ DEFERRED-SECURITY-WORK)
Ruling: CA anchors without a KeyUsage extension are accepted (RFC 5280: absent KU = unrestricted); basicConstraints CA is still required — cost if wrong: a CA without KU (rare, legacy roots) works; tighten later if ETSI profile requires KU.
Task 7: fix round 1/5 (4 addressed, 0 open; commits e6856d0..dbac612)
Task 7: complete (commits 86239b1..dbac612, review clean)
Task 8: dispatched (base dbac612, implementer opus)
Task 8: implementer DONE (5a4f929); controller verified no '&& false'/disabled checks in committed wallet code (git grep clean) after security-scan alert on a transient RED mutation
Task 8: carry to Task 9: Nimbus silently keeps last value on duplicate JSON keys in issuer JWT / KB-JWT payloads — Task 9 must reject duplicate keys (parse payload with strict Jackson or check)
Task 8: review — spec ✅, quality Approved
Ruling: maxJwtBytes caps the WHOLE presentation (issuer JWT + disclosures + KB-JWT) at 64 KB — stricter reading of 'JWT 64 KB'; a PID with x5c + ≤100 disclosures fits well under — cost if wrong: raise the limit to a presentation-specific value.
Task 8: minor (deferred): disclosed claim named _sd_alg leaks into resolved output (contradicts javadoc / RFC 7.1 3.f); no test for trailing-~-omitted; size check counts chars not bytes; digest non-ASCII error code
Task 8: complete (commits dbac612..5a4f929, review clean)
Task 9: dispatched (base 5a4f929, implementer opus)
Task 9: implementer DONE (d8775b7); controller verified committed vct check = noneMatch(accepted::contains) (line 267) after security-scan alert on transient mutant; git grep clean
Ruling: StatusEvaluator contract stays 'VALID or throw'; under FAIL_OPEN_WITH_AUDIT the Task 10 client emits the audit/warn itself and returns VALID — keeps verifiers simple — cost if wrong: contract widening later.
Ruling: VerifiedPresentation gains a credentialType component (vct for SD-JWT, docType for mdoc) in Task 14, which needs it to match each presentation to its DCQL query; Task 14 updates the SD-JWT verifier accordingly — cost if wrong: one record change.
Task 9: review — spec ✅, quality Needs fixes (Important: status fail-open when status_list hidden behind nested _sd or unknown status mechanism → reported ABSENT)
Ruling: any _sd / ... digest anywhere inside never-disclosed objects (status, cnf) → DISCLOSURE_INVALID; a present 'status' with no evaluable mechanism → treated as unavailable per statusPolicy.onUnavailable (default FAIL_CLOSED → STATUS_UNAVAILABLE), never ABSENT — revocation must not be holder-controlled — cost if wrong: credentials from issuers using an unsupported status mechanism are refused by default.
Ruling: include reviewer Minors 'evaluator not invoked on KB failure' and 'explicit kty:oct cnf test' in the fix round — they pin security-relevant ordering/rejection, cheap — cost: none.
Task 9: minor (deferred): exact clock-edge tests with fixed now; aka_vcts honoured although HAIP pins SD-JWT VC -13 (doc that type acceptance == per-anchor trust; PID anchors must be PID-only; consider flag); RSA_PSS guard duplicate
Task 9: fix round 1/5 (status fail-open: _sd in status/cnf rejected, unevaluable status per onUnavailable, KB-fail skips evaluator, kty oct test; commits d8775b7..8914e4f) — re-review: all addressed
Ruling: non-https status_list.uri is enforced in Task 10's TokenStatusListClient (refused before any fetch → handled as unavailable per onUnavailable, never fetched), not in the SD-JWT verifier — retrieval owns scheme policy, same as OutboundUrlGuard — if wrong, an http URI reaches the evaluator but is still never fetched
Ruling: missing/non-integer idx test gap deferred to final-review triage (code is correct by inspection) — cost if wrong: one untested branch
Task 9: complete (commits 5a4f929..8914e4f, review clean)
Task 10: implementer DONE_WITH_CONCERNS (commit 8b3423b; base 8914e4f; 2853+34 green); security-scan "MUTANT guard" alert = transient mutation edit, committed code calls guard.checkAllowed (verified)
Ruling: status-list URIs refused by POLICY (non-https, OutboundUrlGuard-blocked, not in allowedHosts) always fail CLOSED (STATUS_UNAVAILABLE), even under FAIL_OPEN_WITH_AUDIT — fail-open is for transient availability, not for an issuer pointing us at an address we refuse; the URI is issuer-signed so this can't be an attacker toggle — cost if wrong: a misconfigured issuer's credentials are refused until fixed
Ruling: client-owned fail-open (statusResult "VALID" + audit via client sink) accepted; the wiring task (T14) must pass the provider's StatusPolicy + auditLogSink — carried to T14 dispatch; surfacing UNAVAILABLE_ACCEPTED in login audit deferred to final-review triage
Ruling: CWT text media type only, COSE_Mac0 refused, ISO StatusListInfo.certificate left to mdoc tasks (T11-13) — carried to those dispatches
Task 10: review — spec ❌ (policy refusals + integrity failures fail open), quality needs fixes; 1 Critical, 2 Important, 7 Minor (task-10-review.md)
Ruling: every integrity failure of a fetched list (signature, untrusted/expired chain = ISSUER_UNTRUSTED, typ, alg, sub≠uri) fails CLOSED; only transient availability (connect/read error, timeout, 5xx, DNS-resolution failure in the guard) may fail open — a list we fetched but can't trust is not "unavailable" — cost if wrong: an issuer whose status-list cert lapses blocks logins until renewed
Ruling: fix round 1 covers findings 1,2,3,4,7,8; deferred to final triage: 5 (cache memory ~128MB worst case), 6 (guard DNS not inside deadline), 9 (UNAVAILABLE_ACCEPTED visibility → T14), 10 (split CWT class)
Ruling: 404/redirect-limit/malformed/expired-token/size-limit fail CLOSED (only connect/read/TLS/timeout/5xx/DNS fail open) — stricter than reviewer, matches 'only transient' — cost if wrong: an issuer's stale list blocks logins rather than auditing
Task 10: fix round 1/5 (policy+integrity fail closed, 24-class matrix, maxCache clamp, connect-timeout + 256MB bomb tests; commits 8b3423b..f5b42e8) — re-review: all addressed
Ruling: InterruptedException during fetch counts as transient (fail-open eligible) — interruption is an availability event, not a trust signal — cost if wrong: a shutdown-time interrupt accepts one login with an audit entry
Task 10: complete (commits 8914e4f..f5b42e8, review clean)
Ruling: T11 CoseSign1.decode takes Task 6's CborValue (StrictCbor tree), not Jackson JsonNode as the plan sketched — one bounded CBOR parser for all untrusted input (T6 constraint) — cost if wrong: signature differs from plan text only
Ruling: T11 extracts the COSE_Sign1 logic already inlined in StatusListToken (T10 CWT form) into CoseSign1 and makes StatusListToken use it — no duplicated signature verification; also shrinks T10 deferred finding 10 — cost if wrong: T10 tests must stay green, which they gate
Task 11: implementer DONE_WITH_CONCERNS (commit a32226c; base f5b42e8; 2963+34 green)
Ruling: MSO status present without status_list (e.g. identifier_list) → INVALID_RESPONSE for now; T12 (mdoc verifier) must instead treat it as present-but-unevaluable per onUnavailable, matching the SD-JWT path (T9 ruling) — carried to T12 dispatch — cost if wrong: identifier_list wallets refused until T12
Ruling: ESP256 (-9) stays allowed for status-list CWT via an explicit allow-set; CoseSign1 default allow-list = ES256/384/512 — keeps T10 behaviour unchanged — cost if wrong: none for MSO
Task 11: review — spec ✅, quality approved; 9 Minor (task-11-review.md)
Ruling: T11 minors carried to T12 (which touches the same files): #1 non-preferred protected-header test, #3 decode protected header once with CborLimits.DEFAULTS, #6 keep status_list.certificate in StatusReference/MSO for T12-13 trust; parked for final triage: #2 strict tdate, #4 single-cert array, #5 version pin, #7 byte[] equals, #8 DeviceSignature negative test, #9 Nimbus internal ECDSA helper
Task 11: complete (commits f5b42e8..a32226c, review clean)
Ruling: T12 mdoc DeviceAuth failure over the expected SessionTranscript → HOLDER_BINDING_INVALID for BOTH the other-nonce and other-client_id tests (brief asked NONCE_MISMATCH / AUDIENCE_MISMATCH) — the transcript is hashed inside a detached signature, so the verifier cannot tell which input differed; guessing a code would mislead operators — cost if wrong: coarser error code in audit for mdoc only
Ruling: T12 mdoc status: MSO status without status_list (identifier_list etc.) → present-but-unevaluable → onUnavailable (matches SD-JWT path); missing status → ABSENT/STATUS_REQUIRED per StatusPolicy.required
Task 12: implementer DONE_WITH_CONCERNS (commit 4cb35e1; base a32226c; 3032+34 green; B.2.6.1 transcript exact)
Ruling: DeviceSignature alg not fitting the device key (or not allowed) → HOLDER_BINDING_INVALID, matching SD-JWT KB-JWT mapping; IssuerAuth alg not allowed stays ALGORITHM_NOT_ALLOWED — to be fixed in T12 review round — cost if wrong: an audit code differs
Ruling: DeviceResponse version "1.x" accepted (ISO 2nd-ed minor bumps) — cost if wrong: a future incompatible 1.x parses then fails later checks
Ruling: MSO validity outside IssuerAuth cert validity → INVALID_RESPONSE (issuer issued inconsistent data, not a trust failure) — cost if wrong: audit code only
Task 12: review — spec ❌ (ruling 2 DeviceSignature alg mapping), quality needs fixes; 2 Important, 7 Minor, 1 forward note (task-12-review.md)
Ruling: T12 fix round 1 covers 1-8 (all cheap, same files); #9 accepted (record→class safe); #10 (StatusEvaluator lacks status_list.certificate / IssuerAuth chain for ISO §6.5 signer rule) carried to T13 dispatch — T13 widens the evaluator contract
Task 12: fix round 1/5 (DeviceSignature alg→HOLDER_BINDING_INVALID, shared wallet/status/StatusCheck, CborLimits threaded, strict version/date/tdate, key collision; commits 4cb35e1..18d36c6) — re-review: all addressed
Task 12: complete (commits a32226c..18d36c6, review clean)
Ruling: T12 forward note #10 (StatusEvaluator lacks status_list.certificate / IssuerAuth chain for ISO §6.5 signer rule) moves to T14 (wiring), not T13 (decryptor, unrelated) — cost if wrong: mdoc status-list signer not bound to MSO signer until T14
Task 13: implementer DONE (commit e30f10c; base 18d36c6; spec §8.3 vector decrypts; StrictJson extracted from 2 sdjwt files — accepted, dedup)
Task 13: review — spec ✅, quality approved; 2 Minor parked (RSA-OAEP literal test, null input test); Nimbus 10.10 ECDH point-on-curve verified by decompile
Task 13: complete (commits 18d36c6..e30f10c, review clean)
Ruling: earlier "carried to T14" wiring items re-homed — T14 is DCQL, not wiring: StatusPolicy+auditLogSink per provider and the ISO §6.5 mdoc status-list signer rule (StatusEvaluator contract widening) → T19 (WalletIdentityProvider/factory wiring); UNAVAILABLE_ACCEPTED visibility in login audit → T22 (audit) — cost if wrong: none, ordering only
Task 14: implementer DONE_WITH_CONCERNS (commit eb87698; base e30f10c; full 3128+34, sql-init 248 green = Phase 1 gate GREEN)
Ruling: every requested claim is required (DCQL §6.4.1, no claim_sets in PID preset); the realm admin controls requestedClaims (T15/T24), so optional attributes are simply not requested — cost if wrong: a PID lacking a requested optional attribute is refused; claim_sets later if needed
Ruling: SD-JWT credentialType = accepted vct (first accepted aka_vcts entry when matched via aka) — keeps aka-accepted credentials matchable — cost if wrong: one-line change
Ruling: requestedClaims use SD-JWT VC claim names (birthdate, address.locality); T15/T20 must use the same; T18 parses vp_token with StrictJson (carried)
Task 14: review — spec ✅, quality approved; 7 Minor + 4 unverifiable (task-14-review.md)
Ruling: one cheap fix round for minors 1 (null credentialType→INVALID_RESPONSE), 2 (cap dropped names), 3 (JSON-null claim does NOT satisfy a required claim), 4, 6, 8 (check notes for resident_house_number); park 5, 7; carry 9→T15 (acceptedVcts and vct_values from the same PidQuerySpec), 10→T18 (StrictJson vp_token), 11→T20 (both formats answered must agree on identity, or pick one)
Task 14: fix round 1/5 (null credentialType, dropped-name cap, JSON-null not satisfying, vct-wins test, exact assertions, resident_house_number cited; commits eb87698..e85865f) — re-review: all addressed
Task 14: complete (commits e30f10c..e85865f, review clean)
PHASE 1 GATE: GREEN (full 3128+34 + sql-init 248 at eb87698; 3134+34 at e85865f)
Task 15: implementer DONE_WITH_CONCERNS (commit 00e98a6; base e85865f; 3215+34 green)
Ruling: subject "admin number, else link" needs personal_administrative_number requested OPTIONALLY — T21a extends DcqlQueryBuilder with DCQL claim_sets ([requested + personal_administrative_number + issuing_country], [requested]) so wallets without the number still satisfy the query; defaults stay given_name/family_name/birthdate — cost if wrong: subject falls back to linking more often
Ruling: YAML-configured wallet providers resolve accessKeyRef against the master realm (T19) — cost if wrong: YAML users must import the key in master
Ruling: access-cert expiry is a validator error (expired or not-yet-valid → refuse) — to be fixed in T15 review round — cost if wrong: an admin can't save a cert that becomes valid tomorrow
Task 15: review — spec ❌ (cert expiry missing; toStored emits dev private key), quality needs fixes; 4 Important, 5 Minor (task-15-review.md)
Ruling: T15 fix round 1 covers all 1-9. #4: toStored() returns the ProviderSecretKeys Split (secrets never in the plain map). #5: the chain behind accessKeyRef is the single x5c source; a configured accessCertificateChain, if present, must equal it (else field error). #8: spec name accessCertificateKeyRef is refused with "renamed to accessKeyRef" field error, not silently ignored
Ruling: T19 builds x5c from handle.certificateChain() (configured chain only on dev-PEM path) and calls requireValid / validateStored for admin writes — carried to T19
Task 15: fix round 1/5 (cert validity, validateStored per-field, corrupt key, toStored secret-free by construction, single x5c source, renamed-field error; commits 00e98a6..0a16faa) — re-review: all addressed
Task 15: complete (commits e85865f..0a16faa, review clean)
Ruling: T16 Redis index keys for bearer secrets (responseCode, request ids) use SHA-256(value) not the raw value — a Redis read must not yield redeemable codes — cost if wrong: none (lookup hashes first)
Ruling: T16 session-store=queue (PostgreSQL) gets the in-memory store + the multi-replica WARN per plan; a PostgreSQL-backed transaction store is out of scope (final-review note) — cost if wrong: multi-replica queue deployments need sticky sessions for wallet login
Task 16: implementer DONE_WITH_CONCERNS (commit d6d5baa; base 0a16faa; 3292+34 green)
Ruling: keep responseCode hash-only; cross-device gets the code from a new atomic store op issueResponseCode(transactionId, browserBindingHash) → for a VERIFIED CROSS_DEVICE tx with matching binding and no code yet, generate 128-bit code, store its hash, return raw ONCE (second call empty); same-device keeps code from direct_post handler — added in T16 fix round — cost if wrong: one extra store method
Ruling: expired tx looks unknown to byTransactionId; status page says "expired or unknown" (T18) — cost: less specific message
Ruling: redeem never burns on mismatch (burning lets a code-holder cancel the victim's login); in-memory cap 10k refuse-new; Redis refuses create without DB_ENCRYPTION outside dev — accepted
Task 16: review — spec ❌ (issueResponseCode missing), quality needs fixes; 1 Important, 6 Minor (task-16-review.md)
Ruling: T16 fix round 1 covers 1-7; complete() accepts a null code for CROSS_DEVICE (code issued later via issueResponseCode) but requires one for SAME_DEVICE; WARN suppressed under the dev profile; TTL capped at 900s in store validation; carry to T18: redirect_uri only for SAME_DEVICE, realm re-check, full-store IllegalStateException → friendly 503
Ruling: CROSS_DEVICE complete() REQUIRES null code (implementer went stricter than 'accepts null') — the code can only come from the bound browser — cost: none
Task 16: fix round 1/5 (issueResponseCode, race tests, scheduled sweep, atomic cap, TTL 60-900, distinct ids, dev no-WARN; commits d6d5baa..2d557e9) — re-review: all addressed
Ruling: issueResponseCode crash window (codeHash set, index unwritten) accepted — tx self-expires within ≤900s and the user restarts; reversing the order would break "exactly one code" — cost if wrong: rare stuck login until TTL
Task 16: complete (commits 0a16faa..2d557e9, review clean)
Ruling: request-object 'state' is NOT helixState (which must never reach the wallet) — use base64url(SHA-256(transactionId)), deterministic, recomputable when checking the decrypted response — cost if wrong: one derivation change
Task 17: implementer DONE_WITH_CONCERNS (commit c5e3b30; base 2d557e9; 3343+34 green)
Ruling: signatures widened — clientId(cfg, key), invocationUrl(tx, cfg, key, flow, requestUriBase) — x509_hash needs the leaf from the key; accepted — cost: none
Ruling: response enc set = constant {A128GCM, A256GCM} (HAIP: verifiers MUST support both); T18 passes the same constant to VpResponseDecryptor — carried
Ruling: carry to T18: decrypted state == walletState(txId); routes <idpBaseUrl>/realms/<realm>/oid4vp/<alias>/{request|response}/<id>; carry to T19: dev-PEM provider gets a SigningKeyHandle from the configured chain
Task 17: review — spec ✅, quality needs fixes; 1 Important (client_id request-vs-URL mismatch untested), 8 Minor (task-17-review.md)
Ruling: T17 fix round 1 covers 1-8; #2 refuse to sign when exp would be ≤ iat (tx effectively expired) rather than ceil; #4 unknown format → IllegalStateException (validator already refuses unknown formats, so this is defence); #9 accepted (test wallet); carry to T19: under x509_san_dns the handle's leaf must be the validated cert with clientIdHost SAN
Task 17: fix round 1/5 (client_id mismatch + FQDN tests, exp≤iat refusal, exception consistency, format refusal, real-handle signing, x509_hash KAT .crt, strict pctDecode, Oid4vpWalletClient split; commits c5e3b30..7f15dba) — re-review: all addressed
Task 17: complete (commits 2d557e9..7f15dba, review clean)
Ruling: T19 browserBindingHash = SHA-256 of a random per-login secret stored in the HTTP session attribute (not the session id — ids rotate per Task 2); the existing broker controller computes it and passes the 4-arg AuthnRequestContext — cost if wrong: binding breaks across rotation
Ruling: T19 widens StatusEvaluator to carry the issuer chain (SD-JWT x5c / mdoc IssuerAuth x5chain) + optional status_list.certificate so the CWT path enforces ISO §6.5 (list signer chains to MSO signer when no certificate given); existing tests keep passing via an adapter default — cost if wrong: one interface change
Task 19: implementer DONE_WITH_CONCERNS (commit a94fb3d; base 7f15dba; 3418+34 + sql-init 248 green)
Ruling: a STORED wallet provider is bound to its own realm — start() refuses when ctx.realmId ≠ the provider's realm (fail → federation error); YAML providers serve any realm and sign with the master-realm key; T18 also re-checks tx.realmId vs the request realm — to be fixed in T19 review round — cost if wrong: none (cross-realm use was never intended)
Ruling: accepted — WalletIdentityProviders collaborator holder; §6.5 with certificate requires chaining to it AND the provider anchors (stricter); REPLAY for redeem mismatches (redeem can't distinguish, browser sees only error=federation); binding secret for every broker login; wallet icon image → T24
Task 19: review — spec ❌, quality needs fixes; 1 Critical (§6.5 bypass via appended victim anchor in x5chain), 1 Important (realm binding), 7 Minor, 1 unverifiable (task-19-review.md)
Ruling: §6.5 checks run on the PKIX-VALIDATED path + its TrustAnchor, never the raw x5chain; the list signer must chain to the MSO signer's own issuing CA (the cert that issued the IssuerAuth DS cert), not merely share a root — "unrelated trusted CA is refused" wins over the literal shared-root reading; a list naming status_list.certificate must chain to that cert — cost if wrong: issuers using a separate list CA under a shared root must name it via certificate
Ruling: StatusEvaluator default adapter removed — every implementation must take the issuer chain (no silent §6.5 skip); missing validator bean → wallet admin writes fail closed; fromStored normalises protocol (trim + Locale.ROOT); realm import runs validateStored for wallet aliases and refuses with field errors; one log line per refusal (WARN in controller, DEBUG in provider); #9 accepted (not exploitable)
Task 19: fix round 1/5 (§6.5 on ValidatedChain, keyRealm binding, no evaluator default, broker no-leak test, single log, fail-closed validator, normalise, import validation; commits a94fb3d..8f94aca) — re-review (opus, adversarial): all addressed, no bypass constructed
Ruling: parked for final triage/T26 docs — #1 shared-root anchor that issues DS directly lets any list under it pass (document in notes §6.5 + pin test; per-issuer IACA anchors are the norm); #2 CA-cert-as-list-leaf refused (fail closed); #3 persist normalise(protocol); #4 broker start catches RuntimeException for all protocols (→ federation error; arguably better, note in changelog); #5 tx id only at DEBUG
Task 19: complete (commits 7f15dba..8f94aca, review clean)
Ruling: T20 drops age_over_18 from the mapping (T1-era ruling wins over brief text); both formats answered → mapper requires the identity attributes (given_name, family_name, birthdate) to agree after normalisation, else IDENTITY_MISMATCH-style refusal (use INVALID_RESPONSE if no code fits); the SD-JWT presentation is authoritative for the remaining attributes — cost if wrong: refusals when a wallet's two PIDs differ in formatting
Ruling: loa = eIDAS high whenever the presentation verified (verification already requires the chain to validate to the provider's configured PID anchors); documented, no separate anchor list — cost if wrong: no 'substantial' tier for wallet logins
Task 20: implementer DONE (commit 8f531cb; base 8f94aca; 23 new tests, full green)
Ruling: personal_administrative_number stays OUT of brokered attributes; T21a reads it from MatchedPresentations directly for subject resolution — cost: none
Ruling: cross-format conflict and insufficient LoA use INVALID_RESPONSE for now; dedicated codes considered in final triage
FINDING (pre-existing, outside wallet): EidLevelOfAssurance.meetsMinimum treats an unrecognised minimum as always met — wallet guards it; eID/SAML paths still exposed → final review must triage (likely Important)
Task 20: review — spec ❌ (place_of_birth is an object, flat-string mapping drops it), quality needs fixes; 1 Important, 3 Minor, 2 unverifiable
Ruling: T20 fix round 1: place_of_birth → place_of_birth.country/.region/.locality (dotted, like address); tests for scalar mdoc nationality and all address.* rows; verify issuerSubjectDn comes from the validated leaf in both verifiers (add assertions); #6/#7 accepted; wiring of the mapper into the response flow carried to T18 (response endpoint) with T21a subject
Task 20: fix round 1/5 (place_of_birth decomposition, issuerSubjectDn pinned, scalar nationality, all address rows; commits 8f531cb..60a797d) — re-review: all addressed
Task 20: complete (commits 8f94aca..60a797d, review clean)
Ruling: T21 split — T21a now: WalletSubjectResolver + per-realm pepper (encrypted, V-next migration + schema.sql) + WalletLinkService (link store on the existing federated-identity link mechanism, no new parallel table unless none exists) + DcqlQueryBuilder claim_sets for optional personal_administrative_number/issuing_country; T21b after T18: account-console "Link wallet" UI + purpose=link flow + browser e2e
Task 21a: implementer DONE_WITH_CONCERNS (commit 0a55f0b; base 60a797d; 3513+34, sql-init 270 green)
Ruling: three claim_sets options [requested+number+country], [requested+country], [requested] accepted — issuing_country is mandatory in the PID Rulebook so the tuple almost always carries it; locked now before any links exist — cost if wrong: tuple subjects change (no links exist yet)
Ruling: number present + number-subject unlinked + tuple-subject linked → sign in to the tuple-linked user and add the number link (insert-if-absent): upgrade path, prevents a duplicate JIT account — to be done in T21a fix round — cost if wrong: none (tuple link was explicit)
Ruling: carry to T18: Provision → create then link insert-if-absent (never FederatedIdentityStore.link overwrite), never email-link a wallet identity; carry to T21b: controller checks alias belongs to the realm; pepper row on realm deletion → final triage (with verifier_signing_key)
Task 21a: review — spec ❌ (upgrade path missing; stale link → orphaned JIT), quality needs fixes; 2 Important, 6 Minor (task-21a-review.md)
Ruling: T21a fix round 1 covers 1-8. #2: a link whose owner no longer exists in the realm counts as FREE (replace it insert-safely). #5: the tuple field set is fixed by CONFIG, not by the presentation: {issuing_country, family_name, given_name, birthdate} + place_of_birth.* only when the provider requests place_of_birth; a configured field missing from the presentation → SUBJECT_UNAVAILABLE (never a shorter tuple); validator warns that changing the tuple-relevant claims orphans tuple links. #6: route links through the FederatedIdentityPublisher seam like FederatedLoginCompleter (publisher has no JDBC). #7: document dev-plaintext pepper fails closed under DB_ENCRYPTION; realm-deletion cleanup → final triage. #8: take number+country from the same presentation (any presentation carrying both)
Ruling: tuple with place_of_birth configured requires the place_of_birth OBJECT (≥1 part per Rulebook), missing parts encoded as empty strings — the issuer decides which parts a person's PID has, so it stays stable per person — cost if wrong: one-line change
FINDING (pre-existing, outside wallet): AttributeEncryption returns an undecryptable value unchanged (silent plaintext fallback) — affects IdP secrets (T4), signing keys (T5), transactions (T16); wallet pepper now refuses; final review must triage (likely Important)
Ruling: no AMQP adapter exists in this repo (RabbitMQ stripped) — local adapter only is correct
Task 21a: fix round 1/5 (upgrade path, stale links atomic, KATs, normalisation tests, config-fixed tuple, publisher seam, pepper fail-closed, same-presentation pair; commits 0a55f0b..73bcae2) — re-review: all addressed
Ruling: decide() becomes PURE — returns Existing(userId, pendingNumberLink) and the caller claims the number link only after the whole login succeeds (a weak tuple match must never become a permanent number link before MFA/LoA/policy pass) — done now as fix round 2 since no caller exists yet; carry to T18: after JIT provisioning, LINKED_TO_ANOTHER_USER → sign in as the returned owner and delete/never activate the just-provisioned account
Task 21a: fix round 2/5 (pure decide + commitPendingLink, dual-cause pepper message; commits 73bcae2..595559b) — re-review: all addressed
Task 21a: complete (commits 60a797d..595559b, review clean)
Ruling: carry to T18: pass the PendingLink object returned by decide() straight through (never rebuild from client data); call commitPendingLink only after full login success
Ruling: T18 status-endpoint binding uses the T19 session-attribute secret hash (not sha256(session id)); cross-device `next` comes from store.issueResponseCode on the VERIFIED poll; same-device redirect_uri carries the code from complete()
Ruling: T18 response endpoint (wallet's request, no user session) = claimResponse → decrypt (enc constant) → StrictJson vp_token → state==walletState(txId) → DcqlResultMatcher → WalletAttributeMapper → WalletSubjectResolver + WalletLinkService.decide (pure) → store identity + decision (+PendingLink) in verifiedIdentityJson → complete/fail. Browser callback → provider.callback → wallet-aware completion: Existing→sign in; Provision→create user then linkIfAbsent (LINKED_TO_ANOTHER_USER → sign in as owner, delete the fresh user); never email-link; commitPendingLink only after the federated login completes successfully (after any step-up the completer runs; winner≠pending → refuse login)
Ruling: T18 frontend (wallet page) gets an independent UI/UX Playwright review (desktop+mobile) as part of its task review, per the standing frontend rule
Task 18: implementer DONE_WITH_CONCERNS (commit 85dbf9a; base 595559b; 3620+36, sql-init 266 green; screens/ captured)
Ruling: Task 17 ruling wins — helixState never reaches the wallet: the same-device redirect_uri carries only response_code; the callback takes the expected state from the browser session (the binding already ties it) — to be fixed in T18 review round — cost if wrong: none
FINDING (pre-existing, outside wallet, likely Important/security): federated logins never get the post-broker MFA step-up — MfaEnabledCondition reads an empty SecurityContext when FederatedLoginCompleter starts the flow — surface to user; final review must triage
Ruling: accepted — T19 redirect made context-relative (one T19 test line edited to match); JIT race end-to-end covers the unique-username shape, link-lost shape unit-tested
Task 18 UI/UX review: Needs fixes — 3 Important (mobile CTA order, failed state alert styling/role, no 'wallet opened' feedback), 3 Minor (focus to retry, spinner, icon capture) (task-18-uiux-review.md); to be folded into the T18 fix round with the code review
Task 18: code review — spec ❌ (helixState still in wallet-facing redirect_uri), quality needs fixes; 2 Important (state leak; unthrottled /broker start fills 10k store → DoS), 11 Minor (task-18-review.md)
Ruling: T18 fix round 1 covers code 1-9, 11, 13 + UI/UX 1-6. #2: rate-limit the broker start for wallet aliases (reuse RateLimitFilter) AND one live wallet tx per browser binding (a new start fails the previous one). #8: body limit for every method on /oid4vp/** (not only POST). #12 accepted (malformed form refused pre-claim, documented). #10 (X-Forwarded-For trust in RateLimitFilter, pre-existing, all endpoints) → final triage. UI: mobile puts "Open wallet app" first and QR collapsed/secondary; failed/expired uses .hx-alert-error + role=alert and moves focus to retry; status exposes WALLET_OPENED (REQUEST_FETCHED) to the bound browser with copy change; subtle reduced-motion-safe spinner; capture the login-page button screenshot
Ruling: accepted — body-limit filter before rate limit (throttled POST read ≤256 KB before 429; bounded); JIT stale-username retries once with a suffixed username
Task 18 UI/UX re-review: SHIP — all 6 addressed, contrast/tap targets measured; NL-copy screenshots unverified (minor, final triage)
Task 18: fix round 1/5 (commits 85dbf9a..dfefa2d) — code re-review: all addressed BUT 1 new Important (a pending commit that THROWS leaves the session authenticated as the tuple user) + 3 Minor
Ruling: T18 fix round 2: exception from FederatedLoginCommit.commit = refusal (clearContext + invalidate + error redirect) in FederatedLoginCompleter AND FlowController, with throwing-committer tests; isWalletStart swallows every RuntimeException (→ not a wallet start); add one e2e PUT→405 through the real filter chain; concurrent-start leak accepted (rate-bounded); %-encoded path bypass of /oid4vp filters → final triage with #10
Task 18: fix round 2/5 (throwing commit = refusal in both paths, isWalletStart swallows registry errors, real-chain PUT→405 e2e, QR test decoder PURE_BARCODE; commits dfefa2d..793bdc9) — re-review: all addressed
Ruling: parked — Error (not RuntimeException) from a committer escapes with session persisted (JVM-level, don't catch Error); WalletE2eFixture javadoc overstates "what a phone would scan"
Task 18: complete (commits 595559b..793bdc9, code review clean + UI/UX SHIP)
Ruling (USER, 2026-10-12): lighter process from T21b onward — one review per task, Minor findings parked to final review (no fix round for minors), cheaper models for mechanical work
Task 21b: implementer DONE_WITH_CONCERNS (commit c52719b; base 793bdc9; 3915+39, sql-init 282 green; link-* screens)
Task 21b: review (single combined, lighter process) — spec ✅, quality needs fixes; 1 Important (JSON /account/identities unlinks wallet w/o reauth, one row only, shows HMAC), 10 Minor parked (task-21b-review.md)
Ruling: fix I1 only — wallet aliases are excluded from GET /account/identities and DELETE for a wallet alias is refused (409, pointing at the console flow, which has step-up + audit + unlinks all rows); minors M1-M10 parked to final review (M1/M2 → document linking-CSRF/QR-relay limits in docs; consider "wallet linked" notification)
Task 21b: fix round 1/5 (JSON identities API excludes wallet aliases, DELETE → 409; commit 7269391) — controller spot-check OK (lighter process: no separate re-review for a 2-file fix with tests); minor parked: isWallet catches only IllegalArgumentException
Task 21b: complete (commits 793bdc9..7269391)
Task 22: implementer DONE (commit 25c9688; base 7269391; full green)
Ruling: subject hash no longer logged (reverses the T21a "log the hash only" allowance) — T22's hygiene contract wins; the hash is a stable cross-login identifier — cost: operators correlate via audit transactionId instead
Ruling: WALLET_STATUS_CHECK_FAILED keeps its {reason, statusListHost, decision} detail shape — parked to final review
Task 22: review — spec ❌, 2 Critical (missing FAILURE events on completer refusals + wrong-realm branch; subject hash still logged in WalletLinkService), 4 Important (parse-failure unaudited; hygiene test not a real booted e2e, sd-jwt only, no link/JIT path), 4 Minor parked — fix round 1 covers 1-6
Task 22: fix round 1/5 (one FAILURE per refusal via a single helper, subject hash + provisioned username no longer logged, booted hygiene e2e both formats + JIT + upgrade + LINK; commit b587989; full verify 3956 tests 0 failures) — committed by controller after agent stopped
Task 22: complete (commits 7269391..b587989)
Ruling: T23 — no Phase 2 PR/push (standing ruling); write the PR description into docs/superpowers/plans/…-phase2-summary.md instead; run k3d gate only if k3d+docker are available locally; CodeQL triage only if the codeql CLI is installed (else note it for the GitHub run after push)
SIDE WORK (USER 'fix all', 2026-10-12): 4 pre-existing security findings fixed on branch fix/pre-1.0-security (worktree <local> from origin/master c2ad6a0); wallet branch must merge/rebase these before its final review (wallet guards for meetsMinimum/AttributeEncryption may become redundant)
Task 23: DONE (commits b587989..e407d8f: acceptance matrix 24 tests both formats, release-gate flyway dotted-version fix, Phase 2 summary) — full verify 3980+39, sql-init 328, k3d gate 38/38 + flyway V77 — PHASE 2 GATE GREEN; lighter process: controller spot-check, no separate review (tests/docs/script only)
Ruling: callback double-redeem over real HTTP surfaces as STATE_MISMATCH (broker session state consumed first) — defence in depth, document in SECURITY-REVIEW (T26)
Task 23: complete
Task 24: implementer DONE_WITH_CONCERNS (commit 28486f6; base e407d8f; npm 346 + build OK, mvn 3993+39, sql-init 353; 48 console-* screens)
Task 24: review (combined) — spec ❌, 2 Important (console vs server mdoc-claim rule mismatch; wizard inline styles + 640px cap), 14 Minor parked; fix round 1 = I1, I2 + M1 (if the PAGE scrolls sideways at 390, make Tabs scroll inside their own wrapper); then an independent UI/UX sign-off on the recaptured screens (house rule)
Task 24: fix round 1 (mdoc claim rule matches server, wizard inline styles → hx-wizard classes w/o cap, Tabs keep active tab in view; commit 4cee814) — independent UI/UX sign-off: SHIP; parked: 21 pre-existing inline styles in other providers' wizard sub-forms, Choice row + .hx-btn < 44px console-wide, 14 code-review minors
Task 24: complete (commits e407d8f..4cee814)
Task 25: DONE (commit c33be2c: TestWalletCli test-scope, exec plugin unbound, e2e/wallet-demo/seed.sh idempotent, sandbox README walkthrough; LIVE run both flows + both formats + account linking, acr=eIDAS high; jar contains no testwallet) — lighter process: no separate review (test/docs only)
FINDING (final triage, likely Important, not wallet-specific): admin-API/console-managed identity providers never reach the live registry unless helix.federation.store.enabled=true (default false) — every console-created provider may be inert by default; e2e fixtures bypass it by reloading the registry
Task 25: complete
FINDING detail: store refresh at startup loads only helix.federation.store.realm (default master) — providers stored in other realms may not load at boot; final review must verify per-realm loading for stored wallet providers
Task 26: DONE (commit c86cfb8; full verify 3996+39; WalletGdprE2eTest RED first) — docs/GDPR, lighter process: no separate review (final review covers it)
Task 26: complete
ALL TASKS COMPLETE — next: final whole-branch review (most capable model)
FINAL REVIEW: Ready after fixes — 3 Important (multi-realm store loading/alias collision/login buttons; step-up wallet logins never audited; %-encoded path bypasses wallet rate+body limits) + docs; merge interactions A-E with fix/pre-1.0-security (A: EUDI_WALLET missing in canonicalMinimum → every wallet login refused)
Ruling: the %-encoded path bypass is PRE-EXISTING on master (e.g. /l%6Fgin skips the login brute-force limit) → fix it first on fix/pre-1.0-security (into rc.8), then merge that branch into feature/eudi-wallet as part of the single final fix dispatch with items 1, 2, 4 and merge items A-E
Security branch: encoded-path bypass did NOT reproduce — StrictHttpFirewall rejects any '%'/';'/'//' path with 400 before handlers; regression guard test 22889b9; full 2615+32, sql-init 257 green
Ruling: final-review item 3 (wallet limits via encoded path) is moot for the same reason — covered by a wallet regression guard test in the final fix dispatch, no production change
FINAL FIX: DONE (237fbf9 multi-realm registry keyed by (realm, alias) + store default ON + all-realm startup; b2693a2 step-up audit; a55fa34 encoded-path guard; 0215cb2 docs/copy; bae6206 MERGE fix/pre-1.0-security; 29373f6 pepper message post-merge) — full 4199+39, sql-init 388, k3d 38/38, WalletStepUpE2eTest 3/3
Ruling: accepted — (realm, alias) keying (side effect: console-created OIDC/SAML/eID providers now realm-scoped on login pages — a fix); store.enabled default true (AMQP reason obsolete); abandoned step-up emits no FAILURE (documented); broker session attrs keyed by alias only → concurrent same-alias logins in two realms in one browser fail closed (defer)
FINAL RE-REVIEW: ready to finish — 3 Minor parked (cross-realm named(alias) in account/GDPR, refresher build outside lock, recovery-codes page after refused commit)
