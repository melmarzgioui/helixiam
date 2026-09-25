# CHANGES — road to a credible 1.0

Running log for branch **`overhaul/1.0-gaps`**. Every finding, fix, commit, deferred item and open
question. Newest first within each phase.

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
