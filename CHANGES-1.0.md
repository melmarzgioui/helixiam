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
- **Still to do in Phase 2:** **L5** legacy-crypto (AES/ECB) re-encryption migration + remaining-row
  counter — a careful data migration across the 8 encrypted-column entities; deserves its own focused
  change (approach: a one-time job that detects legacy-format values, re-encrypts to AES/GCM, and exposes
  a gauge of rows still on the legacy path so the fallback can be dropped later). Reconcile Flyway vs
  `schema.sql` (O5, likely linked to O1). Sweep remaining user-facing `kubedna`/`kubeiam` strings.

## Phase 1 — Agent delegation  *(in progress; most careful)*
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

- **Still to do in Phase 1 (both large — will bring the design to you before landing):**
  - **Gap 2 — actor-token client authentication / DPoP.** The `actor_token` is today a pure bearer:
    anyone holding an agent's token can act. Fix needs client authentication (client-secret / mTLS /
    private-key-jwt) or DPoP proof-of-possession on the exchange. This is a **breaking change** for
    existing agent callers, so it needs the strict-default + explicit opt-out pattern and a migration
    note — I'll propose the exact shape before touching it.
  - **Gap 7 — kill-switch invalidates already-minted tokens.** Disabling an agent stops *new* mints but
    already-issued delegated JWTs stay valid until expiry. Fix is an introspection-path (or short-TTL +
    revocation-list) check of live agent status; touches the token-validation path, so it needs its own
    focused change.
  - Apply the same review to `WorkloadIdentityTokenController` (the WIF exchange sibling).

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
