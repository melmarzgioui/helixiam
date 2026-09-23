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

## Phase 3 — Runnable in 5 minutes  *(not started)*
Confirmed absent: `helix-iam-server/Dockerfile`, root `docker-compose.yml`, `deploy/helm/`. Next up.

## Phase 6 — Claims vs reality  *(not started)*
`docs/FEATURES.md` to be built. Early flags: SDK npm package `@helixiam/sdk` not published (lives in
`helix-dashboard/src/sdk`); Terraform provider has only `application`+`role` resources; "Keycloak
importer" import path unverified.

## Phase 2 — Secure defaults  *(not started; note)*
Recon shows H1/H2 are **already** partly addressed (DB_ENCRYPTION empty default + loud banner;
`AttributeEncryption` now fails closed). I will verify actual startup behavior against the
"fail startup outside dev unless `HELIX_ALLOW_PLAINTEXT_SECRETS=true`" requirement before changing it,
rather than assuming it is open.

## Phase 1 — Agent delegation  *(not started; most careful)*
Each sub-item (consent/audience binding, actor client-auth/DPoP, chain-depth limit, cross-realm key
isolation, RFC 8693 conformance, `resource`/RFC 8707 allow-list, kill-switch on minted tokens) will be
verified in code first, then fixed with a regression test, and any token/endpoint/config-key impact
brought to you before it lands.

---

## Open questions / to raise
- **O1** `resources/dummy/dummy.json` — what does `ServiceProviderService` use it for? Remove, or is it
  a real seed/default? (Phase 5)
- **O2** Real maintainer names, decision process, and company/legal details for `GOVERNANCE.md` and the
  website About/Trust pages (Phase 5/7) — placeholders in place until you provide them.
- **O3** Third-party pentest before 1.0: SECURITY-REVIEW says it is **required** and the internal tests
  do not discharge it. Recommendation stands: yes, commission one before tagging 1.0.
