# Roadmap

High-level direction. Detailed, in-flight work toward 1.0 is tracked in
[`CHANGES-1.0.md`](CHANGES-1.0.md) and on the `overhaul/1.0-gaps` branch.

## Now — toward a credible 1.0

The gate for 1.0 is "every public claim is true, it runs in five minutes, and the security-critical
paths are hardened and tested."

- **Adoption & honesty** — Dockerfile, docker-compose, Helm chart; an honest feature matrix
  (`docs/FEATURES.md`) with Stable/Beta/Experimental/Planned labels; repo hygiene.
- **Secure defaults** — production-safe defaults without reading every comment, each with a migration
  note and an override.
- **Agent delegation hardening** — the differentiator, made airtight (consent/audience binding, actor
  authentication, delegation-chain limits, cross-realm isolation, RFC 8693/8707 conformance,
  kill-switch on already-minted tokens).
- **CI, supply chain & releases** — full test matrix, CodeQL, dependency and image scanning, signed
  multi-arch images, SBOMs, Helm and Terraform provider releases.
- **Independent third-party security audit + penetration test** — required before tagging 1.0.

## Next — after 1.0

- SDK published as its own package.
- Terraform provider resource coverage (realm, identity provider, agent, flow).
- Live eID (DigiD/eHerkenning/eIDAS) round-trip validation against real peers.
- Federation/config import tooling.
- **EUDI Wallet (OpenID4VP verifier) Phase 4 — interop and stretch** (separate plan, written once Phase 3 of
  `docs/superpowers/specs/2026-10-09-eudi-wallet-openid4vp.md` merges): an OpenID Foundation conformance run
  (OpenID4VP 1.0 + HAIP 1.0 verifier profile) with a recorded pass/deviation list; interop against at least one
  national test wallet (the EU reference wallet is done, see below); the W3C Digital Credentials API (`dc_api`/`dc_api.jwt`)
  as the ecosystem-recommended cross-device path (today only redirect same-device and QR cross-device exist, and
  ARF guidance recommends against the latter for conformant EU wallets — see `docs/eudi-wallet.md` §8); an
  `EuTrustedListSource` (ETSI TS 119 612) so trust anchors update automatically instead of being pasted PEM; a
  Terraform resource for the wallet identity-provider connection; and a separate plan for the step-up/verify-only
  flow (`subject.strategy=NONE`), deliberately left out of the initial implementation (maintainer decision 4).
- **EUDI Wallet follow-ups** (from the final review of the wallet branch):
  - Done (2026-10-15): **interop against the EU reference wallet** and **a third-party mdoc DeviceAuth vector**. The
    EU Digital Identity Wallet reference app (2026.10.43-Demo) signed in with SD-JWT VC and mdoc PIDs from the EU test
    issuer, same-device and cross-device, with no product change; its presentations, with their request objects and
    decryption keys, are offline test vectors, and DeviceAuth is verified over the real SessionTranscript
    (`docs/compliance/eudi-reference-wallet/README.md`). This was the one item listed as needed before the
    "Experimental" label is lifted; lifting it is a maintainer decision. Still untested: `x509_san_dns` with the
    reference wallet (the test registrar's access certificates have no dNSName) and its QR scanner (the QR content was
    passed by an Android intent).
  - Done: a PostgreSQL wallet transaction store, cross-replica identity-provider refresh, and the "wallet linked"
    notification (see `CHANGES-1.0.md`, next release).
  - Realm deletion cleanup: delete the realm's wallet pepper (`realm_wallet_pepper`) and verifier keys
    (`verifier_signing_key`) with the realm. No realm-delete operation exists today; without this, a realm created
    again under the same name would inherit the previous realm's verifier access key and pepper.
- **Post-1.0 platform upgrades** — each a planned major upgrade with its own test pass, not a weekly
  bump (Dependabot ignores these majors until then): Jackson 3 for the application code (the server
  runs on Spring Boot 4.1 / Spring Security 7.1 / springdoc 3 / Flyway 12 since the Boot 4 upgrade, with Jackson 2 kept
  through the deprecated `spring-boot-jackson2` module), Apache Santuario xmlsec 4, Java 25 LTS runtime; in the
  console React 19 and TypeScript 6 (Vite 8, `@vitejs/plugin-react` 6, Storybook 10 and Vitest 5 are in already); in the sandbox RP Express 5,
  `openid-client` 6, `otplib` 13; cosign 3 (`cosign-installer` 4) in the release workflow.

## Later

_TODO: longer-term direction — to be shaped with the maintainers and community._

Dates are intentionally omitted until the maintainer team and release cadence are set
(see [`GOVERNANCE.md`](GOVERNANCE.md)).
