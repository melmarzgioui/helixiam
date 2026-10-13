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
  (OpenID4VP 1.0 + HAIP 1.0 verifier profile) with a recorded pass/deviation list; interop against the EU
  reference wallet plus at least one national test wallet; the W3C Digital Credentials API (`dc_api`/`dc_api.jwt`)
  as the ecosystem-recommended cross-device path (today only redirect same-device and QR cross-device exist, and
  ARF guidance recommends against the latter for conformant EU wallets — see `docs/eudi-wallet.md` §8); an
  `EuTrustedListSource` (ETSI TS 119 612) so trust anchors update automatically instead of being pasted PEM; a
  Terraform resource for the wallet identity-provider connection; and a separate plan for the step-up/verify-only
  flow (`subject.strategy=NONE`), deliberately left out of the initial implementation (maintainer decision 4).
- **EUDI Wallet follow-ups** (from the final review of the wallet branch):
  - **Before the "Experimental" label is lifted:** verify an mdoc DeviceAuth made by a third party. The mdoc decoding
    path is now checked against EU reference wallet DeviceResponses (IssuerAuth, MSO, digests), but no third-party
    vector with its SessionTranscript was available under a usable licence (ISO 18013-5 Annex D is ISO copyright and
    uses `deviceMac`), so DeviceAuthentication is still checked only against the OpenID4VP B.2.6.1 transcript and the
    in-repo test wallet. A capture from a real EU wallet against this verifier (Phase 4) closes it. Also decide whether
    to accept a short (leading-zero-stripped) device-key coordinate, which one reference credential has; today it is
    refused, as RFC 9053 requires.
  - Done: a PostgreSQL wallet transaction store, cross-replica identity-provider refresh, and the "wallet linked"
    notification (see `CHANGES-1.0.md`, next release).
  - Realm deletion cleanup: delete the realm's wallet pepper (`realm_wallet_pepper`) and verifier keys
    (`verifier_signing_key`) with the realm. No realm-delete operation exists today; without this, a realm created
    again under the same name would inherit the previous realm's verifier access key and pepper.
- **Console debt:** 21 inline `style=` attributes in other providers' wizard sub-forms (the wallet form has none;
  the wallet branch removed 4), plus hundreds elsewhere in the console (AccountApp, SecurityTab, AppShell, ...);
  move them to classes under the console design-system rule.
- **Post-1.0 platform upgrades** — each a planned major upgrade with its own test pass, not a weekly
  bump (Dependabot ignores these majors until then): Spring Boot 4 / Spring Security 7 (incl. SAML2
  service provider 7), springdoc 3, Flyway 12+, Apache Santuario xmlsec 4, Java 25 LTS runtime; in the
  console React 19, Vite 7+/`@vitejs/plugin-react` 5+, Storybook 9+, TypeScript 6+, Vitest 3+; in the sandbox RP Express 5,
  `openid-client` 6, `otplib` 13; cosign 3 (`cosign-installer` 4) in the release workflow.

## Later

_TODO: longer-term direction — to be shaped with the maintainers and community._

Dates are intentionally omitted until the maintainer team and release cadence are set
(see [`GOVERNANCE.md`](GOVERNANCE.md)).
