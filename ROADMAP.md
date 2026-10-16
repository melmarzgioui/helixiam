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
- Terraform provider resource coverage (realm, agent, flow; generic identity-provider connections beyond
  the wallet one). Done: `helix_wallet_identity_provider` (the EUDI wallet connection, see below).
- Live eID (DigiD/eHerkenning/eIDAS) round-trip validation against real peers.
- Federation/config import tooling.
- **EUDI Wallet (OpenID4VP verifier) Phase 4 — interop and stretch** (separate plan, written once Phase 3 of
  `docs/superpowers/specs/2026-10-09-eudi-wallet-openid4vp.md` merges): ~~an OpenID Foundation conformance run
  (OpenID4VP 1.0 + HAIP 1.0 verifier profile) with a recorded pass/deviation list~~ — done 2026-10-15, see
  [`docs/compliance/oid4vp-conformance/README.md`](docs/compliance/oid4vp-conformance/README.md); interop against at least one national test
  wallet (the EU reference wallet is done, see below); ~~the W3C Digital Credentials API (`dc_api`/`dc_api.jwt`)
  as the ecosystem-recommended cross-device path (today only redirect same-device and QR cross-device exist, and
  ARF guidance recommends against the latter for conformant EU wallets — see `docs/eudi-wallet.md` §8)~~ — done
  2026-10-15 (signed and unsigned requests, `dc_api.jwt`, opt-in per connection; see `docs/eudi-wallet.md` §12).
  Still open there: a live run with a real wallet over the DC API (not yet done, see §12.6) and multi-signed
  requests; ~~an `EuTrustedListSource` (ETSI TS 119 612) so trust anchors update automatically instead of being
  pasted PEM~~ — done (ETSI TS 119 612 XML and TS 119 602 LoTE JSON, see `docs/eudi-wallet.md` §7.3); the Terraform
  resource for the wallet identity-provider connection is done (`helix_wallet_identity_provider`,
  `terraform-provider-helix/README.md`); and ~~a separate plan for the step-up/verify-only
  flow (`subject.strategy=NONE`), deliberately left out of the initial implementation (maintainer decision 4)~~ —
  done 2026-10-15: the `eudi-wallet-verify` flow step with `acr_values` step-up, see
  [`docs/superpowers/specs/2026-10-15-wallet-verify-only-design.md`](docs/superpowers/specs/2026-10-15-wallet-verify-only-design.md)
  and `docs/eudi-wallet.md` §13 (its deferred items: a standalone RP "verify attributes" API, attribute-matching
  binding, `verified_claims` in userinfo/access tokens, step-up without re-entering the first factor).
- **EUDI Wallet follow-ups** (from the final review of the wallet branch):
  - Done (2026-10-15): **interop against the EU reference wallet** and **a third-party mdoc DeviceAuth vector**. The
    EU Digital Identity Wallet reference app (2026.10.43-Demo) signed in with SD-JWT VC and mdoc PIDs from the EU test
    issuer, same-device and cross-device, with no product change; its presentations, with their request objects and
    decryption keys, are offline test vectors, and DeviceAuth is verified over the real SessionTranscript
    (`docs/compliance/eudi-reference-wallet/README.md`). This was the one item listed as needed before the
    "Experimental" label is lifted. **Done (2026-10-15): the maintainer has lifted it** — together with the OpenID
    Foundation conformance self-run and the internal pentest, the core OpenID4VP verifier (redirect same-device, QR
    cross-device, `direct_post.jwt`, SD-JWT VC and mdoc) is now **Beta** in `docs/FEATURES.md` (see `CHANGES-1.0.md`,
    rc.11). Still untested: `x509_san_dns` with the reference wallet (the test registrar's access certificates have no
    dNSName) and its QR scanner (the QR content was passed by an Android intent); no national wallet has been tested.
    The newer Digital Credentials API and verify-only mode (below) are **Preview**, not Beta: the DC API has not been
    tested with a real wallet.
  - Done: a PostgreSQL wallet transaction store, cross-replica identity-provider refresh, and the "wallet linked"
    notification (see `CHANGES-1.0.md`, rc.9).
  - Done, from the conformance run (`docs/compliance/oid4vp-conformance/README.md`):
    - request objects may be fetched again until the response arrives (ruling on D2);
    - HAIP's DCQL `trusted_authorities` (`aki`) query is sent, derived from the configured trust anchors;
    - the status-list connect-timeout test no longer depends on the network.
  - Still open: file the nonce-entropy issue with the suite
    (`docs/compliance/oid4vp-conformance/upstream-issue-nonce-entropy.md`).
  - Partly done: **`EuTrustedListSource`** — trust anchors from signed ETSI TS 119 612 (XML) and ETSI TS 119 602
    (LoTE JSON) lists, refreshed automatically with a fail-safe grace period (`docs/eudi-wallet.md` §7.3). Still open:
    automatic rotation of a list's own signer (the EU LOTL "pivot" chain; signers are pinned by hand today),
    following LoTE pointers, XAdES signed-properties checks, realm export/import of trusted list sources, and a
    production EU list of PID providers to point at (only the EUDI test list and the Commission's acceptance list are
    published as of 2026-10-15).
  - Done (2026-10-15): **realm deletion cleanup.** `realm_wallet_pepper`, `verifier_signing_key` and
    `wallet_transaction` (and the realm's trusted list sources) now get removed with the realm (a `realm_config_delete_wallet_secrets` trigger on
    `realm_config`, Flyway V85) — not a foreign key: all three are routinely written for a realm id that has no
    `realm_config` row yet (the admin wallet/identity-provider APIs never require one), so a real FK would turn a
    working insert into a constraint violation. There is still no admin realm-delete operation; this closes the gap
    it would otherwise have (a realm created again under the same id silently inheriting the
    previous realm's verifier access key and pepper) for whichever path removes a `realm_config` row. See
    `docs/eudi-wallet.md` §2.5.
- **Post-1.0 platform upgrades** — each a planned major upgrade with its own test pass, not a weekly
  bump (Dependabot ignores these majors until then): Apache Santuario xmlsec 4, Java 25 LTS runtime; in the
  console React 19 and TypeScript 6 (Vite 8, `@vitejs/plugin-react` 6, Storybook 10 and Vitest 5 are in already).
  Done: Jackson 3 for the application code (Spring Boot's deprecated `spring-boot-jackson2` module removed); Express 5,
  `openid-client` 6 and `otplib` 13 in the sandbox RP; cosign 3 (`cosign-installer` 4) in the release workflow (see
  `CHANGES-1.0.md`).
- **Realm signing keys** — done (after rc.11): bring your own key and CA-signed certificate, a CSR flow (the private
  key stays on the server), staged rollover (PENDING → ACTIVE → retained), ES256 realms, `x5c` in the JWKS, CA
  certificates in SAML metadata and daily certificate-expiry warnings (see
  `docs/superpowers/specs/2026-10-16-byo-realm-keys-design.md`). Still open: HSM/KMS-held keys (`pkcs11:` / `kms:`),
  scheduled automatic rotation, ACME renewal, P-384/P-521 and EdDSA keys, encrypted private-key PEM on import.

## Later

_TODO: longer-term direction — to be shaped with the maintainers and community._

Dates are intentionally omitted until the maintainer team and release cadence are set
(see [`GOVERNANCE.md`](GOVERNANCE.md)).
