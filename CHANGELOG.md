# Changelog

All notable changes to HelixIAM are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once a 1.0 line is tagged.

## [Unreleased]

Work toward a credible 1.0 is tracked on the `overhaul/1.0-gaps` branch and in
[`CHANGES-1.0.md`](CHANGES-1.0.md).

### Added
- **EUDI Wallet (OpenID4VP verifier) — Experimental.** Sign in with an EU Digital Identity Wallet (PID, SD-JWT VC
  and/or ISO mdoc) as a per-realm identity-provider connection, same-device and cross-device (QR) flows, Token
  Status List revocation checking. See [`docs/eudi-wallet.md`](docs/eudi-wallet.md) and `docs/FEATURES.md`.

### Changed
- **Identity-provider secrets are write-only in the admin API (API change).** `GET /admin/realms/{realm}/identity-providers`
  (list and by alias) no longer returns secret values (OIDC `clientSecret`, eID SP private keys, the LDAP bind
  password, wallet keys); it returns `"<key>Set": true|false`. On a write, an absent or blank secret keeps the stored
  one, a value replaces it, `"clear<Key>": "true"` removes it. Secrets are now encrypted at rest (`secret_json`,
  Flyway `V75`/`V75.1`). **Clients that read secrets back (for example a Terraform provider or a sync script)
  must stop doing so; a plan that compares the returned secret will always show a diff.** Realm exports mask them.
- **ID tokens carry `acr`** for brokered eID (SAML) logins whose provider asserted a recognised level of assurance,
  and for EUDI Wallet logins (`http://eidas.europa.eu/LoA/high`). It is taken only from the connector's validated
  value, never from a provider attribute, and is cleared on every new login.
- **A federated login gets a new session id** (OIDC, SAML, eID, wallet), at completion and again after a post-login
  step-up; on the `queue` session store the pre-rotation session row is deleted.
- **Console-created identity providers work in every realm.** `helix.federation.store.enabled` now defaults to
  `true` (env `HELIX_FEDERATION_STORE_ENABLED`; it was `false`), the startup load covers every realm (the
  `helix.federation.store.realm` setting is gone), an admin write refreshes only its own realm, and stored providers
  are keyed by realm and alias, so two realms may use the same alias. A realm's login page lists only its own
  providers and the YAML/bean ones. Set the flag to `false` to keep the old "saved but not loaded" behaviour.
- **Broker start errors.** When a provider throws while starting a login (any protocol), or the alias is unknown in
  the realm, the browser is sent to `/login?error=federation` instead of an error page.
- Internal security-test reports relabelled and moved to `docs/security/`; clearly marked as internal
  automated testing, not an independent third-party penetration test.

### Removed
- Local tooling config (`.claude/`) removed from the repository.

### Security
- Nimbus JOSE + JWT pinned to **10.10** (CVE-2025-53864, unbounded JSON nesting → denial of service). Spring
  Authorization Server 1.5.8 brought in the affected 9.47, so this also concerns already-released versions.
- See [`helix-iam-server/SECURITY-REVIEW.md`](helix-iam-server/SECURITY-REVIEW.md) and
  [`docs/security/`](docs/security/) for the internal review and testing to date. An independent
  third-party audit and penetration test remain required before a 1.0 release.

---

_No tagged releases yet. This section will list versioned releases once the release process
(Phase 4) is in place._
