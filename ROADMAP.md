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

## Later

_TODO: longer-term direction — to be shaped with the maintainers and community._

Dates are intentionally omitted until the maintainer team and release cadence are set
(see [`GOVERNANCE.md`](GOVERNANCE.md)).
