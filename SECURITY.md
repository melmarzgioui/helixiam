# Security Policy

HelixIAM is an identity provider — it issues and verifies the credentials other systems trust.
We take vulnerability reports seriously and ask that you report them privately rather than through
a public issue.

## Project maturity — please read before relying on this in production

**HelixIAM is pre-1.0 and has not yet undergone an independent third-party security review or
penetration test.** It implements standard protocols (OAuth2, OIDC, SAML 2.0) and follows common
hardening practices, but for an authentication/authorization server this is exactly the kind of
software where "it looks right" is not the same as "it has been independently verified." Treat it
accordingly:

- Do not deploy it as the sole gate in front of sensitive systems without your own security review
  first.
- Expect breaking changes and security-relevant fixes as the project matures toward a 1.0 release.
- If you perform your own audit or pen test, we would welcome a report — see below.

## Security testing to date

The project has undergone **internal** security work: an adversarial self-review
([`helix-iam-server/SECURITY-REVIEW.md`](helix-iam-server/SECURITY-REVIEW.md)) and internal
automated security testing runs (SAST + live DAST + direct-validator attack harnesses) recorded
under [`docs/security/`](docs/security/). These are **internal tests on our own code — not an
independent third-party penetration test** — and do not substitute for one. An independent
third-party audit and penetration test remain **required before a 1.0 / production release**.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: **`security@helixiam.com`** — *(TODO: configure a real, monitored security-contact
address before accepting external reports; this is a placeholder and does not currently receive
mail.)*

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce (a minimal proof of concept, if you have one).
- The affected component (`helix-iam-server`, `helix-dashboard`, etc.) and version/commit.

We aim to acknowledge reports and work with reporters on a coordinated disclosure timeline. Please
give us a reasonable amount of time to investigate and release a fix before any public disclosure.

## Supported versions

HelixIAM does not yet have a tagged 1.0 release or a formal support/backport policy. Until a
release process is established, treat the `main` branch as the only supported line — apply
security fixes by updating to the latest commit on `main`. This section will be updated with a
concrete version-support table once versioned releases begin.

## Build & supply-chain security

Every push and pull request runs in GitHub Actions (`.github/workflows/`):

- **Build + test** — `helix-iam-server` (`mvn -B clean verify`, with Testcontainers Postgres),
  `helix-dashboard` (vitest + build), and `terraform-provider-helix` (`go vet` + `go test`).
- **CodeQL** static analysis (`security-extended`) for Java and JavaScript/TypeScript, results in
  GitHub code scanning.
- **Trivy** scans the source for vulnerable dependencies (Maven/npm/Go), misconfigurations
  (Dockerfiles, Helm, compose) and secrets, also reported to code scanning; a weekly schedule
  surfaces newly-disclosed CVEs against `main`.
- **Dependabot** keeps dependencies and pinned action SHAs current (Maven, npm, Go modules,
  GitHub Actions, Docker).
- All workflow actions are **pinned to a full commit SHA** (the version is in a trailing comment).

Starting with the first tagged release, the release workflow builds the server image, **signs it with
[cosign](https://github.com/sigstore/cosign) keylessly** (Sigstore OIDC — no long-lived keys),
generates an **SPDX SBOM**, **attests the SBOM to the image**, and attaches the SBOM to the GitHub
release. (No release is tagged yet, so no signed image exists on a registry at time of writing.)

## Scope

This policy covers the code in this repository (`helix-iam-server`, `helix-dashboard`,
`helix-sandbox-rp`, `helix-mcp-demo`, `terraform-provider-helix`). Vulnerabilities in third-party dependencies should generally be
reported upstream as well; let us know here if a dependency vulnerability affects how HelixIAM
uses it.
