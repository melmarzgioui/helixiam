# Contributing to HelixIAM

Thanks for your interest in contributing. This document covers how to build and test the code,
how to propose a change, and the legal basics.

## Ground rules

- All contributions are accepted under the project's license, **Apache License 2.0** (see
  [LICENSE](LICENSE)). By submitting a pull request you agree your contribution is licensed under
  those terms.
- We use a **Developer Certificate of Origin (DCO)** instead of a separate CLA. Every commit must
  be signed off, certifying you wrote it or otherwise have the right to submit it under the
  project's license:

  ```bash
  git commit -s -m "your message"
  ```

  This adds a `Signed-off-by: Your Name <you@example.com>` trailer. The DCO text is at
  <https://developercertificate.org/>.

## Building and testing

### helix-iam-server (Java / Spring Boot, Java 21 + Maven)

```bash
cd helix-iam-server
mvn -o clean test        # runs the test suite; Testcontainers starts its own PostgreSQL
```

Docker must be running locally (Testcontainers needs it for the integration tests). Redis is
**not** required for tests — they run with `spring.session.store-type=none`.

To build the runnable jar without running tests:

```bash
mvn -o clean package -DskipTests
```

See [`helix-iam-server/README.md`](helix-iam-server/README.md) for how to run the server locally
against Postgres + Redis in Docker.

### helix-dashboard (React / Vite / TypeScript)

```bash
cd helix-dashboard
npm ci
npm test          # vitest
npm run build     # tsc -b && vite build
```

### Other components

`helix-docs-site` (MkDocs), `helixiam-website` (Astro), `helix-sandbox-rp` (Node), `helix-mcp-demo`
(Node) and `terraform-provider-helix` (Go) each build with their own toolchain — see the
component's own files (`package.json`, `go.mod`, `mkdocs.yml`) for the relevant commands.

## Making a change

1. Fork the repository and create a branch from `main` (`feature/…`, `fix/…`, or similar).
2. Keep pull requests focused — one logical change per PR is much easier to review than a mix of
   unrelated changes.
3. Add or update tests for the behavior you change. This is an identity/auth server: untested
   changes to authentication, token issuance, session handling, or the admin API are a security
   risk, not just a quality one.
4. Run the relevant test suite locally before opening the PR (see above).
5. Write clear commit messages: a short imperative summary line, then (if useful) a body
   explaining *why*, not just *what*. Sign off every commit (`-s`, see DCO above).
6. Open the pull request against `main` and fill in the PR template. Link any related issue.

## Reporting bugs and requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/`. For **security vulnerabilities**, do
**not** open a public issue — see [SECURITY.md](SECURITY.md) instead.

## Code review

Maintainers will review PRs for correctness, security implications, test coverage, and fit with
the existing architecture (see `helix-iam-server/ADAPTERS.md` for background on how the module is
put together). Be patient — reviews on an auth server tend to be thorough by necessity.
