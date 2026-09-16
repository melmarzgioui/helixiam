## Summary

<!-- What does this change do, and why? -->

## Related issue

<!-- Fixes #123 / Relates to #123, if any -->

## Component(s) touched

- [ ] helix-iam-server
- [ ] helix-dashboard
- [ ] helix-docs-site
- [ ] helixiam-website
- [ ] helix-sandbox-rp
- [ ] helix-mcp-demo
- [ ] terraform-provider-helix
- [ ] CI / tooling / docs (repo-level)

## How was this tested?

<!-- Commands run, tests added/updated, manual verification steps. -->

## Checklist

- [ ] Commits are signed off (`git commit -s`) per [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] Tests added/updated for the change (this is an identity/auth server — untested changes to
      auth, token issuance, session, or the admin API are a security risk)
- [ ] `mvn -o clean test` (or the relevant component's test command) passes locally
- [ ] Docs updated if behavior, configuration, or APIs changed
- [ ] No secrets, credentials, or real key material added
