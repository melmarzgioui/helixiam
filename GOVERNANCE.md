# Governance

> **Draft — needs real details.** The maintainer/company placeholders below (`TODO:`) must be filled
> in before this is presented as final. Kept honest rather than inventing names.

HelixIAM is an open-source project licensed under Apache-2.0. This document describes who maintains it
and how decisions are made.

## Maintainers

| Role | Who | Contact |
|---|---|---|
| Lead maintainer | _TODO: name_ | _TODO: contact_ |
| Maintainers | _TODO_ | |

The current authoritative list of people with merge rights lives in
[`CODEOWNERS`](.github/CODEOWNERS) _(TODO: add this file)_.

## Sponsoring entity

_TODO: legal entity, country, and its relationship to the project (for the website About/Trust pages
and `SECURITY.md`)._

## How decisions are made

- **Everyday changes** (bug fixes, docs, dependency bumps) — a maintainer reviews and merges a PR.
- **Significant changes** (public API, token/claim formats, endpoint paths, DB schema, security
  defaults) — proposed in an issue first, need agreement from at least _TODO: N_ maintainers, and are
  recorded in `CHANGELOG.md`. Security-sensitive changes always ship with a regression test.
- **Breaking changes** — must include a migration path and a compatibility note.

## Security decisions

Security issues follow [`SECURITY.md`](SECURITY.md) (private reporting, coordinated disclosure). A
change may never weaken an existing security check to make a test pass.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). New contributors: issues labelled **good first issue** are a
good place to start.
