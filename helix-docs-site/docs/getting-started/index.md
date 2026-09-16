# Getting started

Helix IAM installs on your own infrastructure. Pick a path:

- **[Quickstart (trial)](quickstart.md)** — one command, ephemeral, throwaway secrets. Best for a
  first look.
- **[Install](install.md)** — a persistent install with Docker Compose or Helm.
- **[Configuration](configuration.md)** — the environment variables that drive everything.

Before configuring much, skim **[Core concepts](concepts.md)** — realms, applications, clients and
flows are the vocabulary the rest of the documentation uses — and **[Architecture](architecture.md)**
for how the pieces fit together.

!!! note "Conventions"
    Helix is multi-tenant: every realm is simultaneously an OpenID Connect / OAuth 2.1 issuer at
    `https://<host>/realms/<realm>`, a SAML 2.0 Identity Provider, and the issuer for federated and
    non-human (agent / workload) identities. The bootstrap realm is `master`. Throughout the docs,
    replace `<host>` and `<realm>` with your values.
