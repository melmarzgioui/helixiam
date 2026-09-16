# Helix IAM

**Helix IAM** is the complete identity & access management platform for modern applications — a
multi-tenant OpenID Connect and SAML 2.0 identity provider with strong authentication, federation,
EU electronic IDs, provisioning, and a full admin & end-user console. It secures **human, machine, and
AI-agent** identities alike: first-class non-human identities (NHI) with an accountable owner, a
lifecycle kill-switch, and on-behalf-of delegation for agents acting for users. Secure every app with
enterprise single sign-on, run it on your own infrastructure, and own your identity layer end to end.

<div class="grid cards" markdown>

-   :material-rocket-launch: **Get started**

    Try it in one command, then install for real with Docker Compose or Helm.

    [:octicons-arrow-right-24: Getting started](getting-started/index.md)

-   :material-cog: **Manage**

    Realms, applications, users, roles, scopes & claims, groups, organizations.

    [:octicons-arrow-right-24: Manage](manage/index.md)

-   :material-shield-key: **Authenticate**

    The flow editor, MFA, passkeys, device push, and risk-based step-up.

    [:octicons-arrow-right-24: Authentication](authentication/index.md)

-   :material-account-network: **Federate**

    OIDC / SAML / LDAP / social brokers, plus DigiD, eHerkenning and eIDAS.

    [:octicons-arrow-right-24: Federation & eIDs](federation/index.md)

-   :material-puzzle: **Integrate**

    SDKs, Terraform, SCIM, webhooks, the API reference and the account console.

    [:octicons-arrow-right-24: Integration](integration/index.md)

-   :material-server: **Operate**

    Keys, theming, RBAC, GDPR, observability, backup/DR and hardening.

    [:octicons-arrow-right-24: Operations](operations/index.md)

</div>

## What Helix does

| Capability | |
|------------|--|
| **Protocols** | OAuth 2.1 / OpenID Connect (authorization code + PKCE, client credentials, refresh, device, CIBA), SAML 2.0 IdP, FAPI (mTLS-bound tokens, signed request objects, JARM), DPoP, PAR |
| **Authentication** | Data-driven flow engine; password policy + breach check + lockout; TOTP, SMS/email OTP; WebAuthn passkeys; device push with number matching; transaction signing (WYSIWYS) |
| **Federation** | OIDC, SAML, LDAP/AD and social brokers with JIT provisioning, account linking and claim mappers |
| **EU eIDs** | DigiD (NL citizen), eHerkenning (NL business), eIDAS (EU cross-border) connectors |
| **AI agents / NHI** | First-class agent identities with an accountable owner, lifecycle kill-switch, `nhi` token claims, least-privilege roles, and RFC 8693 on-behalf-of delegation (effective roles = user ∩ agent leash ∩ scope) |
| **Workload identity** | Keyless token exchange for Kubernetes/CI workloads (federated JWTs, no stored secret) |
| **Multi-tenant** | Realms isolate users, agents, clients, keys, flows and branding; each realm is its own OIDC issuer **and** SAML 2.0 IdP |
| **Provisioning** | SCIM 2.0 (in and out), LDAP sync, bulk import, Dynamic Client Registration |
| **Authorization** | Realm & client roles, hierarchical groups, UMA 2.0 authorization services (resources / policies / permissions), and resource indicators (RFC 8707) |
| **B2B** | Organizations — member companies with their own domains and identity providers inside a realm |
| **Operations** | Per-realm key management & rotation, audit log + SIEM, outbound webhooks, admin RBAC, GDPR tools, Prometheus metrics & health |
| **Consoles** | A React admin console and a self-service end-user account console |

## How it's built

Helix runs as a single standalone service plus a console:

- **helix-iam-server** — OAuth2 / OIDC / SAML endpoints, the admin REST API, and the identity domain,
  owning one PostgreSQL database directly. No message broker, no separate services to coordinate.
- **Console** — serves the admin and account single-page apps.

Session and token state lives in PostgreSQL (and, optionally, Redis for the high-throughput tier), not in
any one server instance, so it scales horizontally for login throughput. See
[Architecture](getting-started/architecture.md).

!!! tip "New here?"
    Start with the [Quickstart](getting-started/quickstart.md) to get a working instance in one
    command, then read [Core concepts](getting-started/concepts.md) to learn the vocabulary
    (realms, applications, clients, flows) the rest of the docs use.
