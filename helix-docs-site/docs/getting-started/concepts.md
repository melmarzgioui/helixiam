# Core concepts

A small vocabulary runs through Helix IAM. Learn these and the rest of the docs read easily.

## Realm

A **realm** is an isolated tenant. It has its own users, applications, clients, roles, signing keys,
authentication flows and login branding. Realms don't share anything, so you can run staging and
production, or multiple customers, on one Helix install.

Each realm is protocol-agnostic: it is at once an **OpenID Connect / OAuth 2.1 issuer** at
`https://<host>/realms/<realm>` **and** a **SAML 2.0 Identity Provider**, and it can broker external
IdPs and issue tokens to non-human identities. The bootstrap realm — created on first start with the
admin account — is `master`. See [Realms](../manage/realms.md).

## Application

An **[application](../manage/applications.md)** (a "service provider") is the protocol-agnostic parent
of the things an integrated app needs. One application can own:

- an **[OIDC client](../manage/oidc-clients.md)** (for OAuth2 / OpenID Connect), and/or
- a **[SAML relying party](../manage/saml-clients.md)** (for SAML 2.0),

sharing the same subject-claim and login-flow settings. If you only do OIDC, an application with one
OIDC client is all you need.

## Client

A **client** is an OAuth2/OIDC client — the credential an app uses to request tokens. Clients are
**confidential** (have a secret; e.g. a server-side web app) or **public** (no secret; e.g. a SPA or
mobile app, which use PKCE). Clients declare their grant types, redirect URIs, scopes and token
settings.

## Scope & claim

A **[client scope](../manage/scopes-and-claims.md)** is a bundle of **claims** (user attributes) that a
token carries when the scope is requested — e.g. the `profile` scope adds `name`, `given_name`, etc.
Claims map user/identity attributes into OIDC token fields.

## Role & group

**[Roles](../manage/roles.md)** are named permissions you assign to users (realm roles) or scope to a
client (client roles). **[Groups](../manage/groups.md)** are hierarchical collections of users; members
inherit the group's role mappings.

## Flow

An **[authentication flow](../authentication/flows.md)** is the journey a user takes to sign in —
password, then OTP, passkey, device push or an eID step, with conditions. Flows are data-driven and
edited visually; you bind a flow per realm or per client.

## Identity provider

An **[identity provider](../federation/identity-providers.md)** (a broker) delegates authentication to
an external source — another OIDC/SAML provider, an LDAP directory, a social login, or an EU eID
(DigiD, eHerkenning, eIDAS). Helix just-in-time provisions and links the federated user.

## Agent (non-human identity)

An **[agent](../integration/agents.md)** is a first-class identity for an AI assistant, bot, or
automation — a *non-human identity* (NHI). Unlike a bare OAuth client, an agent has an accountable
human **owner**, a **lifecycle** (active → suspended → revoked) that acts as a kill-switch at token
issuance, its own least-privilege roles, and tokens marked `nhi: true`. An agent can also act **on
behalf of** a user (RFC 8693 delegation): the resulting token names both the user (`sub`) and the
agent (`act`), and its permissions are the **intersection** of the user's roles, the agent's own
leash, and the requested scope — never a union. See [Agent authorization](../integration/agent-authorization.md).

## Workload identity

A **[workload identity](../integration/workload-identity.md)** lets a Kubernetes pod or CI job exchange
its platform-issued JWT for a Helix token — **keyless**, with no client secret to store or rotate. It's
how machines authenticate; an agent often authenticates this way.

## Organization

An **[organization](../manage/organizations.md)** is a B2B tenant *within* a realm — a member company
with its own domains and (optionally) its own identity providers, so partners and customers manage
their own users while sharing your realm's applications.

## Session

A **session** is a signed-in user's presence. Helix tracks unified SSO sessions across the
applications a user has logged into, supports single logout, and lets admins review and revoke them
from [Sessions](../manage/sessions.md).

## Console

There are two web UIs:

- the **admin console** (manage realms, applications, users, …), and
- the self-service **[account console](../integration/account-console.md)** where end users manage
  their own profile, credentials and sessions.
