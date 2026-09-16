# API Reference

Explore and integrate against the complete admin and protocol API — documented live from the running server.

## What it is

Helix IAM publishes its full API as **OpenAPI**, generated directly from the running server, so the reference is always exactly in step with the version you are running. Browse it interactively, or pull the spec to generate a typed client in your language of choice.

| Resource | URL |
| --- | --- |
| Interactive docs | `/swagger-ui.html` |
| OpenAPI spec | `/v3/api-docs` |

```bash
# Fetch the machine-readable spec
curl https://auth.example.com/v3/api-docs -o helix-openapi.json
```

The spec covers both the **admin API** (realms, applications, users, roles, scopes, identity providers, sessions, webhooks, SCIM targets, import/export) and the **protocol endpoints** (OIDC, SAML, account).

## Generate a client

Point any OpenAPI generator at the spec to scaffold a typed SDK:

```bash
openapi-generator-cli generate \
  -i helix-openapi.json \
  -g typescript-fetch \
  -o ./helix-client
```

!!! tip "Prefer the official SDK for OIDC"
    For login flows and admin automation in TypeScript, the [TypeScript SDK](sdk-typescript.md) gives you ergonomic, hand-tuned helpers on top of the API. Use a generated client when you need a language the SDK does not yet cover.

## Dynamic Client Registration

Applications can register themselves programmatically via **Dynamic Client Registration** (DCR) at:

```
POST /connect/register
```

DCR is protected by an **initial access token** issued by an administrator. Present it to register a new client and receive its credentials and a registration access token for later management.

```http
POST /realms/acme/connect/register
Authorization: Bearer <initial-access-token>
Content-Type: application/json

{
  "client_name": "Acme Web",
  "redirect_uris": ["https://app.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"]
}
```

!!! note "Mint initial access tokens carefully"
    Treat initial access tokens like onboarding credentials: scope them, time-box them, and hand them only to trusted provisioning systems.

## Endpoint catalog

The tables below are generated from the running server's OpenAPI spec (`/v3/api-docs`). Helix exposes **two API surfaces that authenticate differently** — see [Authenticating to the API](../getting-started/api-authentication.md):

| Surface | Path prefix | Auth |
| --- | --- | --- |
| **Admin API** | `/admin/realms/{realm}/…` | Admin **session + CSRF** (writes need `X-XSRF-TOKEN`) |
| **Protocol** | `/realms/{realm}/…` | OAuth2 / OIDC **bearer tokens** |

### Admin API

All paths below are relative to `/admin/realms/{realm}`.

#### Users

| Method & path | Purpose |
| --- | --- |
| `GET /users` · `POST /users` | List / create users |
| `GET` · `PUT` · `DELETE /users/{userId}` | Read / update / delete a user |
| `GET` · `POST /users/{userId}/roles` | List / assign user role mappings |
| `DELETE /users/{userId}/roles/{roleId}` | Unassign a role |
| `GET /users/{userId}/credentials` | List a user's credentials |
| `DELETE /users/{userId}/credentials/{type}/{id}` | Revoke a credential |
| `PUT /users/{userId}/password` | Reset a user's password |
| `GET` · `PUT /users/{userId}/required-actions` | Get / set required actions |
| `POST /users/{userId}/impersonate` | Impersonate a user |
| `GET /users/{userId}/gdpr/export` | Export a user's personal data |
| `GET /users/{userId}/gdpr/consents` | List a user's consent records |
| `DELETE /users/{userId}/gdpr` | Erase a user (right to be forgotten) |
| `POST /users/import` | Bulk-import users |

#### Clients

| Method & path | Purpose |
| --- | --- |
| `GET /clients` · `POST /clients` | List / create OIDC clients |
| `GET` · `PUT` · `DELETE /clients/{id}` | Read / update / delete a client |
| `GET` · `POST /clients/{id}/secret` | Reveal / regenerate the client secret |
| `GET` · `POST /clients/{clientId}/roles` · `DELETE .../roles/{name}` | Client roles |
| `GET` · `POST /clients/{clientId}/mappers` · `PUT` · `DELETE .../mappers/{mapperId}` | Protocol mappers |
| `GET` · `POST` · `DELETE /clients/{clientId}/service-account/roles` | Service-account role mappings |
| `GET` · `PUT /clients/{clientId}/allowed-resources` | Resource-indicator allow-list (RFC 8707) |
| `GET` · `PUT /clients/{clientId}/authz/settings` | Authorization Services (UMA) settings |
| `GET` · `POST /clients/{clientId}/authz/resources` · `DELETE .../resources/{name}` | UMA resources |
| `GET` · `POST /clients/{clientId}/authz/policies` · `DELETE .../policies/{name}` | UMA policies |
| `GET` · `POST /clients/{clientId}/authz/permissions` · `DELETE .../permissions/{name}` | UMA permissions |
| `GET` · `POST /clients/{clientId}/authz/scopes` · `DELETE .../scopes/{name}` | UMA scopes |
| `POST /clients/{clientId}/authz/evaluate` | Evaluate an authorization request |

#### Roles

| Method & path | Purpose |
| --- | --- |
| `GET /roles` · `POST /roles` | List / create realm roles |
| `GET` · `PUT` · `DELETE /roles/{roleId}` | Read / update / delete a realm role |
| `PUT /roles/{roleId}/default` | Set the realm's default role |

#### Groups

| Method & path | Purpose |
| --- | --- |
| `GET /groups` · `POST /groups` | List / create groups |
| `PUT` · `DELETE /groups/{groupId}` | Update / delete a group |
| `GET /groups/{groupId}/members` · `PUT` · `DELETE .../members/{userId}` | Group membership |
| `GET /groups/{groupId}/roles` · `PUT` · `DELETE .../roles/{roleId}` | Group role mappings |

#### Organizations

| Method & path | Purpose |
| --- | --- |
| `GET /organizations` · `POST /organizations` | List / create organizations |
| `GET` · `PUT` · `DELETE /organizations/{orgId}` | Read / update / delete an organization |
| `GET /organizations/{orgId}/members` · `PUT` · `DELETE .../members/{userId}` | Organization membership |

#### Client scopes

| Method & path | Purpose |
| --- | --- |
| `GET /client-scopes` · `POST /client-scopes` | List / create client scopes |
| `GET` · `DELETE /client-scopes/{scopeId}` | Read / delete a client scope |
| `PUT` · `DELETE /client-scopes/{scopeId}/claims/{claimId}` | Attach / detach a claim mapper |

#### Claims

| Method & path | Purpose |
| --- | --- |
| `GET /claims` · `POST /claims` | List / create claim mappers |
| `PUT` · `DELETE /claims/{claimId}` | Update / delete a claim mapper |

#### Identity providers

| Method & path | Purpose |
| --- | --- |
| `GET /identity-providers` · `POST /identity-providers` | List / create identity providers |
| `GET` · `PUT` · `DELETE /identity-providers/{alias}` | Read / update / delete a provider |

#### Webhooks

| Method & path | Purpose |
| --- | --- |
| `GET /webhooks` · `POST /webhooks` | List / create subscriptions |
| `PUT` · `DELETE /webhooks/{id}` | Update / remove a subscription |

#### Applications

| Method & path | Purpose |
| --- | --- |
| `GET /applications` · `POST /applications` | List / create applications |
| `GET` · `PUT` · `DELETE /applications/{name}` | Read / update / delete an application |

#### Agents (AI / non-human identity)

| Method & path | Purpose |
| --- | --- |
| `GET /agents` · `POST /agents` | List / create agents |
| `GET` · `PUT` · `DELETE /agents/{id}` | Read / update / delete an agent |
| `POST /agents/{id}/activate` · `/suspend` · `/revoke` | Lifecycle transitions |
| `GET /agents/owner-review` | Owner attestation / review queue |

#### SAML clients

| Method & path | Purpose |
| --- | --- |
| `GET /saml-clients` · `POST /saml-clients` | List / register SAML relying parties |
| `GET` · `PUT` · `DELETE /saml-clients/{entityId}` | Read / update / delete a SAML client |
| `POST /saml-clients/import` · `/import-url` | Import from metadata (body / URL) |

#### Keys

| Method & path | Purpose |
| --- | --- |
| `GET /keys` | List realm signing keys |
| `DELETE /keys/{keyId}` | Retire a key |
| `POST /keys/rotate` | Rotate the active signing key |

#### Sessions

| Method & path | Purpose |
| --- | --- |
| `GET /sessions` | List active sessions |
| `DELETE /sessions/{id}` | Revoke a session |
| `GET /sessions/service-accounts` | List service-account sessions |

#### Authentication flows

| Method & path | Purpose |
| --- | --- |
| `GET /flows` · `POST /flows` | List / create authentication flows |
| `GET` · `PUT` · `PATCH` · `DELETE /flows/{alias}` | Read / save / rename / delete a flow |
| `GET` · `PUT /flow` | Get / save the browser sign-in flow |
| `GET /authenticators` | List available authenticators |

#### Admin roles (RBAC)

| Method & path | Purpose |
| --- | --- |
| `GET /admin-roles` | List admin roles |
| `PUT /admin-roles/{roleId}` | Set an admin role's permissions |
| `GET /admin-roles/permissions` | List assignable admin permissions |

#### Messaging (SMS / email / push)

| Method & path | Purpose |
| --- | --- |
| `GET` · `PUT /messaging/providers` | List / save channel providers |
| `DELETE /messaging/providers/{channel}/{driver}` | Remove a provider |
| `POST /messaging/providers/{channel}/test` | Send a test message |
| `GET` · `PUT /messaging/templates` | List / save message templates |
| `POST /messaging/templates/preview` | Preview a rendered template |
| `GET` · `POST /messaging/push-tokens` | List / register push tokens |

#### SCIM targets (outbound provisioning)

| Method & path | Purpose |
| --- | --- |
| `GET /scim-targets` · `POST /scim-targets` | List / register downstream SCIM targets |
| `PUT` · `DELETE /scim-targets/{id}` | Update / remove a target |

#### Import / export

| Method & path | Purpose |
| --- | --- |
| `GET /export` | Export the realm |
| `POST /import` | Import a realm |
| `POST /import/keycloak` | Import from a Keycloak export |
| `POST /users/import` | Bulk-import users |

#### Realm settings & operations

| Method & path | Purpose |
| --- | --- |
| `GET` · `PUT /settings` | Read / update realm settings |
| `GET` · `PUT /subject-claim` | Read / set the subject-claim strategy |
| `GET` · `PUT /provisioning` | Read / update DCR & provisioning config |
| `POST /provisioning/initial-access-tokens` | Mint a DCR initial access token |
| `GET /endpoints` | Realm endpoint URLs |
| `GET /health` | Realm health |
| `GET /events` | Query the audit-event log |
| `POST /user-federation/{alias}/sync` | Trigger an LDAP sync |
| `GET /workload-identity` · `POST` · `GET`/`PUT`/`DELETE /workload-identity/{id}` | Workload identity federation configs |

!!! note "Global admin endpoints"
    A few endpoints are server-wide rather than realm-scoped: `GET /admin/metrics/summary` (Prometheus-style summary) and `GET /admin/audit/config`.

### Protocol endpoints (bearer / public)

These run under the realm prefix `/realms/{realm}/…` and authenticate with **bearer tokens** (or their own onboarding credential), not an admin session.

| Method & path | Auth | Purpose |
| --- | --- | --- |
| `/account/**` | User bearer token | End-user self-service — see [Account console](account-console.md) |
| `/scim/v2/**` | Per-realm SCIM token | SCIM 2.0 provisioning — see [SCIM](scim.md) |
| `POST /connect/register` · `GET`/`PUT`/`DELETE /connect/register/{clientInternalId}` | Initial / registration access token | Dynamic Client Registration (RFC 7591) |
| `POST /workload-identity/token` | Workload JWT | Exchange a workload JWT for a Helix token |
| `POST /agent/delegation/token` | Client / bearer | On-behalf-of agent delegation (RFC 8693) |
| `POST /device/enroll` · `/device/enroll/start` | Enrollment token | Device / MFA enrollment |
| `GET /push/{id}` · `POST /push/{id}/approve` · `/deny` | Session | Push-based MFA approval |
| `GET /qr/{id}` · `POST /qr/{id}/confirm` | Session | QR-based device confirmation |
| `POST /tx` · `GET /tx/{id}` · `POST /tx/{id}/sign` · `/consume` | Bearer | Signing / consent transactions |
| `GET /saml/idp/metadata` | Public | SAML 2.0 IdP metadata |
| `GET /.well-known/oauth-protected-resource` | Public | RFC 9728 protected-resource metadata |

!!! tip "Standard OIDC/SAML endpoints"
    The usual protocol endpoints — `/authorize`, `/token`, `/userinfo`, `/logout`, `/.well-known/openid-configuration`, JWKS — are advertised by the realm's discovery document. See the [OIDC quickstart](oidc-quickstart.md).

## See also

- [Authenticating to the API](../getting-started/api-authentication.md)
- [OIDC quickstart](oidc-quickstart.md)
- [TypeScript SDK](sdk-typescript.md)
- [Terraform provider](terraform.md)
- [Manage applications](../manage/applications.md)
