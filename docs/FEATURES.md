# HelixIAM feature matrix

An honest map of what HelixIAM does, how far along it is, where it lives in the code, and what
tests back it. Kept in sync with the marketing site — if the site claims it, it is here with a
status.

**Status legend**
- **Stable** — implemented and covered by automated tests in this repo; API expected to stay.
- **Beta** — implemented and tested, but the API may change, external conformance is not yet
  proven, or it needs your own third-party agreement to exercise end-to-end.
- **Experimental** — present but not yet solid enough to depend on.
- **Planned** — claimed somewhere but not implemented (or only partially).

> "Stable" means *tested in this repo*, not *independently certified*. FAPI and the EU eIDs in
> particular need external conformance / a live peer before you should rely on them in production
> (see the notes). An independent third-party security audit + pentest is still required before 1.0
> (`SECURITY-REVIEW.md`).

## Authentication
| Feature | Status | Code (helix-iam-server unless noted) | Tests |
|---|---|---|---|
| OAuth2 / OIDC provider (authorize, token, userinfo, JWKS, discovery, logout) | Stable | `authorization/idp`, `authorization/security/OAuthConfig` | OIDC/discovery/JWKS suites |
| RS256 + PS256 signing, per-realm keys & rotation | Stable | `authorization/security/RealmJwkSource`, realm-keys | realm-signing tests |
| Passkeys / WebAuthn (FIDO2) | Stable | `authentication/webauthn` | Passkey (5), WebAuthn (4) |
| TOTP / OTP factors | Stable | `authentication/otp` | OTP suites |
| Magic-link / passwordless | Beta | `authentication` magic-link | MagicLink (2) |
| Device push login | Beta | `notification/delivery` push + login | partial |
| Risk-based / adaptive step-up | Beta | `authentication` adaptive | Adaptive (4) |
| Brute-force lockout, password policy, HIBP | Stable | `authentication` policy | policy suites |

## SSO & Federation
| Feature | Status | Code | Tests |
|---|---|---|---|
| SAML 2.0 IdP (SSO/SLO, POST + Artifact) | Beta | `authorization/idp/saml` | SAML IdP + deep-SAML suites |
| SAML / OIDC / social brokering | Beta | `authorization/federation` | broker + validator suites |
| LDAP / Active Directory | Beta | `authorization/federation/ldap` | federation tests |
| Single Logout (front / back / SAML) | Beta | SLO controllers | SLO tests |

## Non-human identity (the differentiator)
| Feature | Status | Code | Tests |
|---|---|---|---|
| AI-agent identity & lifecycle | Beta | `authorization/idp/agent` | agent suites |
| On-behalf-of delegation (RFC 8693, scope intersection, attenuation) | Beta — hardening in progress (see `CHANGES-1.0.md` Phase 1) | `authorization/idp/agent/DelegationTokenController`, `security/agent/*` | Delegation (3), TokenExchange (1) |
| Workload Identity Federation (keyless K8s/CI) | Beta | `authorization/idp/workloadidentity` | WorkloadIdentity (8) |
| MCP-ready resource-server auth | Beta | `helix-mcp-demo`, RFC 9728 metadata | mcp-demo tests |

## European eIDs
| Feature | Status | Code | Tests |
|---|---|---|---|
| DigiD (NL citizen) | **Beta — connector included; requires your own Logius/broker agreement** | `authorization/federation/eid` | DigiD (15) — validator-level |
| eHerkenning (NL business) | Beta — connector, your own agreement | `authorization/federation/eid` | Eherkenning (4) |
| eIDAS (EU cross-border) | Beta — connector, your own agreement | `authorization/federation/eid` | Eidas (6) |

> The eID assertion validators are well-tested, but the **live DigiD `ArtifactResolve` mTLS SOAP
> round-trip and `EncryptedID` decryption are not exercised** (no live DigiD test peer). Treat eID
> as "connector included," not "certified integration."

## Developer & admin
| Feature | Status | Code | Tests |
|---|---|---|---|
| Admin console (realms, apps, users, roles, sessions, flows, keys, events) | Stable | `helix-dashboard` | vitest suites |
| Realm import/export | Stable | `authorization/controller/admin/io/RealmIoController` | io tests |
| Import from Keycloak realm export | Stable | `authorization/controller/admin/io/KeycloakImporter` | `KeycloakImporterTest` |
| SCIM 2.0 (in & out) | Stable | `authorization/idp/scim` | SCIM (9) |
| Dynamic Client Registration | Stable | DCR controller | DCR tests |
| OpenAPI / Swagger | Stable | springdoc (gated by `helix.springdoc.public`) | — |
| TypeScript SDK | **Experimental — not published to npm** | `helix-dashboard/src/sdk` (`index.ts`, `types.ts`) | `index.test.ts` |
| Terraform provider | **Beta — `helix_application` + `helix_realm_role` only** (+ `helix_client_id` / `helix_client_secret` data sources) | `terraform-provider-helix/internal/provider` | 2 test files |

## Security & compliance
| Feature | Status | Code | Tests |
|---|---|---|---|
| FAPI (mTLS/PS256-bound tokens) | Beta — unit-tested; **OpenID conformance suite not yet run** (planned, CI Phase 4) | `authorization/security` FAPI | Fapi (8) |
| DPoP (RFC 9449) | Beta | DPoP validators | DPoP (2) |
| PAR (RFC 9126) | Beta | pushed-authorization endpoint | PushedAuthorization (1) |
| Device authorization grant (RFC 8628) | Beta | device endpoints | DeviceCode/Authorization (2) |
| Resource indicators (RFC 8707) | Beta | aud-narrowing | resource-indicator tests |
| Searchable audit log + SIEM/webhooks | Stable | `audit`, webhook HMAC | audit suites |
| SSRF egress guard | Stable | `common/net/OutboundUrlGuard` | OutboundUrlGuard tests |

## Known claim corrections (to reconcile on the website)
1. **`import { HelixIAM } from "@helixiam/sdk"`** — no such npm package is published; the SDK lives
   in `helix-dashboard/src/sdk`. Either extract + publish it, or change the website example. *(Open.)*
2. **Terraform provider "manages realms, clients, and flows"** — it manages `application` and
   `realm_role` (+ client id/secret data sources). Add `realm` / `identity_provider` / `agent` /
   `flow` resources, or correct the claim. *(Open.)*
3. **eID** — word it as "connector included; requires your own Logius/broker agreement," not a
   turnkey certified integration. *(Reflected above.)*
4. **"All shipped. All documented."** — not literally true (SDK unpublished, Terraform partial,
   several Beta). Use per-feature Beta labels instead. *(For Phase 7.)*
