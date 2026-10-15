# HelixIAM feature matrix

An honest map of what HelixIAM does, how far along it is, where it lives in the code, and what
tests back it. Kept in sync with the marketing site — if the site claims it, it is here with a
status.

**Status legend**
- **Stable** — implemented and covered by automated tests in this repo; API expected to stay.
- **Beta** — implemented and tested, but the API may change, external conformance is not yet
  proven, or it needs your own third-party agreement to exercise end-to-end.
- **Preview** — implemented and tested in this repo, but not yet exercised against a real-world
  counterpart (no live third-party peer, or a newer path layered on a Beta/Stable feature); expect
  rough edges.
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
| TOTP / OTP factors (enrolment confirmed by a first code, ±30 s, replay-protected, recovery codes, per-realm `requireMfa` + skip grace) | Stable | `service/mfa`, `security/mfa` | `MfaE2eTest`, `TotpServiceTest` |
| Magic-link / passwordless (opt-in per realm; hashed single-use links, 15-min expiry, rate limited per email + IP; emailed via the realm's provider; TOTP still enforced) | Stable | `service/magiclink`, `controller/MagicLinkController` | `MagicLinkE2eTest`, `MagicLinkServiceTest` |
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
| EUDI Wallet (OpenID4VP verifier) — redirect same-device, QR cross-device, SD-JWT VC + mdoc | Beta — proven against the EU reference wallet and an OIDF conformance self-run | `authorization/federation/wallet` | 1323 |
| EUDI Wallet: W3C Digital Credentials API (`dc_api`/`dc_api.jwt`) | Preview — not yet tested with a real wallet | `authorization/federation/wallet` | `WalletDcApiFlowE2eTest` |
| EUDI Wallet: verify-only / step-up (`subject.strategy=NONE`) | Preview | `authorization/federation/wallet` | `WalletVerifyDcApiE2eTest`, verify-only suites |

## Non-human identity (the differentiator)
| Feature | Status | Code | Tests |
|---|---|---|---|
| AI-agent identity & lifecycle | Beta | `authorization/idp/agent` | agent suites |
| On-behalf-of delegation (RFC 8693, scope intersection, attenuation) at `/agent/delegation/token` | Beta — hardening in progress (see `CHANGES-1.0.md` Phase 1) | `authorization/idp/agent/DelegationTokenController`, `security/agent/*` | Delegation (3), TokenExchange (1) |
| Token exchange at `/oauth2/token` (RFC 8693 impersonation: `subject_token` only, `audience`/`resource`, `act` = requesting client) | Beta. An `actor_token` / `actor_token_type` is refused (`invalid_request`): RFC 8693 actor semantics (`may_act`, `act` from the actor) are not implemented there; use `/agent/delegation/token` | `security/tokenexchange/ActorTokenRefusingConverter`, `security/TokenExchangeTargets`, `service/client/TokenExchangePolicyService` | TokenExchange (4), TokenExchangeActorRefused (2+2) |
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

### eID minimum level of assurance

Each eID connection has a minimum level of assurance (`minimumLoa`). It is both requested in the AuthnRequest
(`RequestedAuthnContext`, comparison `minimum`) and enforced on the assertion. The value must be one the server
knows for the scheme; an unknown value is refused when the connection is saved (`400`) and when it is loaded.

| Scheme | Console keywords | Also accepted (the URN itself) |
|---|---|---|
| DigiD | `loa1`/`basis`, `loa2`/`midden`, `loa3`/`substantieel`, `loa4`/`hoog`; each is requested as the SAML 2.0 context class: `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport` (Basis), `…:MobileTwoFactorContract` (Midden), `…:Smartcard` (Substantieel), `…:SmartcardPKI` (Hoog) | those four classes; `urn:nl-eid-gdi:1.0:LoA:Low/Midden/Substantial/High` (same rungs, for brokers that assert them) |
| eHerkenning | `loa2`, `loa2plus`, `loa3`, `loa4` (EH2+ ranks above EH2, below EH3) | `urn:etoegang:core:assurance-class:loa2/loa2plus/loa3/loa4` |
| eIDAS | `low`, `substantial`, `high` | `http://eidas.europa.eu/LoA/low/substantial/high` |

**DigiD levels.** The DigiD mapping is the one in Logius, *Koppelvlakspecificatie DigiD SAML Authenticatie* v3.5:
Basis = `PasswordProtectedTransport`, Midden = `MobileTwoFactorContract`, Substantieel = `Smartcard`, Hoog =
`SmartcardPKI` (all `urn:oasis:names:tc:SAML:2.0:ac:classes:*`). A DigiD keyword is sent in the AuthnRequest as
`RequestedAuthnContext Comparison="minimum"` with that class, and the asserted class is ranked on the same ladder.
A broker that asserts the `urn:nl-eid-gdi:1.0:LoA:*` URNs is still accepted at the same rungs, and such a URN may
still be stored as the minimum; it is compared as stored, but the DigiD AuthnRequest asks for the oasis class of the
same level (DigiD does not know the nl-eid-gdi URNs in a request). No eID scheme puts an nl-eid-gdi URN in the
request: the eIDAS and eHerkenning schemes request their own ladders, and a custom minimum must be on the scheme's
ladder. A broker that requires the nl-eid-gdi URN in the AuthnRequest is therefore not supported as such; the generic
SAML connection sends no `RequestedAuthnContext` at all (and does not enforce an eID minimum). Routing services and CombiConnect may
assert other URIs (for example eIDAS `…/LoA/NotNotified/*`), which the server does not rank and therefore never
accepts against a set minimum.

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
