# Spec — Workload Identity Federation (Kubernetes & keyless service auth)

**Status:** proposed · **Scope:** net-new feature (own epic) · **Branch:** feature/helix-iam

## Goal

Let a workload — a Kubernetes pod, a CI job, any process that can obtain a signed OIDC JWT from a
trusted issuer — obtain a Helix access token **without any client secret**, by presenting its
issuer-signed JWT. This is the same model as Entra Workload ID / AWS IAM-Roles-for-ServiceAccounts /
GitHub OIDC, but **cloud-agnostic**: Helix becomes the workload-identity broker for any cluster
(EKS/GKE/AKS/RKE2/k3s) and any downstream that trusts Helix tokens.

## How it works (token exchange)

```
 pod ──(projected SA JWT, aud=helix)──▶  Helix workload token endpoint
                                          1. parse iss from the JWT
                                          2. find the matching Workload Identity Credential (iss+sub+aud)
                                          3. fetch+cache the issuer JWKS (OIDC discovery or explicit uri)
                                          4. verify sig (RS256/ES256) + iss + aud + exp/nbf
                                          5. mint a Helix access token for the mapped client identity
 pod ◀──(Helix access token, signed by the realm key)────────────────────────────────────
```

The mint reuses the realm's signing key, so the issued token is an ordinary Helix access token that any
Helix-protected resource server verifies against the realm JWKS.

## Data model

One resource, modelled on Entra's "federated identity credential":

`workload_identity_credential`
| column | meaning |
|--------|---------|
| `id` | uuid |
| `realm_id` | realm scope |
| `name` | unique per realm |
| `issuer` | exact `iss` to trust (e.g. the cluster's OIDC issuer URL) |
| `jwks_uri` | optional explicit JWKS; if null, derived from `issuer` via OIDC discovery |
| `subject` | exact `sub` to match (e.g. `system:serviceaccount:apps:billing`) |
| `audience` | required `aud` the workload must request (e.g. `helix`) |
| `client_id` | the Helix client/service-account identity the workload acts as |
| `scopes` | space-delimited scopes granted to the minted token |
| `enabled` | bool |

Idempotent `ADD COLUMN IF NOT EXISTS` schema.

## Endpoints

**Admin:** realm-scoped CRUD
`GET/POST /admin/realms/{realm}/workload-identity`,
`GET/PUT/DELETE /admin/realms/{realm}/workload-identity/{id}`.

**Token (public, no client auth):**
`POST /realms/{realm}/workload-identity/token`, form-encoded:
- `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
- `subject_token=<the issuer-signed JWT>`
- `subject_token_type=urn:ietf:params:oauth:token-type:jwt`
- optional `scope`

Returns `{ access_token, token_type: Bearer, expires_in, scope }`. A dedicated endpoint (not the
SAS-owned `/oauth2/token`) — the SAS hot path is untouched, mirroring how device/QR/push flows are added.

## Validation & hardening (must-haves)

- Signature verified against the issuer JWKS with a **fixed algorithm allow-list** (RS256/RS384/RS512,
  ES256/384/512); reject `alg:none`, HMAC, and unexpected algs.
- **Exact** issuer match; **exact** audience match (the credential's `audience`); `exp`/`nbf`/`iat`
  enforced with small clock skew; reject tokens with too-long lifetime.
- Subject match is exact (no wildcards in v1 — add guarded patterns later).
- JWKS fetched over **https only**, cached with refresh + rotation, bounded size/timeouts.
- Per-credential `enabled` gate; realm scoping enforced; unknown issuer/subject → generic 401 (no
  enumeration). Every exchange (success/failure) emits an **audit event** with issuer+subject.
- Replay window bounded by `exp`; optionally pin `jti` cache. Rate-limit the endpoint.
- The minted token's lifetime is short (configurable; default a few minutes) and carries the workload
  context (issuer, subject) as claims for downstream policy.

## Out of scope (v1)

Subject wild/pattern matching, mTLS-bound workload tokens, a k8s mutating webhook/projected-token
helper (client-side; documented instead), multi-audience credentials.

## Acceptance

1. Admin can CRUD a workload identity credential (API + console).
2. A real Kubernetes pod's projected ServiceAccount JWT is exchanged for a Helix access token, end to
   end, against a live cluster (k3d/minikube) — **no secret used**.
3. Tampered / wrong-issuer / wrong-audience / expired / wrong-subject tokens are all rejected.
4. Docs page added under Integration.
