# Workload identity federation

Give your Kubernetes pods and CI jobs a Helix identity **without a client secret**. A workload presents
a short-lived JWT that its own platform already issues — a Kubernetes projected ServiceAccount token, a
GitHub Actions or GitLab CI OIDC token — and Helix exchanges it for a Helix access token. Nothing to
store, nothing to rotate, nothing to leak.

This is the same trust model the major clouds use for keyless deployment, available for every workload
that can obtain an OIDC-signed JWT.

## Why keyless

A long-lived client secret in a pod or a CI variable is the credential most likely to leak and least
likely to be rotated. Workload identity federation removes it entirely:

- **No secret to manage.** The workload authenticates with a token its platform mints on demand and
  rotates automatically (a Kubernetes projected token is typically valid for an hour and refreshed in
  place).
- **Bound to a real identity.** The exchange is authorized only for an exact issuer, subject, and
  audience — e.g. *"the `billing` ServiceAccount in the `apps` namespace of this cluster."* A token from
  any other workload is rejected.
- **Fully auditable.** Every exchange — granted or denied — is an audit event naming the workload.

## How it works

```
┌────────────────────┐   1. projected SA token (iss, sub, aud)   ┌──────────────────────┐
│  Kubernetes pod /   │ ───────────────────────────────────────▶ │   Helix token        │
│  CI job             │                                           │   exchange endpoint  │
│                     │ ◀─────────────────────────────────────── │                      │
└────────────────────┘   4. Helix access token (realm-signed)    └──────────┬───────────┘
                                                                             │ 2. verify signature
                                                                             │    against issuer JWKS
                                                                  ┌──────────▼───────────┐
                                                                  │  issuer's published  │
                                                                  │  JWKS (OIDC)         │
                                                                  └──────────────────────┘
```

1. The workload obtains a JWT from its own platform (a Kubernetes projected ServiceAccount token, a CI
   OIDC token).
2. The workload POSTs that JWT to the Helix exchange endpoint.
3. Helix selects the matching **workload identity credential** for the realm, then cryptographically
   verifies the JWT against the issuer's published JWKS — checking the signature, the exact issuer,
   audience, subject, and expiry. The expected values come from the registered credential, never from
   the token's own claims.
4. On success Helix mints a realm-signed access token for the mapped client identity and returns it.

The exchange follows [RFC 8693 (OAuth 2.0 Token Exchange)](https://www.rfc-editor.org/rfc/rfc8693).

## Setup guide: a Kubernetes client, end to end

This is the full path to give one workload — say a `billing` service running in your cluster — a keyless
Helix identity. It takes five steps and ~10 minutes.

!!! abstract "What you'll do"
    1. Collect the workload's identity facts (`issuer`, `subject`, `audience`).
    2. Make the cluster's signing keys reachable to Helix.
    3. Register a workload identity credential in the realm.
    4. Wire the workload to fetch its token and exchange it.
    5. Verify, then harden.

### Prerequisites

- A Helix realm and admin access to it (console or the admin API).
- A Kubernetes cluster (1.20+) — projected ServiceAccount tokens and the OIDC discovery endpoints are on
  by default.
- The Helix identity (`clientId`) the workload should act as, and the scopes it needs.

### Step 1 — Collect the workload's identity facts

Helix authorizes a workload by the exact `iss` / `sub` / `aud` of the token it presents. Get them from
the cluster and the ServiceAccount:

```bash
# the cluster's OIDC issuer (this becomes the credential's "Issuer")
kubectl get --raw /.well-known/openid-configuration | jq -r .issuer
# e.g. https://kubernetes.default.svc.cluster.local

# the workload's ServiceAccount (namespace + name → the "Subject")
#   subject = system:serviceaccount:<namespace>:<serviceaccount>
# e.g. for SA "billing" in namespace "apps":
#   system:serviceaccount:apps:billing

# the audience is one you choose and require — keep it stable, e.g. "helix"
```

!!! tip "Pick a dedicated ServiceAccount per workload"
    The `subject` is what binds the credential to *this* workload. Give each workload its own
    ServiceAccount (`kubectl -n apps create serviceaccount billing`) so credentials stay one-to-one and
    revocation is surgical.

### Step 2 — Make the cluster's signing keys reachable to Helix

Helix verifies the presented token against the **issuer's JWKS** (its public signing keys). Helix must be
able to fetch them. Choose the path that matches your topology:

| Your situation | What to set as **JWKS URL** |
| --- | --- |
| Helix runs **inside the same cluster** (or can route to the API server) | leave blank — Helix discovers it from the issuer's OIDC metadata |
| The cluster exposes a **public/anonymous** OIDC discovery + JWKS | leave blank, or set the published `jwks_uri` |
| Helix is **outside** the cluster and the in-cluster JWKS isn't reachable | publish the cluster's JWKS to a URL Helix can reach, and set that URL |

For the third case, mirror the cluster's keys once (they rotate rarely; refresh on rotation):

```bash
# export the cluster's public JWKS …
kubectl get --raw /openid/v1/jwks > cluster-jwks.json
# … and serve it somewhere Helix can GET (object storage, an internal endpoint, a config server).
# Set the credential's JWKS URL to that location. The Issuer stays the real cluster issuer
# (it must equal the token's `iss`); only the key-fetch location changes.
```

The keys are public — there is nothing secret to protect here.

### Step 3 — Register the credential

A workload acts as an **Application's OIDC client** (its *service account*) — that's the identity that
holds the roles and scopes the minted token carries. So you bind the credential **to an Application**,
not to a free-text name. If you don't have one yet, create the Application and give its OIDC client the
**service account** (the `client_credentials` grant), then assign it the realm/client roles the workload
needs.

=== "Admin console"

    Open the Application → **OIDC** tab → **Workload identity** → **Add credential**. (Workload identity
    is an OIDC/OAuth-only feature, so it lives among the OIDC client's tabs.) The "acts as" identity is
    implicit — it's this application's OIDC client — so you only supply the trust facts:

    | Field | Value (example) |
    | --- | --- |
    | Name | `Prod cluster (apps/billing)` |
    | Issuer | `https://kubernetes.default.svc.cluster.local` |
    | JWKS URL | *(blank, or the mirror URL from Step 2)* |
    | Subject | `system:serviceaccount:apps:billing` |
    | Audience | `helix` |
    | Scopes | `billing.read billing.write` |
    | Enabled | ✓ |

    The application's **service-account roles** are carried automatically — assign them on the OIDC
    client. The standalone **Workload identity** page (under Configure) is a read-only overview of every
    credential in the realm.

=== "Admin API"

    `clientId` is the Application's OIDC client — it must already exist in the realm with its service
    account enabled (the `client_credentials` grant), or the call is rejected with `400`.

    ```bash
    curl -X POST https://helix.example.com/admin/realms/apps/workload-identity \
      -H "Content-Type: application/json" \
      -d '{
        "name": "Prod cluster (apps/billing)",
        "issuer": "https://kubernetes.default.svc.cluster.local",
        "jwksUri": null,
        "subject": "system:serviceaccount:apps:billing",
        "audience": "helix",
        "clientId": "billing-service",
        "scopes": "billing.read billing.write",
        "enabled": true
      }'
    ```

    Drive the same call from your IaC tooling (Terraform `http`/`restapi`, Ansible `uri`, a CI step) to
    manage credentials as code.

### Step 4 — Wire the workload to fetch and exchange its token

Two parts: **project a token** scoped to your audience, and **exchange it** for a Helix token.

Project the token (a volume Kubernetes keeps fresh for you):

```yaml
# deployment.yaml (excerpt)
spec:
  template:
    spec:
      serviceAccountName: billing            # ← the SA from Step 1
      containers:
        - name: billing
          image: registry.example.com/billing:1.4.0
          env:
            - name: HELIX_TOKEN_URL
              value: https://helix.example.com/realms/apps/workload-identity/token
            - name: K8S_TOKEN_PATH
              value: /var/run/secrets/helix/token
          volumeMounts:
            - name: helix-token
              mountPath: /var/run/secrets/helix
              readOnly: true
      volumes:
        - name: helix-token
          projected:
            sources:
              - serviceAccountToken:
                  path: token
                  audience: helix            # ← must equal the credential's Audience
                  expirationSeconds: 3600
```

Exchange it (the app does this on startup and before the cached token expires):

```bash
#!/bin/sh
# get-helix-token.sh — prints a Helix access token to stdout
SUBJECT_TOKEN="$(cat "$K8S_TOKEN_PATH")"
curl -s -X POST "$HELIX_TOKEN_URL" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=$SUBJECT_TOKEN" \
  | jq -r .access_token
```

Then call your downstream API with the result: `Authorization: Bearer <helix access token>`.

!!! note "Refresh, don't cache forever"
    The Helix token's lifetime is in `expires_in` (default 900s). Re-run the exchange before it expires —
    the projected ServiceAccount token underneath is rotated by Kubernetes automatically, so the exchange
    keeps working with no redeploy.

### Step 5 — Verify

```bash
# from inside the pod (or with a token minted by `kubectl create token`):
TOKEN=$(kubectl -n apps create token billing --audience=helix --duration=3600s)
curl -s -X POST https://helix.example.com/realms/apps/workload-identity/token \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=$TOKEN" | jq .
```

A `200` with an `access_token` means it's working end to end. A `401 invalid_grant` means the credential
didn't match or the token didn't verify — see [Troubleshooting](#troubleshooting). Decode the returned
token (e.g. on [jwt.io](https://jwt.io)) and confirm `sub` is your `clientId` and `wif` is `true`.

### Harden (recommended)

- One ServiceAccount → one credential, so you can disable exactly one workload.
- Grant only the scopes the workload needs.
- Ship the `WORKLOAD_TOKEN_ISSUED` / `WORKLOAD_TOKEN_DENIED` [audit events](#audit) to your SIEM and
  alert on unexpected `DENIED` spikes.
- To rotate a workload off immediately, toggle its credential **Disabled** — exchanges stop at once.

## How the exchange executes, step by step

This section traces a single request from the wire to the minted token. It's useful when you're
integrating, debugging a rejection, or reviewing the security model.

### The request

The workload makes a form-encoded POST. The path is realm-scoped:

```http
POST /realms/{realm}/workload-identity/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<the workload's JWT>
&scope=<optional space-delimited subset of the credential's scopes>
```

There is **no `Authorization` header and no client secret** — the `subject_token` *is* the credential.

### The sequence

```
 Workload            Helix exchange endpoint            Issuer JWKS         Credential store
    │                          │                            │                     │
    │ 1. POST subject_token    │                            │                     │
    │─────────────────────────▶│                            │                     │
    │                          │ 2. parse JWT (UNVERIFIED)  │                     │
    │                          │    read iss, sub, aud      │                     │
    │                          │ 3. find credential ────────┼────────────────────▶│
    │                          │    (realm, iss, sub, aud, enabled)               │
    │                          │◀───────────────────────────┼─────────────────────│
    │                          │ 4. fetch issuer keys ──────▶│                     │
    │                          │◀───────────────────────────│                     │
    │                          │ 5. VERIFY signature + iss  │                     │
    │                          │    + aud + sub + exp        │                     │
    │                          │    (expected values from    │                     │
    │                          │     the credential)         │                     │
    │                          │ 6. mint realm-signed token  │                     │
    │ 7. 200 { access_token }  │ 7. emit audit event         │                     │
    │◀─────────────────────────│                            │                     │
```

### What the server does

1. **Routing.** A request filter strips `/realms/{realm}` and pins the active realm before security or
   MVC runs, so the endpoint is reached at its bare path and every downstream lookup is realm-scoped.

2. **Request validation.** If `grant_type` isn't the token-exchange URN, or `subject_token` is missing,
   the request is rejected immediately with `400 invalid_request`. (Nothing is parsed yet.)

3. **Rate limiting.** The attempt is counted against a per-`(realm, source-IP)` window. Over the limit
   returns `429` — this bounds how fast a caller can probe the verifier.

4. **Read the token's claims — without trusting them.** The JWT is parsed (not verified) only to read
   its `iss`, `sub`, and `aud`. These three values are used **solely to select which credential's trust
   policy applies** — they are never themselves trusted to authorize anything.

5. **Select the credential.** Helix looks up an **enabled** credential in the realm whose registered
   `issuer`, `subject`, and `audience` match the presented token. If none matches, the request stops here
   with `401 invalid_grant`. (A K8s token's `aud` is a list; each value is tried.)

6. **Resolve the issuer's keys.** Helix uses the credential's configured **JWKS URL**, or — when blank —
   discovers it from `{issuer}/.well-known/openid-configuration`. The key set is cached and refreshed, so
   issuer key rotation is picked up automatically.

7. **Cryptographically verify the token.** This is the security gate. In one pass Helix checks:

    - the **signature** validates against the issuer's JWKS, using an **asymmetric algorithm only**
      (RS256/384/512, ES256/384/512, PS256). `none` and HMAC are rejected by construction;
    - `iss` **exactly equals** the credential's registered issuer;
    - `aud` **contains** the credential's registered audience;
    - `sub` **exactly equals** the credential's registered subject;
    - `exp` is in the future.

    Crucially, the *expected* issuer / audience / subject passed to the verifier come from the **stored
    credential**, not from the token's own claims. A forged or mis-targeted token therefore can never
    satisfy a credential it doesn't cryptographically match. Any failure stops here with
    `401 invalid_grant`.

8. **Mint the Helix token.** Only now does Helix build a realm-signed access token (RS256, signed with
   the realm's active key) for the credential's bound **Application client** and return it. The token
   carries that client's **service-account roles** (as `realm_access` / `resource_access` claims) —
   the same grants a `client_credentials` token for that client would carry — plus the scopes (the
   requested subset of the credential's scopes, or all of them when `scope` is omitted).

9. **Audit.** A `WORKLOAD_TOKEN_ISSUED` event is emitted on success (naming the client identity, issuer,
   and subject); a `WORKLOAD_TOKEN_DENIED` event is emitted on any failure.

### What the minted token contains

```json
{
  "iss": "https://helix.example.com/realms/{realm}",
  "sub": "billing-service",          // the credential's mapped client identity
  "aud": ["billing-service"],
  "azp": "billing-service",
  "client_id": "billing-service",
  "scope": "billing.read billing.write",
  "realm_access": { "roles": ["ledger-writer"] },           // the client's service-account roles
  "resource_access": { "orders-api": { "roles": ["read"] } },
  "wif": true,                        // marks this as a workload-identity token
  "workload_iss": "https://kubernetes.default.svc.cluster.local",
  "workload_sub": "system:serviceaccount:apps:billing",
  "iat": 1735000000,
  "exp": 1735000900,
  "jti": "…"
}
```

The roles come from the Application client's **service-account roles** — assign them once on the client
and every workload that federates into it inherits them. `realm_access` / `resource_access` are omitted
when the client has no roles assigned (a scope-only token).

→ For where to assign these roles in Helix and how to **enforce them in Kubernetes** (RBAC, and
service-to-service with Cilium / Istio / Envoy Gateway), see
[Using workload roles in Kubernetes](workload-identity-roles.md).

It is an ordinary realm-signed access token — verify it against the realm JWKS
(`/realms/{realm}/oauth2/jwks`) exactly like any other Helix token. `workload_iss` / `workload_sub`
record the originating workload for traceability.

### Why an unauthorized workload can't get in

The model is defence-in-depth, and the key property is that a workload's **subject is cryptographically
bound by its own platform**:

- A Kubernetes API server (or a CI provider) is the *only* party that can sign a token, and it always
  stamps the token's `sub` with the **real** identity of the workload requesting it. A pod running as
  `payments/untrusted` cannot obtain a token claiming `sub=apps:billing` — it only ever gets
  `sub=payments/untrusted`.
- Because step 5 matches that subject against the registered credentials, an unregistered workload finds
  **no credential** and is denied — even though its token is perfectly valid and its signature checks out.
  The rejection is *authorization*, not authentication.
- Step 7 then re-asserts the issuer, audience, and subject cryptographically against the credential, so a
  token stolen from one workload can't be replayed to act as another.
- Every failed exchange returns the same generic `invalid_grant` — Helix never reveals *which* check
  failed, so the endpoint can't be used to enumerate which subjects or issuers are registered.

In short: a genuine-but-unregistered workload, a token with the wrong audience, a token from an
unregistered issuer, a tampered token, and a credential that's been disabled all converge on a single
`401 invalid_grant`.

## Register a workload identity credential

A credential is a trust policy: *"a JWT from this issuer, with this subject and this audience, may be
exchanged for a Helix token acting as **this Application**."* The Application's OIDC client (its service
account) is the identity — it holds the roles and scopes the token carries. Create one credential per
workload (or per group of workloads that share a subject).

=== "Admin console"

    Open the **Application** → **OIDC** tab → **Workload identity** → **Add credential**. (It sits among the
    OIDC client's tabs because workload identity is OIDC/OAuth-only.) "Acts as" is implicit (this
    application's OIDC client), so you supply only the trust facts:

    | Field | Meaning | Example |
    | --- | --- | --- |
    | **Name** | A human label for the credential | `Prod cluster (apps/billing)` |
    | **Issuer** | The exact `iss` of the workload's token | `https://kubernetes.default.svc.cluster.local` |
    | **JWKS URL** | Where the issuer publishes its signing keys (optional — discovered from the issuer when blank) | `https://…/openid/v1/jwks` |
    | **Subject** | The exact `sub` the token must carry | `system:serviceaccount:apps:billing` |
    | **Audience** | The `aud` the workload must request | `helix` |
    | **Scopes** | Scopes added to the minted token (on top of the client's roles) | `billing.read billing.write` |

    The standalone **Workload identity** page under Configure is a read-only overview of every credential
    in the realm.

=== "Admin API"

    ```bash
    curl -X POST https://helix.example.com/admin/realms/{realm}/workload-identity \
      -H "Content-Type: application/json" \
      -d '{
        "name": "Billing service (prod cluster)",
        "issuer": "https://kubernetes.default.svc.cluster.local",
        "subject": "system:serviceaccount:apps:billing",
        "audience": "helix",
        "clientId": "billing-service",
        "scopes": "billing.read billing.write",
        "enabled": true
      }'
    ```

    No field is secret, so the credential round-trips to the console unmasked.

!!! note "Finding the issuer and JWKS"
    For a Kubernetes cluster, read them straight from the API server:

    ```bash
    # the issuer
    kubectl get --raw /.well-known/openid-configuration | jq -r .issuer
    # the signing keys (if Helix can't reach the in-cluster JWKS, publish these to a URL Helix can reach)
    kubectl get --raw /openid/v1/jwks
    ```

## Exchange a token from a pod

Mount a projected ServiceAccount token with the Helix audience, then exchange it:

```yaml
# deployment.yaml — project a token scoped to the "helix" audience
volumes:
  - name: helix-token
    projected:
      sources:
        - serviceAccountToken:
            path: token
            audience: helix
            expirationSeconds: 3600
```

```bash
# inside the pod
SUBJECT_TOKEN=$(cat /var/run/secrets/helix/token)

curl -s -X POST https://helix.example.com/realms/{realm}/workload-identity/token \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=$SUBJECT_TOKEN"
```

A successful exchange returns a standard OAuth token response:

```json
{
  "access_token": "eyJraWQi…",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "billing.read billing.write"
}
```

The `access_token` is a normal realm-signed Helix token — verify it against the realm JWKS exactly like
any other access token. It carries the mapped client identity as `sub`, plus `wif: true` and the
originating workload's `workload_iss` / `workload_sub` for traceability.

## Try it against a local cluster

You can prove the whole flow end-to-end with a throwaway [k3d](https://k3d.io) cluster:

```bash
# 1. a namespace + service account
kubectl create namespace apps
kubectl -n apps create serviceaccount billing

# 2. a projected token for the "helix" audience
TOKEN=$(kubectl -n apps create token billing --audience=helix --duration=3600s)

# 3. register the credential (issuer + subject from the token, see "Finding the issuer" above)
#    then exchange it
curl -s -X POST https://helix.example.com/realms/{realm}/workload-identity/token \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=$TOKEN" | jq .
```

## CI/CD providers

Any OIDC-capable CI platform works the same way — register a credential matching that provider's issuer,
subject, and audience.

| Provider | Issuer | Subject example |
| --- | --- | --- |
| GitHub Actions | `https://token.actions.githubusercontent.com` | `repo:my-org/my-repo:ref:refs/heads/main` |
| GitLab CI | `https://gitlab.com` | `project_path:my-group/my-project:ref_type:branch:ref:main` |
| Kubernetes | `https://kubernetes.default.svc.cluster.local` | `system:serviceaccount:apps:billing` |

## Security model

- **Asymmetric signatures only.** The presented token is verified with RS256/384/512, ES256/384/512, or
  PS256. The `none` algorithm and HMAC are never accepted.
- **Expected values come from the credential.** Issuer, audience, and subject are matched against the
  registered credential, not against the token's self-asserted claims — a forged or mis-targeted token
  can never select a credential it doesn't cryptographically satisfy.
- **Expiry enforced.** Expired tokens are rejected.
- **Generic failures.** Every failed exchange returns a single generic `invalid_grant` — Helix never
  reveals which check failed, so the endpoint can't be used to enumerate credentials.
- **Rate limited.** Repeated attempts from one source are throttled.
- **Disable instantly.** Toggling a credential off blocks all exchanges for it immediately.

## Audit

Each exchange emits an audit event:

| Event | Outcome | When |
| --- | --- | --- |
| `WORKLOAD_TOKEN_ISSUED` | `SUCCESS` | a token was minted; the event names the client identity, issuer, and subject |
| `WORKLOAD_TOKEN_DENIED` | `DENIED` | the exchange failed (no matching credential, verification failed, malformed token) |

See [Events & audit](../manage/events.md) for shipping these to your SIEM.

## Troubleshooting

Because Helix returns a single generic `invalid_grant` for every authorization failure (so the endpoint
can't be probed), use this table plus the `WORKLOAD_TOKEN_DENIED` audit event's `reason` field to find
the cause.

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `400 invalid_request` | wrong `grant_type`, or `subject_token` missing | Send `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` and a non-empty `subject_token`. |
| `401 invalid_grant`, reason *no matching credential* | the token's `iss`/`sub`/`aud` don't match any enabled credential | Compare the token's claims (decode it) against the credential. Common slips: a trailing slash on the issuer, the wrong namespace/SA in the subject, or the projected token's `audience` not equal to the credential's Audience. |
| `401 invalid_grant`, reason *verification failed* | signature/JWKS problem | Helix couldn't fetch the issuer's keys or the signature didn't validate. Check the **JWKS URL** (Step 2) is reachable from Helix and serves the cluster's current keys; confirm the issuer hasn't rotated keys past your mirror. |
| `401 invalid_grant` after it worked before | the credential was **disabled**, or the cluster rotated its signing keys | Re-enable the credential; refresh the JWKS mirror if you're using one. |
| `401`, token looks valid | the token **expired** between mint and exchange, or `aud` is a different value than registered | Mint a fresh token; ensure the projected-token `audience` exactly equals the credential's Audience. |
| `429 slow_down` | too many attempts from one source | Back off; the endpoint is rate-limited per source. Don't exchange on every request — cache the Helix token until shortly before `expires_in`. |
| Returned token rejected by your API | your API isn't validating against the realm JWKS, or expects a different `aud` | Verify the Helix token against `/realms/{realm}/oauth2/jwks`; the token's `aud` is the `clientId`. |

To confirm a workload *should* match, decode its token and check the three values that must line up:

```bash
kubectl -n apps create token billing --audience=helix \
  | cut -d. -f2 | base64 -d 2>/dev/null | jq '{iss, sub, aud}'
```

## Reference

- Admin API: `GET/POST/PUT/DELETE /admin/realms/{realm}/workload-identity`
- Exchange endpoint: `POST /realms/{realm}/workload-identity/token`
- See the [API reference](api-reference.md) for full request and response schemas.
