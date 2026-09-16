# Using workload roles in Kubernetes

A workload identity token isn't just proof of *who* a workload is — it carries *what it's allowed to do*.
The minted Helix token includes the bound Application client's **service-account roles**
(`realm_access.roles` / `resource_access.roles`) and its **scopes**. This guide shows where those roles
come from in Helix, and the two places Kubernetes can enforce them:

- **Option A — Kubernetes RBAC:** the API server trusts Helix as an OIDC provider and maps the role claim
  to RBAC, so the token governs *cluster access*.
- **Option B — service-to-service:** your CNI / mesh / gateway validates the token and enforces the role
  on *east-west traffic between services* — the usual use for a workload token.

It assumes you've already set up [workload identity](workload-identity.md) (an Application with a
keyless credential bound to a Kubernetes ServiceAccount).

---

## Step 1 — Define the role in Helix

A workload acts as its Application's **OIDC client (service account)**, so the token carries whatever
roles are assigned to *that service account*. Define a role and assign it there.

### 1a. Create the role

A **realm role** lands in `realm_access.roles`; a **client role** lands in
`resource_access.<clientId>.roles`. Use a realm role for cross-cutting capabilities (e.g.
`ledger-writer`), a client role when it's specific to one downstream API.

=== "Admin console"

    **Realm roles → New role** → name it `ledger-writer`. (For a client role, use the target client's
    **Roles** tab instead.)

=== "Admin API"

    ```bash
    curl -X POST https://helix.example.com/admin/realms/apps/roles \
      -H "Content-Type: application/json" -d '{"name": "ledger-writer"}'
    ```

### 1b. Assign it to the Application's service account

This is the step that puts the role into the workload's token — assign it to the **OIDC client's service
account**, which is the identity the workload acts as.

=== "Admin console"

    Open the **Application → OIDC** tab → its client → **Service account roles** → assign `ledger-writer`.

=== "Admin API"

    ```bash
    curl -X POST https://helix.example.com/admin/realms/apps/clients/billing-service/service-account/roles \
      -H "Content-Type: application/json" \
      -d '{"roleName": "ledger-writer", "roleType": "REALM"}'
    ```

### 1c. Confirm it's in the token

Exchange a workload token (see the [setup guide](workload-identity.md#setup-guide-a-kubernetes-client-end-to-end))
and decode the result:

```json
{
  "sub": "billing-service",
  "realm_access": { "roles": ["ledger-writer"] },
  "scope": "billing.read billing.write",
  "wif": true
}
```

Every workload that federates into this Application now inherits `ledger-writer` — assign once, applies
everywhere.

---

## Option A — Kubernetes RBAC (govern cluster access)

Use this when a workload, CI job, or human should act on the **Kubernetes API** itself (e.g. a deploy
pipeline that needs read-only access). The API server authenticates the Helix token and standard
**RBAC** decides what it can do — no long-lived kubeconfig.

!!! note "Token audience"
    The token you present to the API server must have an `aud` the server accepts. Create an Application
    (e.g. `kubernetes`) for cluster access and use its client as the credential's "acts as", so the
    minted token's `aud` matches the `audiences` below.

### 1. Trust Helix at the API server

Kubernetes 1.30+ **Structured Authentication Configuration** can read your *nested* `realm_access.roles`
with a CEL expression — no flattening needed:

```yaml
# /etc/kubernetes/auth/helix.yaml
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt:
  - issuer:
      url: https://helix.example.com/realms/apps     # must be HTTPS and match the token's iss
      audiences: ["kubernetes"]                       # must match the token's aud
    claimMappings:
      username:
        claim: sub
        prefix: "helix:"
      groups:
        expression: 'claims.realm_access.roles'       # nested role claim → Kubernetes groups
```

Point the API server at it (flag: `--authentication-config=/etc/kubernetes/auth/helix.yaml`). On k3s/RKE2
pass it with `--kube-apiserver-arg=authentication-config=…`; on managed clusters use the provider's OIDC
settings.

### 2. Bind the role to permissions

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: helix-ledger-writer }
roleRef: { kind: ClusterRole, name: view, apiGroup: rbac.authorization.k8s.io }
subjects:
  - kind: Group
    name: ledger-writer          # the Helix role, surfaced as a group
    apiGroup: rbac.authorization.k8s.io
```

### 3. Use it

```bash
kubectl --token="$HELIX_TOKEN" get pods -n apps      # ✅ allowed (view)
kubectl --token="$HELIX_TOKEN" delete pod x -n apps  # ❌ Forbidden — RBAC denies
```

Change the role assignment in Helix and access changes immediately — nothing to re-issue on the cluster.

---

## Option B — Enforce on service-to-service traffic

This is the usual path for a workload token: a pod calls another service with
`Authorization: Bearer <helix token>`, and the in-cluster data plane validates the token against Helix's
JWKS and requires the role *before the request reaches your app*. Pick the tab for your stack.

!!! info "Two complementary layers"
    These policies enforce the **role in the token** (identity *authorization*). They pair with your CNI's
    **identity-based** network policy (which *pods* may reach a service at all) — defense in depth. A
    Cilium identity example is at the end.

=== "Cilium"

    Cilium ships Envoy and lets you inject L7 filters with **`CiliumEnvoyConfig`** — use Envoy's
    `jwt_authn` filter to validate the Helix token against its JWKS, then the `rbac` filter to require the
    role. Attach it to the service with a `CiliumNetworkPolicy` that selects the Envoy listener.

    ```yaml
    apiVersion: cilium.io/v2
    kind: CiliumEnvoyConfig
    metadata:
      name: ledger-api-jwt
      namespace: apps
    spec:
      services:
        - name: ledger-api
          namespace: apps
      resources:
        - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
          name: ledger-api-listener
          filterChains:
            - filters:
                - name: envoy.filters.network.http_connection_manager
                  typedConfig:
                    "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                    statPrefix: ledger
                    routeConfig:
                      virtualHosts:
                        - name: ledger
                          domains: ["*"]
                          routes:
                            - match: { prefix: "/" }
                              route: { cluster: "apps/ledger-api" }
                    httpFilters:
                      # 1) validate the Helix token, expose its claims as metadata
                      - name: envoy.filters.http.jwt_authn
                        typedConfig:
                          "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
                          providers:
                            helix:
                              issuer: "https://helix.example.com/realms/apps"
                              remoteJwks:
                                httpUri:
                                  uri: "https://helix.example.com/realms/apps/oauth2/jwks"
                                  cluster: "helix-jwks"
                                  timeout: 5s
                                cacheDuration: 300s
                              payloadInMetadata: "helix"      # claims → dynamic metadata
                          rules:
                            - match: { prefix: "/" }
                              requires: { providerName: "helix" }
                      # 2) require realm_access.roles to contain "ledger-writer"
                      - name: envoy.filters.http.rbac
                        typedConfig:
                          "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC
                          rules:
                            action: ALLOW
                            policies:
                              ledger-writers:
                                permissions: [ { any: true } ]
                                principals:
                                  - metadata:
                                      filter: envoy.filters.http.jwt_authn
                                      path: [ { key: "helix" }, { key: "realm_access" }, { key: "roles" } ]
                                      value: { listMatch: { oneOf: { stringMatch: { exact: "ledger-writer" } } } }
                      - name: envoy.filters.http.router
                        typedConfig:
                          "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
    ```

    A caller without a valid Helix token, or whose token lacks `ledger-writer`, is rejected by Envoy
    before reaching `ledger-api`. See Cilium's *L7-aware policy / CiliumEnvoyConfig* docs for wiring the
    `helix-jwks` cluster.

=== "Istio"

    `RequestAuthentication` validates the token; `AuthorizationPolicy` requires the role.

    ```yaml
    apiVersion: security.istio.io/v1
    kind: RequestAuthentication
    metadata: { name: helix, namespace: apps }
    spec:
      selector: { matchLabels: { app: ledger-api } }
      jwtRules:
        - issuer: "https://helix.example.com/realms/apps"
          jwksUri: "https://helix.example.com/realms/apps/oauth2/jwks"
    ---
    apiVersion: security.istio.io/v1
    kind: AuthorizationPolicy
    metadata: { name: ledger-writers-only, namespace: apps }
    spec:
      selector: { matchLabels: { app: ledger-api } }
      action: ALLOW
      rules:
        - when:
            - key: request.auth.claims[realm_access][roles]
              values: ["ledger-writer"]
    ```

    `request.auth.claims[realm_access][roles]` reads the nested claim directly — no flattening.

=== "Envoy Gateway (Gateway API)"

    If you front the service with [Envoy Gateway](https://gateway.envoyproxy.io), a `SecurityPolicy`
    attached to the `HTTPRoute` validates the token and authorizes the role.

    ```yaml
    apiVersion: gateway.envoyproxy.io/v1alpha1
    kind: SecurityPolicy
    metadata: { name: ledger-api-helix, namespace: apps }
    spec:
      targetRefs:
        - group: gateway.networking.k8s.io
          kind: HTTPRoute
          name: ledger-api
      jwt:
        providers:
          - name: helix
            issuer: "https://helix.example.com/realms/apps"
            remoteJWKS:
              uri: "https://helix.example.com/realms/apps/oauth2/jwks"
      authorization:
        rules:
          - action: Allow
            principal:
              jwt:
                provider: helix
                claims:
                  - name: realm_access.roles
                    valueType: StringArray
                    values: ["ledger-writer"]
        defaultAction: Deny
    ```

=== "Gateway API (generic)"

    With other Gateway API implementations (Kong, Contour + ext-authz, NGINX Gateway Fabric), terminate
    the JWT at the gateway and forward only role-bearing requests — consult that controller's JWT /
    external-authorization extension. The principle is identical: validate against
    `…/oauth2/jwks`, require `realm_access.roles` contains the role.

### Complementary: Cilium identity-based policy

The role check answers *"is the caller authorized?"*. Cilium network policy answers the orthogonal
*"may these pods talk at all?"* — enforce both:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: { name: only-frontend-to-ledger, namespace: apps }
spec:
  endpointSelector: { matchLabels: { app: ledger-api } }
  ingress:
    - fromEndpoints:
        - matchLabels: { app: billing }     # only the billing pods, by identity…
      toPorts:
        - ports: [ { port: "8080", protocol: TCP } ]
          rules:
            http:
              - method: "GET"
                path: "/ledger/.*"           # …and only this method/path
```

A pod must be **both** an allowed Cilium identity *and* present a Helix token carrying `ledger-writer`.

---

## Choosing between A and B

| Question | Use |
| --- | --- |
| Should the workload act on the **Kubernetes API** (read pods, apply manifests)? | **Option A** (RBAC) |
| Should the workload call **another service** that checks its role? | **Option B** (CNI/mesh/gateway) |
| Both? | Both — they're independent and compose |

In all cases the role lives in **one place — the Application's service account in Helix** — and flows into
every workload that federates into it.

## Verify end to end

```bash
# the workload's token carries the role
TOKEN=$(kubectl -n apps create token billing --audience=helix)
curl -s -X POST https://helix.example.com/realms/apps/workload-identity/token \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=$TOKEN" \
  | jq -r .access_token | cut -d. -f2 | base64 -d | jq '.realm_access'
# → { "roles": ["ledger-writer"] }

# Option A: cluster access is RBAC-bound
kubectl --token="$HELIX_TOKEN" auth can-i get pods -n apps     # yes
kubectl --token="$HELIX_TOKEN" auth can-i delete pods -n apps  # no

# Option B: a call without the role is rejected by the data plane (403), with the role is allowed (200)
```
