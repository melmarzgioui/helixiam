# terraform-provider-helix

Manage [Helix IAM](https://kubedna.io) as code — realms' applications and roles via the admin API.
Built on the Terraform Plugin Framework.

## Provider configuration

```hcl
provider "helix" {
  issuer        = "https://idp.example.com/realms/master" # the realm issuer (mints the admin token)
  realm         = "master"                                 # realm to administer (default: master)
  client_id     = var.helix_client_id                      # OAuth2 client-credentials client
  client_secret = var.helix_client_secret
  # base_url    = "https://admin.example.com"              # only if the admin API is on another host
}
```

All attributes also read from environment: `HELIX_ISSUER`, `HELIX_REALM`, `HELIX_BASE_URL`,
`HELIX_CLIENT_ID`, `HELIX_CLIENT_SECRET`. The provider authenticates with the OAuth2
client-credentials grant and caches the token until just before expiry.

## Resources

### `helix_application`
A Helix Application (Service Provider) — the protocol-agnostic parent of an OIDC client / SAML RP.

| Attribute | | |
|-----------|---|---|
| `name` | required, forces replace | unique application name (natural key) |
| `display_name` | optional | human-friendly name |
| `description` | optional | |
| `subject_claim` | optional | token subject claim (e.g. `email`) |
| `auth_flow_alias` | optional | bound authentication flow |
| `enabled` | optional, default true | |
| `id` / | computed | the application name |

### `helix_realm_role`
A realm role.

| Attribute | | |
|-----------|---|---|
| `name` | required, forces replace | unique role name |
| `description` | optional | |
| `role_id` / `id` | computed | server-assigned role id |

## Build & test

```bash
go build ./...        # compile the provider
go test ./...         # unit tests (httptest-backed client tests)
go vet ./...

# Live CRUD against a running Helix (dev instance with admin auth open, or set client creds):
HELIX_LIVE_BASEURL=http://localhost:8083 go test ./internal/provider -run TestLiveCRUD -v
```

## Local install (try it without the registry)

```bash
go build -o terraform-provider-helix
# Place it on Terraform's local plugin path, e.g.:
#   ~/.terraform.d/plugins/registry.terraform.io/kubedna/helix/0.1.0/<os>_<arch>/
# then `terraform init` in examples/ and `terraform apply`.
```

See `examples/main.tf` for a complete configuration.

## Status

The admin client + both resources' CRUD are **verified live** against a running Helix publisher
(application create/read/update/delete + realm role create/read/delete). Acceptance tests (`TF_ACC`)
and registry publication are the remaining release steps.
