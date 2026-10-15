# terraform-provider-helix

Manage [Helix IAM](https://github.com/melmarzgioui/helixiam) as code — realms' applications and roles via the admin API.
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

### `helix_wallet_identity_provider`
An EUDI Wallet (OpenID4VP verifier) identity-provider connection — an `/admin/realms/{realm}/identity-providers`
connection with protocol `eudi-wallet` (see [`docs/eudi-wallet.md`](../docs/eudi-wallet.md)). Supports `terraform
import helix_wallet_identity_provider.<name> <alias>`.

| Attribute | | |
|-----------|---|---|
| `alias` | required, forces replace | unique connection alias within the realm |
| `display_name` | optional | label shown in the console and on the login page |
| `enabled` | optional, default true | |
| `client_id_scheme` | optional | `x509_hash` (default) or `x509_san_dns` |
| `client_id_host` | optional | required DNS host for `x509_san_dns` |
| `access_key_ref` | optional | realm signing-key reference (e.g. `software:gov/primary`); required unless `access_certificate_private_key` is used |
| `access_certificate_chain` | optional | PEM chain, leaf first, no root |
| `access_certificate_private_key` | optional, **sensitive**, write-only | dev-profile-only raw PEM key; never read back — see below |
| `registration_certificate` | optional | PEM bundle for OpenID Federation registration |
| `invocation_scheme` | optional | default `haip-vp` |
| `response_mode` | optional | `direct_post.jwt` (default) or `direct_post` (dev only) |
| `request_uri_method` | optional | `get` (default) or `post` |
| `transaction_ttl_seconds` | optional | 60–900, default 300 |
| `credential_formats` | optional, list | `dc+sd-jwt` and/or `mso_mdoc` |
| `pid_sd_jwt_vcts` | optional, list | accepted SD-JWT VC `vct`s |
| `pid_mdoc_doctype` | optional | mdoc PID doctype |
| `pid_requested_claims` | optional, list | PID claims to request |
| `custom_credential_queries` | optional, list | not supported yet (must stay empty) |
| `trust_anchors` | optional | PEM bundle of trusted PID-issuer CAs |
| `revocation_checking` | optional | default `HARD_FAIL` |
| `status_list_required` / `status_list_on_unavailable` / `status_list_max_cache_seconds` / `status_list_allowed_hosts` | optional | Token Status List policy |
| `subject_strategy` / `subject_acknowledge_weak_subject` | optional | how the Helix subject is derived |
| `minimum_loa` | optional | default `http://eidas.europa.eu/LoA/high` |
| `clock_skew_seconds` | optional | 0–60, default 60 |
| `allow_legacy_vc_sd_jwt_typ` | optional | default false |
| `limits_max_jwt_bytes` / `limits_cbor_max_depth` / `limits_cbor_max_items` / `limits_cbor_max_bytes` | optional | parser bounds |
| `id` | computed | the connection alias |

Every attribute above maps to a key of the connection's `config` map on the server
(`WalletProviderConfig.java`); leaving one unset omits it from the write, so the server's own default
applies and `terraform plan` never shows drift for it. `accessCertificateKeyRef` (renamed to
`access_key_ref`, always refused by the server) and `subjectPepper` (a realm-level secret unrelated to
any one connection) are deliberately not exposed. **`access_certificate_private_key` is write-only**: the
admin API never returns a secret's value, only whether one is set, so a read keeps whatever is already in
state. Removing the line from your configuration stops Terraform from managing it but does not clear the
value on the server (the API keeps a secret it isn't told to replace or clear) — to actually remove it,
recreate the resource or clear it through the admin API directly.

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
#   ~/.terraform.d/plugins/registry.terraform.io/melmarzgioui/helix/0.1.0/<os>_<arch>/
# then `terraform init` in examples/ and `terraform apply`.
```

See `examples/main.tf` for a complete configuration.

## Status

The admin client + the application and realm-role resources' CRUD are **verified live** against a
running Helix publisher (application create/read/update/delete + realm role create/read/delete).
`helix_wallet_identity_provider` CRUD and import are covered by unit tests against a mock admin API
(`internal/provider/wallet_identity_provider_test.go`) and has a gated live test
(`TestLiveWalletIdentityProviderCRUD`) not yet run against a live server. Acceptance tests (`TF_ACC`)
and registry publication are the remaining release steps.
