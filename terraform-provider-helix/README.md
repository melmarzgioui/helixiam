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

**The realm is the provider's, not any one resource's.** Every resource below is created in whichever
realm the provider block is configured for. Changing `realm` (or `HELIX_REALM`) does not move existing
resources: Terraform plans to create them again in the new realm, and the resources left in the old realm
stay there, unmanaged (`terraform plan`/`apply` never deletes them, since the provider's state for the old
realm is simply no longer reachable under the new configuration).

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
| `access_key_ref` | optional, **recommended** | realm signing-key reference (e.g. `software:gov/primary`, imported via `/admin/realms/{realm}/verifier-keys`); never written to Terraform state. Required unless `access_certificate_private_key` is used |
| `access_certificate_chain` | optional | PEM chain, leaf first, no root |
| `access_certificate_private_key` | optional, **sensitive**, write-only | a raw PEM key, as an alternative to `access_key_ref`. The server accepts this only in its `dev` deployment profile and refuses it in every other profile. Never read back from the admin API — but **stored in plaintext in Terraform state**, since `Sensitive` only redacts CLI output/logs, not the state file; see below |
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
| `subject_strategy` / `subject_acknowledge_weak_subject` | optional | how the Helix subject is derived: `ADMINISTRATIVE_NUMBER` (default), `ATTRIBUTE_TUPLE` (needs the acknowledgement), or `NONE` (verify-only, see `verify_*`) |
| `minimum_loa` | optional | default `http://eidas.europa.eu/LoA/high` |
| `clock_skew_seconds` | optional | 0–60, default 60 |
| `allow_legacy_vc_sd_jwt_typ` | optional | default false |
| `limits_max_jwt_bytes` / `limits_cbor_max_depth` / `limits_cbor_max_items` / `limits_cbor_max_bytes` | optional | parser bounds |
| `dcql_trusted_authorities` | optional | whether the DCQL query carries the `aki` Trusted Authorities Query naming `trust_anchors`' key identifiers. Unset (the default): server decides — on for `client_id_scheme = "x509_hash"` + `response_mode = "direct_post.jwt"`, off otherwise. `true` requires every trust anchor to carry a SubjectKeyIdentifier extension |
| `dc_api_enabled` | optional | also offer the W3C Digital Credentials API (OpenID4VP Appendix A, HAIP §5.2) on the wallet page where the browser supports it. Unset: server default `false`. The response is `dc_api.jwt` when `response_mode` is `direct_post.jwt` |
| `dc_api_request` | optional | `signed` (server default: `openid4vp-v1-signed`, access certificate + `expected_origins`) or `unsigned` (`openid4vp-v1-unsigned`) |
| `dc_api_expected_origins` | optional | list of web origins a DC API response may be bound to, written as a browser reports them (`https://login.example.eu`); at most 10, each on a host the server answers for (`IDP_BASE_URL` or `HELIX_ALLOWED_HOSTS`). Unset: the origin of `IDP_BASE_URL` |
| `trusted_lists` | optional, list | names of the realm's trusted list sources (Federation → Trusted lists, `/admin/realms/{realm}/trusted-lists`) whose verified PID issuer anchors are trusted in addition to `trust_anchors`; each must exist in the realm. Unset: none (an empty list is refused) |
| `trusted_list_service_types` | optional, list | narrows `trusted_lists` to these service type URIs. Unset: every type the sources load |
| `verify_linked_provider` | optional | with `subject_strategy = "NONE"` (verify-only / step-up, never a sign-in): the alias of the realm's wallet sign-in connection whose links prove whose wallet it is. Required with `NONE`, refused otherwise (see `docs/eudi-wallet.md` §13) |
| `verify_released_claims` | optional, list | with `NONE`: the verified claims released as `verified_claims` (requested mapped PID claims, or `age_over_NN`), only to a client that asks for the `verified_claims` scope. Unset: nothing is released (an empty list is refused) |
| `id` | computed | the connection alias |

Every attribute above maps to a key of the connection's `config` map on the server
(`WalletProviderConfig.java`); leaving one unset omits it from the write, so the server's own default
applies and `terraform plan` never shows drift for it. `accessCertificateKeyRef` (renamed to
`access_key_ref`, always refused by the server) and `subjectPepper` (a realm-level secret unrelated to
any one connection) are deliberately not exposed.

**`access_certificate_private_key` is write-only against the API, but not encrypted in Terraform state.**
The admin API never returns a secret's value, only whether one is set, so a read keeps whatever is
already in state — Terraform cannot refresh it and does not need to. But what you write into this
attribute is stored in plaintext in the Terraform state file like any other string attribute;
`Sensitive: true` only redacts it from CLI output and logs, it does not encrypt the state file. If you set
this attribute at all, keep state encrypted at rest or in a remote backend that encrypts it (Terraform
Cloud, an S3 backend with SSE and a restrictive bucket policy, etc.). **Prefer `access_key_ref`** instead
(a key imported via `/admin/realms/{realm}/verifier-keys`, never written to Terraform state at all) for
anything beyond a dev instance — the server (`WalletConfigValidator`) only accepts
`access_certificate_private_key` when it is running in the `dev` deployment profile and refuses it in
every other profile.

**Removing `access_certificate_private_key` from your configuration clears it.** Declarative removal means
removal: if state has a value and the plan no longer does, the resource sends
`clearAccessCertificatePrivateKey=true`, so the stored secret is actually deleted server-side, not merely
left unmanaged by Terraform while the old value lingers. This flag is never sent when state has no value
for it in the first place — for example right after `terraform import`, where Terraform cannot know
whether the server has a secret set at all, let alone clear it. To rotate the key, set a new value
directly (a value always replaces the stored one); to remove it, delete the line; to stop managing it
without touching the stored value, use `terraform state rm` instead of editing the configuration.

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

The admin client + all three resources' CRUD are **verified live** against a running Helix publisher:
application create/read/update/delete, realm role create/read/delete, and (`TestLiveWalletIdentityProviderCRUD`,
gated on `HELIX_LIVE_BASEURL`/`HELIX_LIVE_WALLET_ACCESS_KEY_REF`/`HELIX_LIVE_WALLET_TRUST_ANCHORS`) wallet
identity-provider create/read/update/delete — run and passing against a dev-profile server as of
2026-10-15. `helix_wallet_identity_provider` additionally has unit-level coverage against a mock admin
API (`internal/provider/wallet_identity_provider_test.go`): the model/wire helpers in isolation, and the
resource's own Create/Read/Update/ImportState through real `tfsdk.Plan`/`tfsdk.State` values — create →
read → update, the secret's keep-vs-clear behaviour (including the import case, where it must never
clear), a 400 with field errors becoming per-attribute diagnostics, and an import → read → no-op-update
sequence that leaves the resource undisturbed. Acceptance tests (`TF_ACC`) and registry publication are
the remaining release steps.
