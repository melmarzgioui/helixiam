# Terraform Provider

Manage Helix IAM as code — version your realms, applications, and roles in the same workflow as the rest of your infrastructure.

## What it is

`terraform-provider-helix` lets you declare Helix resources in HCL and reconcile them with `terraform apply`. Configuration becomes reviewable, repeatable, and promotable between environments — no click-ops drift.

Available resources include:

| Resource | Manages |
| --- | --- |
| `helix_realm` | A [realm](../manage/realms.md) — the isolated tenant boundary |
| `helix_client` | An [OIDC client](../manage/oidc-clients.md) under `/admin/realms/{realm}/clients` |
| `helix_application` | An [application](../manage/applications.md) and its OIDC/SAML client |
| `helix_user` | A [user](../manage/users.md) under `/admin/realms/{realm}/users` |
| `helix_realm_role` | A [realm role](../manage/roles.md) |

## Authentication

The provider authenticates with **OAuth2 client credentials**. Configure it inline or via environment variables (`HELIX_ISSUER`, `HELIX_REALM`, `HELIX_CLIENT_ID`, `HELIX_CLIENT_SECRET`), which take over when the matching argument is omitted.

```hcl
terraform {
  required_providers {
    helix = {
      source = "helix-iam/helix"
    }
  }
}

provider "helix" {
  issuer        = "https://auth.example.com"
  realm         = "acme"
  client_id     = "terraform"
  client_secret = var.helix_client_secret # or HELIX_CLIENT_SECRET
}
```

!!! tip "Use a dedicated automation client"
    Create a confidential client for Terraform with just the admin scopes it needs, and supply the secret via `HELIX_CLIENT_SECRET` so it never lands in state or VCS.

## Usage

A complete example — declare a realm, a confidential OIDC client, a realm role, and a user, then wire them together. The resource arguments mirror the admin API bodies documented in the [API reference](api-reference.md).

```hcl
# The tenant boundary
resource "helix_realm" "acme" {
  name         = "acme"
  display_name = "Acme"
  enabled      = true
}

# A confidential OIDC client (mints a secret — keep it out of VCS)
resource "helix_client" "web" {
  realm          = helix_realm.acme.name
  client_id      = "acme-web"
  name           = "Acme Web"
  public_client  = false
  grant_types    = ["authorization_code", "refresh_token"]
  redirect_uris  = ["https://app.example.com/callback"]
  web_origins    = ["https://app.example.com"]
}

# A realm role
resource "helix_realm_role" "billing_admin" {
  realm       = helix_realm.acme.name
  name        = "billing-admin"
  description = "Manage billing"
}

# A user, granted the role above
resource "helix_user" "jane" {
  realm    = helix_realm.acme.name
  username = "jane"
  email    = "jane@example.com"
  enabled  = true
  roles    = [helix_realm_role.billing_admin.name]
}
```

```bash
terraform init
terraform plan
terraform apply
```

!!! warning "Client secrets land in state"
    A confidential `helix_client` returns a secret that Terraform stores in state. Use a remote backend with encryption and restricted access, or provision the client as `public_client = true` (PKCE) where a secret is not needed.

## See also

- [Manage applications](../manage/applications.md)
- [Roles](../manage/roles.md)
- [Import / export & migration](import-export.md)
- [TypeScript SDK](sdk-typescript.md)
