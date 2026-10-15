terraform {
  required_providers {
    helix = {
      source = "melmarzgioui/helix"
    }
  }
}

provider "helix" {
  issuer        = "https://idp.example.com/realms/master"
  realm         = "master"
  client_id     = var.helix_client_id
  client_secret = var.helix_client_secret
}

variable "helix_client_id" { type = string }
variable "helix_client_secret" {
  type      = string
  sensitive = true
}

# An Application (Service Provider) managed as code.
resource "helix_application" "billing" {
  name          = "billing"
  display_name  = "Billing Portal"
  description   = "Customer billing self-service"
  subject_claim = "email"
  enabled       = true
}

# A realm role.
resource "helix_realm_role" "billing_admin" {
  name        = "billing-admin"
  description = "Full access to the billing portal"
}

output "billing_role_id" {
  value = helix_realm_role.billing_admin.role_id
}

# An EUDI Wallet (OpenID4VP verifier) identity-provider connection. access_key_ref must already be
# imported into the realm (POST /admin/realms/{realm}/verifier-keys, docs/eudi-wallet.md §2.4 step 1) —
# Terraform does not manage signing keys.
resource "helix_wallet_identity_provider" "eudi_wallet" {
  alias        = "eudi-wallet"
  display_name = "EU Digital Identity Wallet"
  enabled      = true

  access_key_ref      = "software:gov/primary"
  trust_anchors       = file("${path.module}/pid-issuer-ca.pem")
  credential_formats  = ["dc+sd-jwt", "mso_mdoc"]

  pid_requested_claims = ["given_name", "family_name", "birthdate"]
  minimum_loa          = "http://eidas.europa.eu/LoA/high"

  # Left unset here: the server defaults this to on for x509_hash + direct_post.jwt (both defaults
  # above), off otherwise. Set explicitly only if every certificate in trust_anchors carries a
  # SubjectKeyIdentifier extension — otherwise `true` is refused.
  # dcql_trusted_authorities = true
  # dc_api_enabled          = true # W3C Digital Credentials API, where the browser supports it
  # dc_api_expected_origins = ["https://login.example.eu"]
}
