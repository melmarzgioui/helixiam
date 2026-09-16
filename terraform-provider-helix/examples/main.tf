terraform {
  required_providers {
    helix = {
      source = "kubedna/helix"
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
