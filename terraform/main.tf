terraform {
  required_version = ">= 1.0"
  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 4.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
}

provider "okta" {
  org_name  = var.okta_org_name
  base_url  = var.okta_base_url
  api_token = var.okta_api_token
}

locals {
  cc = jsondecode(file("../assets/cc_public_key.json")).keys[0]
}

resource "okta_app_oauth" "api_service_app" {
  label                      = var.app_label
  type                       = "service"
  grant_types                = ["client_credentials"]
  token_endpoint_auth_method = "private_key_jwt"
  response_types             = ["token"]
  jwks {
    kid = local.cc.kid
    kty = local.cc.kty
    n   = local.cc.n
    e   = local.cc.e
  }
}

resource "okta_app_oauth_api_scope" "users_read" {
  app_id = okta_app_oauth.api_service_app.id
  issuer = "https://${var.okta_org_name}.${var.okta_base_url}"
  scopes = ["okta.users.read"]
}

resource "okta_auth_server" "dpop" {
  audiences   = ["api://dpop"]
  description = "My dpop Auth Server"
  name        = "dpop"
  issuer_mode = "ORG_URL"
  status      = "ACTIVE"
}