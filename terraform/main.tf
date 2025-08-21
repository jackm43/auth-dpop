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

# Custom API scopes on the dpop authorization server
resource "okta_auth_server_scope" "app_read" {
  auth_server_id = okta_auth_server.dpop.id
  name           = "app.read"
  description    = "Read access to application API"
  consent        = "IMPLICIT"
}

resource "okta_auth_server_scope" "app_write" {
  auth_server_id = okta_auth_server.dpop.id
  name           = "app.write"
  description    = "Write access to application API"
  consent        = "IMPLICIT"
}



# Access policy allowing service apps to get tokens via client_credentials
resource "okta_auth_server_policy" "dpop_service_policy" {
  auth_server_id = okta_auth_server.dpop.id
  name           = "Service Policy"
  description    = "Allow client_credentials for service apps"
  status         = "ACTIVE"
  client_whitelist = [
    okta_app_oauth.api_service_app.id,
    okta_app_oauth.secondary_service_app.id
  ]
  priority       = 1
}

resource "okta_auth_server_policy_rule" "allow_service_cc" {
  policy_id             = okta_auth_server_policy.dpop_service_policy.id
  name                  = "Allow client_credentials"
  priority              = 1
  status                = "ACTIVE"
  grant_type_whitelist  = ["client_credentials"]
  scope_whitelist       = [
    okta_auth_server_scope.app_read.name,
    okta_auth_server_scope.app_write.name
  ]

  auth_server_id = okta_auth_server.dpop.id
}

# Secondary service app (for multi-app support)
resource "okta_app_oauth" "secondary_service_app" {
  label                      = var.secondary_app_label
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

resource "okta_app_oauth_api_scope" "secondary_users_read" {
  app_id = okta_app_oauth.secondary_service_app.id
  issuer = "https://${var.okta_org_name}.${var.okta_base_url}"
  scopes = ["okta.users.read"]
}

# Web application for authorization code flow with refresh tokens
resource "okta_app_oauth" "web_app" {
  label                      = var.web_app_label
  type                       = "web"
  grant_types                = ["authorization_code", "refresh_token"]
  token_endpoint_auth_method = "private_key_jwt"
  response_types             = ["code"]
  redirect_uris              = ["http://localhost:8080/callback", "http://127.0.0.1:8080/callback"]
  post_logout_redirect_uris  = ["http://localhost:8080/logout"]
  
  jwks {
    kid = local.cc.kid
    kty = local.cc.kty
    n   = local.cc.n
    e   = local.cc.e
  }
}

# Add the refresh scope for refresh tokens
resource "okta_auth_server_scope" "refresh" {
  auth_server_id = okta_auth_server.dpop.id
  name           = "refresh"
  description    = "Refresh token access"
  consent        = "IMPLICIT"
}

# Policy for web application authorization code flow
resource "okta_auth_server_policy" "web_app_policy" {
  auth_server_id = okta_auth_server.dpop.id
  name           = "Web App Policy"
  description    = "Allow authorization_code and refresh_token for web apps"
  status         = "ACTIVE"
  client_whitelist = [
    okta_app_oauth.web_app.id
  ]
  priority       = 2
}

resource "okta_auth_server_policy_rule" "allow_web_auth_code" {
  policy_id             = okta_auth_server_policy.web_app_policy.id
  name                  = "Allow authorization_code and refresh_token"
  priority              = 1
  status                = "ACTIVE"
  grant_type_whitelist  = ["authorization_code"]
  scope_whitelist       = [
    okta_auth_server_scope.app_read.name,
    okta_auth_server_scope.app_write.name,
    okta_auth_server_scope.refresh.name
  ]
  
  # Allow all users by including the Everyone group
  group_whitelist = ["EVERYONE"]

  auth_server_id = okta_auth_server.dpop.id
}