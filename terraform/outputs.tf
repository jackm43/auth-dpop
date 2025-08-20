output "app_client_id" {
  description = "Okta OAuth app client ID"
  value       = okta_app_oauth.api_service_app.client_id
}

output "app_client_secret" {
  description = "Okta OAuth app client secret"
  value       = okta_app_oauth.api_service_app.client_secret
  sensitive   = true
}

output "secondary_app_client_id" {
  description = "Secondary Okta OAuth app client ID"
  value       = okta_app_oauth.secondary_service_app.client_id
}

output "org_issuer" {
  description = "Organization issuer URL"
  value       = "https://${var.okta_org_name}.${var.okta_base_url}/oauth2"
}

output "dpop_issuer" {
  description = "Custom dpop authorization server issuer URL"
  value       = "https://${var.okta_org_name}.${var.okta_base_url}/oauth2/${okta_auth_server.dpop.id}"
}