output "app_client_id" {
  description = "Okta OAuth app client ID"
  value       = okta_app_oauth.api_service_app.client_id
}

output "app_client_secret" {
  description = "Okta OAuth app client secret"
  value       = okta_app_oauth.api_service_app.client_secret
  sensitive   = true
}
