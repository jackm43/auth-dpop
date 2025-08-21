variable "okta_org_name" {
  description = "Okta organization name (subdomain)"
  type        = string
  default     = "integrator-3111559"
}

variable "okta_base_url" {
  description = "Okta base URL (e.g., okta.com, okta-emea.com)"
  type        = string
  default     = "okta.com"
}

variable "okta_api_token" {
  description = "Okta API token for Terraform provider authentication"
  type        = string
  sensitive   = true
}

variable "app_label" {
  description = "Label for the Okta API service application"
  type        = string
  default     = "DPoP API Service App"
}

variable "secondary_app_label" {
  description = "Label for the secondary Okta API service application"
  type        = string
  default     = "DPoP Secondary Service App"
}

variable "web_app_label" {
  description = "Label for the Okta web application with authorization code flow"
  type        = string
  default     = "DPoP Web App with Refresh Tokens"
}