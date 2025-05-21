variable "app_name" {
  type        = string
  description = "A short name for this application, example: backup-service"
  default     = "serverless-mfa-api-go"
}

variable "app_env" {
  type        = string
  description = "Environment name, ex: prod, stage, dev"
}

variable "aws_access_key_id" {
  type        = string
  description = "Access Key ID for user with permissions to create resources for serverless framework"
}

variable "aws_account_id" {
  type        = string
  description = "AWS Account ID for use in IAM policy resource references"
}

variable "aws_region" {
  description = "Primary AWS region where this lambda will be deployed"
  type        = string
}

variable "aws_region_secondary" {
  description = "Secondary AWS region where this lambda will be deployed"
  type        = string
}

variable "aws_secret_access_key" {
  type        = string
  description = "Secret access Key ID for user with permissions to create resources for serverless framework"
}

variable "api_key_table" {
  type        = string
  description = "Override api key table name"
  default     = ""
}

variable "create_api_key_table" {
  type    = bool
  default = true
}

variable "totp_table" {
  description = "Override totp table name"
  type        = string
  default     = null
}

variable "create_totp_table" {
  description = "enable the creation of a DynamoDB table for TOTP credentials"
  type        = bool
  default     = false
}

variable "webauthn_table" {
  type        = string
  description = "Override webauthn table name"
  default     = ""
}

variable "create_webauthn_table" {
  type    = bool
  default = true
}

variable "cloudflare_token" {
  description = "The Cloudflare limited access API token"
  type        = string
}

variable "cloudflare_domain" {
  description = "Cloudflare zone (domain) for DNS records"
  type        = string
}

/*
 * AWS tag values
 */

variable "app_customer" {
  description = "customer name to use for the itse_app_customer tag"
  type        = string
  default     = "shared"
}

variable "app_environment" {
  description = "environment name to use for the itse_app_environment tag, e.g. staging, production"
  type        = string
  default     = "production"
}

variable "app_name_tag" {
  description = "app name to use for the itse_app_name tag"
  type        = string
  default     = "idp"
}
