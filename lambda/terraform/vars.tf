variable "app_name" {
  type        = string
  description = "A short name for this application, example: backup-service"
  default     = "serverless-mfa-api-go"
}

variable "app_env" {
  type        = string
  description = "Environment name, ex: prod, stage, dev"
}

variable "aws_access_key" {
  type        = string
  description = "Access Key ID for serverless framework user"
}

variable "aws_account_id" {
  type        = string
  description = "AWS Account ID for use in IAM policy resource references"
}

variable "aws_region" {
  type        = string
  description = "A valid AWS region where this lambda will be deployed"
}

variable "aws_secret_key" {
  type        = string
  description = "Secret access Key ID for serverless framework user"
}

variable "extra_policies" {
  type        = list(string)
  description = "Optionally provide additional inline policies to attach to user"
  default = [
    <<EOT
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:CreateTags",
        "ec2:DeleteTags",
        "iam:getRolePolicy",
        "logs:FilterLogEvents",
        "apigateway:UpdateRestApiPolicy"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
EOT
  ]
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

variable "webauthn_table" {
  type        = string
  description = "Override webauthn table name"
  default     = ""
}

variable "create_webauthn_table" {
  type    = bool
  default = true
}
