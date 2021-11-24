variable "app_name" {
  type        = string
  description = "A short name for this application, example: backup-service"
  default     = "serverless-mfa-api-go"
}

variable "aws_access_key" {
  type        = string
  description = "Access Key ID for serverless framework user"
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
  default     = [
    <<EOT
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudformation:DescribeStacks",
        "ec2:CreateTags",
        "ec2:DeleteTags",
        "ec2:DescribeSecurityGroups",
        "iam:getRolePolicy",
        "logs:FilterLogEvents"
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