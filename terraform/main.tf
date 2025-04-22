locals {
  stage_for_api = var.app_env == "dev" ? var.app_env : var.app_environment
  api_name      = "${var.app_name}-${local.stage_for_api}"
}

/*
 * Module docs: https://registry.terraform.io/modules/silinternational/serverless-user/aws/latest
 * Create IAM user with permissions to create lambda function, API gateway, etc.
*/
module "serverless-user" {
  source  = "silinternational/serverless-user/aws"
  version = "~> 0.4.2"

  app_name           = "${var.app_name}-${var.app_env}"
  aws_region_policy  = "*"
  enable_api_gateway = true
  extra_policies     = var.extra_policies
}

// Set up custom domain name for easier fail-over.
module "dns_for_failover" {
  source  = "silinternational/serverless-api-dns-for-failover/aws"
  version = "~> 0.6.0"

  api_name             = local.api_name
  cloudflare_zone_name = var.cloudflare_domain
  serverless_stage     = local.stage_for_api
  subdomain            = var.app_name

  providers = {
    aws           = aws
    aws.secondary = aws.secondary
  }
}

// Create role for lambda function
resource "aws_iam_role" "lambdaRole" {
  name = "${var.app_name}-${var.app_env}-lambdaRole"

  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "lambda.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
}

data "template_file" "lambdaRolePolicy" {
  template = file("${path.module}/lambda-role-policy.json")
  vars = {
    aws_account    = var.aws_account_id
    app_name       = var.app_name
    app_env        = var.app_env
    api_key_table  = coalesce(var.api_key_table, aws_dynamodb_table.apiKeyTable[0].name)
    totp_table     = coalesce(var.totp_table, aws_dynamodb_table.totp[0].name)
    webauthn_table = coalesce(var.webauthn_table, aws_dynamodb_table.webauthnTable[0].name)
  }
}

resource "aws_iam_role_policy" "lambdaRolePolicy" {
  name   = "${var.app_name}-${var.app_env}-lambdaRolePolicy"
  role   = aws_iam_role.lambdaRole.id
  policy = data.template_file.lambdaRolePolicy.rendered
}

// Create DynamoDB tables
resource "aws_dynamodb_table" "apiKeyTable" {
  count        = var.create_api_key_table ? 1 : 0
  name         = "${var.app_name}-${var.app_env}-api-key"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "value"

  attribute {
    name = "value"
    type = "S"
  }

  tags = {
    app_name = var.app_name
    app_env  = var.app_env
  }
}

resource "aws_dynamodb_table" "totp" {
  count = var.create_totp_table ? 1 : 0

  name                        = "${var.app_name}_${var.app_env}_totp_global"
  hash_key                    = "uuid"
  billing_mode                = "PAY_PER_REQUEST"
  deletion_protection_enabled = true
  stream_enabled              = true
  stream_view_type            = "NEW_IMAGE"

  attribute {
    name = "uuid"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  replica {
    region_name = var.aws_region_secondary
  }

  lifecycle {
    ignore_changes = [replica]
  }
}

resource "aws_dynamodb_table" "webauthnTable" {
  count        = var.create_webauthn_table ? 1 : 0
  name         = "${var.app_name}-${var.app_env}-webauthn"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "uuid"

  attribute {
    name = "uuid"
    type = "S"
  }

  tags = {
    app_name = var.app_name
    app_env  = var.app_env
  }
}
