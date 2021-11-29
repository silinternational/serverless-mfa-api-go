// Docs: https://registry.terraform.io/modules/silinternational/serverless-user/aws/latest
// Create IAM user with permissions to create lambda function, API gateway, etc.
module "serverless-user" {
  source             = "silinternational/serverless-user/aws"
  version            = "0.0.11"
  app_name           = "${var.app_name}-${var.app_env}"
  aws_region         = var.aws_region
  enable_api_gateway = true
  extra_policies     = var.extra_policies
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
    aws_region     = var.aws_region
    aws_account    = var.aws_account_id
    app_name       = var.app_name
    app_env        = var.app_env
    api_key_table  = var.api_key_table != "" ? var.api_key_table : aws_dynamodb_table.apiKeyTable.name
    webauthn_table = var.webauthn_table != "" ? var.webauthn_table : aws_dynamodb_table.webauthnTable.name
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
