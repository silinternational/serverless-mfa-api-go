// Docs: https://registry.terraform.io/modules/silinternational/serverless-user/aws/latest
// Create IAM user with permissions to create lambda function, API gateway, etc.
module "serverless-user" {
  source             = "silinternational/serverless-user/aws"
  version            = "0.0.11"
  app_name           = var.app_name
  aws_region         = var.aws_region
  enable_api_gateway = true
  extra_policies     = var.extra_policies
}