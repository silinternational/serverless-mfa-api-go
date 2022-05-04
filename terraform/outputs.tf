output "serverless_user_key_secret" {
  value     = "${module.serverless-user.aws_access_key_id},${module.serverless-user.aws_secret_access_key}"
  sensitive = true
}

output "lambda_role_arn" {
  value = aws_iam_role.lambdaRole.arn
}