output "scanner_user_name" {
  description = "Name of the InfraGuard scanner IAM user"
  value       = aws_iam_user.infraguard_scanner.name
}

output "scanner_user_arn" {
  description = "ARN of the InfraGuard scanner IAM user"
  value       = aws_iam_user.infraguard_scanner.arn
}

output "scanner_access_key_id" {
  description = "Access key ID for InfraGuard scanner (sensitive)"
  value       = aws_iam_access_key.infraguard_scanner.id
  sensitive   = true
}

output "scanner_secret_access_key" {
  description = "Secret access key for InfraGuard scanner (sensitive)"
  value       = aws_iam_access_key.infraguard_scanner.secret
  sensitive   = true
}

output "credentials_secret_arn" {
  description = "ARN of the Secrets Manager secret containing scanner credentials"
  value       = aws_secretsmanager_secret.infraguard_credentials.arn
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = var.create_lambda_role ? aws_iam_role.lambda_execution[0].arn : ""
}

output "lambda_role_name" {
  description = "Name of the Lambda execution role"
  value       = var.create_lambda_role ? aws_iam_role.lambda_execution[0].name : ""
}
