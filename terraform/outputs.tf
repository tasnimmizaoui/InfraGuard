# ============================================
# General Outputs
# ============================================

output "account_id" {
  description = "AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "AWS Region"
  value       = data.aws_region.current.name
}

# ============================================
# Storage Outputs
# ============================================

output "logs_bucket_name" {
  description = "Name of the S3 bucket for logs"
  value       = module.storage.bucket_name
}

output "logs_bucket_arn" {
  description = "ARN of the S3 bucket for logs"
  value       = module.storage.bucket_arn
}

# ============================================
# IAM Outputs
# ============================================

output "scanner_user_name" {
  description = "Name of the InfraGuard scanner IAM user"
  value       = module.iam.scanner_user_name
}

output "scanner_access_key_id" {
  description = "Access Key ID for InfraGuard scanner (SENSITIVE)"
  value       = module.iam.scanner_access_key_id
  sensitive   = true
}

output "scanner_secret_access_key" {
  description = "Secret Access Key for InfraGuard scanner (SENSITIVE)"
  value       = module.iam.scanner_secret_access_key
  sensitive   = true
}

output "credentials_secret_arn" {
  description = "ARN of Secrets Manager secret containing scanner credentials"
  value       = module.iam.credentials_secret_arn
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = module.iam.lambda_role_arn
}

# ============================================
# Logging Outputs
# ============================================

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = module.logging.cloudtrail_arn
}

output "cloudtrail_id" {
  description = "ID of the CloudTrail trail"
  value       = module.logging.cloudtrail_id
}

output "vpc_flow_log_ids" {
  description = "IDs of the VPC Flow Logs"
  value       = module.logging.vpc_flow_log_ids
}

# ============================================
# Alerting Outputs
# ============================================

output "sns_topic_arn" {
  description = "ARN of the SNS topic for alerts"
  value       = module.alerting.topic_arn
}

output "sns_topic_name" {
  description = "Name of the SNS topic"
  value       = module.alerting.topic_name
}

# ============================================
# Lambda Outputs
# ============================================

output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = var.enable_lambda_deployment ? module.lambda[0].function_name : "Not deployed"
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = var.enable_lambda_deployment ? module.lambda[0].function_arn : "Not deployed"
}

output "lambda_schedule_rule_arn" {
  description = "ARN of the EventBridge schedule rule"
  value       = var.enable_lambda_deployment ? module.lambda[0].schedule_rule_arn : "Not deployed"
}

output "lambda_function_url" {
  description = "URL of the Lambda function (if enabled)"
  value       = var.enable_lambda_deployment && var.enable_lambda_function_url ? module.lambda[0].function_url : "Not enabled"
}

# ============================================
# Quick Start Instructions
# ============================================

output "quick_start_instructions" {
  description = "Instructions for getting started with InfraGuard"
  value = <<-EOT
    
    ╔══════════════════════════════════════════════════════════════════╗
    ║          InfraGuard Infrastructure Successfully Deployed!        ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    📋 Next Steps:
    
    1. Retrieve Scanner Credentials (stored securely in Secrets Manager):
       aws secretsmanager get-secret-value --secret-id ${module.iam.credentials_secret_arn} --query SecretString --output text
    
    2. Configure Local Environment:
       export AWS_ACCESS_KEY_ID="<from step 1>"
       export AWS_SECRET_ACCESS_KEY="<from step 1>"
       export AWS_REGION="${data.aws_region.current.name}"
       export INFRAGUARD_S3_BUCKET="${module.storage.bucket_name}"
       export INFRAGUARD_SNS_TOPIC_ARN="${module.alerting.topic_arn}"
    
    3. Run InfraGuard Locally (optional):
       cd ..
       python main.py check-all
    
    ${var.enable_lambda_deployment ? "4. Lambda Function Deployed:\n       - Function: ${module.lambda[0].function_name}\n       - Schedule: ${var.lambda_schedule}\n       - Automated scans will run daily at 9 AM UTC\n       - Check logs: aws logs tail /aws/lambda/${module.lambda[0].function_name} --follow" : "4. Lambda deployment disabled - run scans manually"}
    
    ${length(var.alert_email_addresses) > 0 ? "5. Confirm SNS Email Subscriptions:\n       Check your email(s) for SNS confirmation links" : "5. No email alerts configured - add emails to alert_email_addresses variable"}
    
    📊 Resources Created:
    - S3 Bucket: ${module.storage.bucket_name}
    - CloudTrail: ${module.logging.cloudtrail_id}
    - VPC Flow Logs: ${length(module.logging.vpc_flow_log_ids)} enabled
    - SNS Topic: ${module.alerting.topic_name}
    - IAM User: ${module.iam.scanner_user_name}
    ${var.enable_lambda_deployment ? "- Lambda: ${module.lambda[0].function_name}" : ""}
    
    💰 Estimated Monthly Cost: $1-3 (mostly VPC Flow Logs)
    
    🔒 Security: All credentials stored in AWS Secrets Manager
    
    For more information, see README.md in the parent directory.
    
  EOT
}
