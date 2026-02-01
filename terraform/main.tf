# ============================================
# InfraGuard Terraform Root Module
# ============================================

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.default_tags
  }
}

# ============================================
# Data Sources
# ============================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ============================================
# Storage Module - S3 Buckets
# ============================================

module "storage" {
  source = "./modules/storage"

  bucket_name        = var.s3_bucket_name
  log_retention_days = var.log_retention_days
  tags               = var.resource_tags
}

# ============================================
# Alerting Module - SNS Topic
# ============================================

module "alerting" {
  source = "./modules/alerting"

  topic_name        = var.sns_topic_name
  email_addresses   = var.alert_email_addresses
  sms_numbers       = var.alert_sms_numbers
  publisher_arns    = [] # Will be populated after IAM module
  enable_encryption = false
  tags              = var.resource_tags
}

# ============================================
# IAM Module - Users and Roles
# ============================================

module "iam" {
  source = "./modules/iam"

  scanner_user_name  = var.scanner_user_name
  lambda_role_name   = var.lambda_role_name
  create_lambda_role = var.enable_lambda_deployment
  logs_bucket_arn    = module.storage.bucket_arn
  sns_topic_arn      = module.alerting.topic_arn
  tags               = var.resource_tags
}

# ============================================
# Logging Module - CloudTrail and VPC Flow Logs
# ============================================

module "logging" {
  source = "./modules/logging"

  cloudtrail_name         = var.cloudtrail_name
  multi_region_trail      = var.multi_region_trail
  s3_bucket_name          = module.storage.bucket_name
  s3_bucket_arn           = module.storage.bucket_arn
  s3_bucket_policy_id     = module.storage.bucket_name # For dependency
  cloudtrail_s3_prefix    = module.storage.cloudtrail_prefix
  enable_vpc_flow_logs    = var.enable_vpc_flow_logs
  vpc_flow_logs_s3_prefix = module.storage.vpc_flow_logs_prefix
  additional_vpc_ids      = var.additional_vpc_ids
  tags                    = var.resource_tags

  depends_on = [module.storage]
}

# ============================================
# Lambda Module - Automated Scanning (Optional)
# ============================================

module "lambda" {
  count  = var.enable_lambda_deployment ? 1 : 0
  source = "./modules/lambda"

  function_name         = var.lambda_function_name
  lambda_role_arn       = module.iam.lambda_role_arn
  s3_bucket_name        = module.storage.bucket_name
  sns_topic_arn         = module.alerting.topic_arn
  python_runtime        = var.lambda_python_runtime
  timeout               = var.lambda_timeout
  memory_size           = var.lambda_memory_size
  log_level             = var.lambda_log_level
  schedule_expression   = var.lambda_schedule
  log_retention_days    = var.lambda_log_retention_days
  enable_function_url   = var.enable_lambda_function_url
  environment_variables = var.lambda_environment_variables
  tags                  = var.resource_tags

  depends_on = [module.iam, module.storage, module.alerting, module.logging]
}
