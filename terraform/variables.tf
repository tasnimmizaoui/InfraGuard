# ============================================
# General Configuration
# ============================================

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "infraguard"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "default_tags" {
  description = "Default tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "InfraGuard"
    ManagedBy   = "Terraform"
    Environment = "Production"
  }
}

variable "resource_tags" {
  description = "Additional tags for specific resources"
  type        = map(string)
  default     = {}
}

# ============================================
# Storage Configuration
# ============================================

variable "s3_bucket_name" {
  description = "Name of S3 bucket for logs (leave empty for auto-generated name)"
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "Number of days to retain logs before deletion"
  type        = number
  default     = 90
}

# ============================================
# IAM Configuration
# ============================================

variable "scanner_user_name" {
  description = "Name of the IAM user for InfraGuard scanner"
  type        = string
  default     = "infraguard-scanner"
}

variable "lambda_role_name" {
  description = "Name of the IAM role for Lambda execution"
  type        = string
  default     = "InfraGuardLambdaRole"
}

# ============================================
# Logging Configuration
# ============================================

variable "cloudtrail_name" {
  description = "Name of the CloudTrail trail"
  type        = string
  default     = "infraguard-trail"
}

variable "multi_region_trail" {
  description = "Whether CloudTrail should be multi-region"
  type        = bool
  default     = true
}

variable "enable_vpc_flow_logs" {
  description = "Whether to enable VPC Flow Logs for default VPC"
  type        = bool
  default     = true
}

variable "additional_vpc_ids" {
  description = "List of additional VPC IDs to enable flow logs"
  type        = list(string)
  default     = []
}

# ============================================
# Alerting Configuration
# ============================================

variable "sns_topic_name" {
  description = "Name of the SNS topic for alerts"
  type        = string
  default     = "infraguard-alerts"
}

variable "alert_email_addresses" {
  description = "List of email addresses to receive alerts"
  type        = list(string)
  default     = []
  # Example: ["security@example.com", "admin@example.com"]
}

variable "alert_sms_numbers" {
  description = "List of phone numbers (E.164 format) to receive SMS alerts"
  type        = list(string)
  default     = []
  # Example: ["+12345678901"]
}

# ============================================
# Lambda Configuration
# ============================================

variable "enable_lambda_deployment" {
  description = "Whether to deploy Lambda function for automated scans"
  type        = bool
  default     = true
}

variable "lambda_function_name" {
  description = "Name of the Lambda function"
  type        = string
  default     = "infraguard-scanner"
}

variable "lambda_python_runtime" {
  description = "Python runtime for Lambda"
  type        = string
  default     = "python3.11"
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds (max 900)"
  type        = number
  default     = 300
}

variable "lambda_memory_size" {
  description = "Lambda memory in MB"
  type        = number
  default     = 512
}

variable "lambda_log_level" {
  description = "Log level for Lambda function"
  type        = string
  default     = "INFO"
  validation {
    condition     = contains(["DEBUG", "INFO", "WARNING", "ERROR"], var.lambda_log_level)
    error_message = "Log level must be DEBUG, INFO, WARNING, or ERROR."
  }
}

variable "lambda_schedule" {
  description = "Schedule expression for Lambda (cron or rate)"
  type        = string
  default     = "cron(0 9 * * ? *)" # Daily at 9 AM UTC
}

variable "lambda_log_retention_days" {
  description = "Number of days to retain Lambda logs"
  type        = number
  default     = 30
}

variable "enable_lambda_function_url" {
  description = "Enable Lambda function URL for manual invocation"
  type        = bool
  default     = false
}

variable "lambda_environment_variables" {
  description = "Additional environment variables for Lambda"
  type        = map(string)
  default     = {}
}
variable "github_sha" {
  description = "Git commit SHA"
  type        = string
  default     = "unknown"
}