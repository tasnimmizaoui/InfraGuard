variable "function_name" {
  description = "Name of the Lambda function"
  type        = string
  default     = "infraguard-scanner"
}

variable "lambda_role_arn" {
  description = "ARN of the IAM role for Lambda execution"
  type        = string
}

variable "s3_bucket_name" {
  description = "Name of the S3 bucket for logs"
  type        = string
}

variable "sns_topic_arn" {
  description = "ARN of the SNS topic for alerts"
  type        = string
}

variable "python_runtime" {
  description = "Python runtime version for Lambda"
  type        = string
  default     = "python3.11"
}

variable "timeout" {
  description = "Lambda function timeout in seconds (max 900 = 15 minutes)"
  type        = number
  default     = 300
}

variable "memory_size" {
  description = "Lambda function memory in MB"
  type        = number
  default     = 512
}

variable "log_level" {
  description = "Logging level for InfraGuard"
  type        = string
  default     = "INFO"
}

variable "schedule_expression" {
  description = "CloudWatch Events schedule expression (cron or rate)"
  type        = string
  default     = "cron(0 9 * * ? *)" # Daily at 9 AM UTC
}

variable "log_retention_days" {
  description = "Number of days to retain Lambda logs"
  type        = number
  default     = 30
}

variable "enable_function_url" {
  description = "Whether to create a Lambda function URL for manual invocation"
  type        = bool
  default     = false
}

variable "environment_variables" {
  description = "Additional environment variables for Lambda"
  type        = map(string)
  default     = {}
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
