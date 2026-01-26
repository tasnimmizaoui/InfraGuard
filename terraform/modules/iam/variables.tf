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

variable "create_lambda_role" {
  description = "Whether to create IAM role for Lambda execution"
  type        = bool
  default     = true
}

variable "logs_bucket_arn" {
  description = "ARN of the S3 bucket for logs"
  type        = string
}

variable "sns_topic_arn" {
  description = "ARN of the SNS topic for alerts"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
