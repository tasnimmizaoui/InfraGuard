variable "cloudtrail_name" {
  description = "Name of the CloudTrail trail"
  type        = string
  default     = "infraguard-trail"
}

variable "multi_region_trail" {
  description = "Whether the trail should be multi-region"
  type        = bool
  default     = true
}

variable "s3_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail logs"
  type        = string
}

variable "s3_bucket_arn" {
  description = "ARN of the S3 bucket for logs"
  type        = string
}

variable "s3_bucket_policy_id" {
  description = "ID of the S3 bucket policy (for dependency)"
  type        = string
}

variable "cloudtrail_s3_prefix" {
  description = "S3 prefix for CloudTrail logs"
  type        = string
  default     = "cloudtrail/"
}

variable "enable_vpc_flow_logs" {
  description = "Whether to enable VPC Flow Logs for default VPC"
  type        = bool
  default     = true
}

variable "vpc_flow_logs_s3_prefix" {
  description = "S3 prefix for VPC Flow Logs"
  type        = string
  default     = "vpc-flow-logs/"
}

variable "additional_vpc_ids" {
  description = "List of additional VPC IDs to enable flow logs for"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
