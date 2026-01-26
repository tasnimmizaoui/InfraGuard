variable "bucket_name" {
  description = "Name of the S3 bucket for logs (leave empty to auto-generate)"
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "Number of days to retain logs before deletion (cost control)"
  type        = number
  default     = 90
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
