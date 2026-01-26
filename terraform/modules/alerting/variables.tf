variable "topic_name" {
  description = "Name of the SNS topic for alerts"
  type        = string
  default     = "infraguard-alerts"
}

variable "email_addresses" {
  description = "List of email addresses to subscribe to alerts"
  type        = list(string)
  default     = []
}

variable "sms_numbers" {
  description = "List of phone numbers (E.164 format) to subscribe via SMS"
  type        = list(string)
  default     = []
}

variable "publisher_arns" {
  description = "List of IAM principal ARNs allowed to publish to this topic"
  type        = list(string)
  default     = []
}

variable "enable_encryption" {
  description = "Whether to enable SNS encryption at rest"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
