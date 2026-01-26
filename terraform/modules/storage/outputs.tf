output "bucket_name" {
  description = "Name of the S3 bucket for logs"
  value       = aws_s3_bucket.logs.id
}

output "bucket_arn" {
  description = "ARN of the S3 bucket for logs"
  value       = aws_s3_bucket.logs.arn
}

output "bucket_domain_name" {
  description = "Domain name of the S3 bucket"
  value       = aws_s3_bucket.logs.bucket_domain_name
}

output "cloudtrail_prefix" {
  description = "S3 prefix for CloudTrail logs"
  value       = "cloudtrail/"
}

output "vpc_flow_logs_prefix" {
  description = "S3 prefix for VPC Flow Logs"
  value       = "vpc-flow-logs/"
}
