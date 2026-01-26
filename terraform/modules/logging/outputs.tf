output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.infraguard.arn
}

output "cloudtrail_id" {
  description = "ID of the CloudTrail trail"
  value       = aws_cloudtrail.infraguard.id
}

output "cloudtrail_home_region" {
  description = "Home region of the CloudTrail trail"
  value       = aws_cloudtrail.infraguard.home_region
}

output "vpc_flow_log_ids" {
  description = "IDs of the VPC Flow Logs"
  value = concat(
    var.enable_vpc_flow_logs ? [aws_flow_log.default_vpc[0].id] : [],
    [for fl in aws_flow_log.additional_vpcs : fl.id]
  )
}
