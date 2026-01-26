output "topic_arn" {
  description = "ARN of the SNS topic for alerts"
  value       = aws_sns_topic.infraguard_alerts.arn
}

output "topic_name" {
  description = "Name of the SNS topic"
  value       = aws_sns_topic.infraguard_alerts.name
}

output "topic_id" {
  description = "ID of the SNS topic"
  value       = aws_sns_topic.infraguard_alerts.id
}

output "email_subscriptions" {
  description = "List of email subscription ARNs"
  value       = [for sub in aws_sns_topic_subscription.email : sub.arn]
}

output "sms_subscriptions" {
  description = "List of SMS subscription ARNs"
  value       = [for sub in aws_sns_topic_subscription.sms : sub.arn]
}
