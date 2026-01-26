output "function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.infraguard_scanner.function_name
}

output "function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.infraguard_scanner.arn
}

output "function_invoke_arn" {
  description = "Invoke ARN of the Lambda function"
  value       = aws_lambda_function.infraguard_scanner.invoke_arn
}

output "log_group_name" {
  description = "Name of the CloudWatch Log Group"
  value       = aws_cloudwatch_log_group.lambda.name
}

output "schedule_rule_arn" {
  description = "ARN of the EventBridge schedule rule"
  value       = aws_cloudwatch_event_rule.schedule.arn
}

output "function_url" {
  description = "URL of the Lambda function (if enabled)"
  value       = var.enable_function_url ? aws_lambda_function_url.infraguard[0].function_url : ""
}
