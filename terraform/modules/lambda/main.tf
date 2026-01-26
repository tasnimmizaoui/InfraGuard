# ============================================
# Lambda Module - Automated Security Scanning
# ============================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ============================================
# Package InfraGuard Code
# ============================================

# Create Lambda deployment package with both infra_guard module and lambda_handler
data "archive_file" "infraguard_lambda" {
  type        = "zip"
  output_path = "${path.module}/lambda_function.zip"
  
  source {
    content  = file("${path.root}/../lambda_handler.py")
    filename = "lambda_handler.py"
  }
  
  source {
    content  = file("${path.root}/../infra_guard/__init__.py")
    filename = "infra_guard/__init__.py"
  }
  
  source {
    content  = file("${path.root}/../infra_guard/config.py")
    filename = "infra_guard/config.py"
  }
  
  source {
    content  = file("${path.root}/../infra_guard/utils.py")
    filename = "infra_guard/utils.py"
  }
  
  source {
    content  = file("${path.root}/../infra_guard/detection_rules.py")
    filename = "infra_guard/detection_rules.py"
  }
  
  source {
    content  = file("${path.root}/../infra_guard/alerting.py")
    filename = "infra_guard/alerting.py"
  }
  
  source {
    content  = file("${path.root}/../infra_guard/log_ingestion.py")
    filename = "infra_guard/log_ingestion.py"
  }
}

# ============================================
# Lambda Function
# ============================================

resource "aws_lambda_function" "infraguard_scanner" {
  filename         = data.archive_file.infraguard_lambda.output_path
  function_name    = var.function_name
  role             = var.lambda_role_arn
  handler          = "lambda_handler.handler"
  source_code_hash = data.archive_file.infraguard_lambda.output_base64sha256
  runtime          = var.python_runtime
  timeout          = var.timeout
  memory_size      = var.memory_size

  environment {
    variables = merge(
      {
        INFRAGUARD_S3_BUCKET     = var.s3_bucket_name
        INFRAGUARD_SNS_TOPIC_ARN = var.sns_topic_arn
        INFRAGUARD_LOG_LEVEL     = var.log_level
      },
      var.environment_variables
    )
  }

  tags = merge(
    var.tags,
    {
      Name        = "InfraGuard Scanner"
      Description = "Automated AWS security scanning"
    }
  )
}

# ============================================
# CloudWatch Logs for Lambda
# ============================================

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${aws_lambda_function.infraguard_scanner.function_name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

# ============================================
# EventBridge Rule for Scheduling
# ============================================

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.function_name}-schedule"
  description         = "Trigger InfraGuard security scans"
  schedule_expression = var.schedule_expression

  tags = merge(
    var.tags,
    {
      Name = "InfraGuard Scan Schedule"
    }
  )
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "InfraGuardLambda"
  arn       = aws_lambda_function.infraguard_scanner.arn
}

# Grant EventBridge permission to invoke Lambda
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.infraguard_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

# ============================================
# Optional: Lambda Function URL (for manual triggering)
# ============================================

resource "aws_lambda_function_url" "infraguard" {
  count              = var.enable_function_url ? 1 : 0
  function_name      = aws_lambda_function.infraguard_scanner.function_name
  authorization_type = "AWS_IAM"
}
 