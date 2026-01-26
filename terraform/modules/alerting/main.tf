# ============================================
# Alerting Module - SNS Topic for Alerts
# ============================================

# ============================================
# SNS Topic for InfraGuard Alerts
# ============================================

resource "aws_sns_topic" "infraguard_alerts" {
  name              = var.topic_name
  display_name      = "InfraGuard Security Alerts"
  kms_master_key_id = var.enable_encryption ? "alias/aws/sns" : null

  tags = merge(
    var.tags,
    {
      Name        = "InfraGuard Alerts Topic"
      Description = "SNS topic for InfraGuard security alerts"
    }
  )
}

# ============================================
# Email Subscriptions
# ============================================

resource "aws_sns_topic_subscription" "email" {
  for_each  = toset(var.email_addresses)
  topic_arn = aws_sns_topic.infraguard_alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# ============================================
# SMS Subscriptions (Optional)
# ============================================

resource "aws_sns_topic_subscription" "sms" {
  for_each  = toset(var.sms_numbers)
  topic_arn = aws_sns_topic.infraguard_alerts.arn
  protocol  = "sms"
  endpoint  = each.value
}

# ============================================
# SNS Topic Policy
# ============================================

data "aws_iam_policy_document" "sns_topic_policy" {
  dynamic "statement" {
    for_each = length(var.publisher_arns) > 0 ? [1] : []
    content {
      sid    = "AllowInfraGuardPublish"
      effect = "Allow"

      principals {
        type        = "AWS"
        identifiers = var.publisher_arns
      }

      actions = [
        "SNS:Publish"
      ]

      resources = [
        aws_sns_topic.infraguard_alerts.arn
      ]
    }
  }

  # Allow CloudWatch Alarms to publish (optional for future use)
  statement {
    sid    = "AllowCloudWatchAlarms"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    actions = [
      "SNS:Publish"
    ]

    resources = [
      aws_sns_topic.infraguard_alerts.arn
    ]
  }
}

resource "aws_sns_topic_policy" "infraguard_alerts" {
  arn    = aws_sns_topic.infraguard_alerts.arn
  policy = data.aws_iam_policy_document.sns_topic_policy.json
}
