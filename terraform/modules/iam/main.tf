# ============================================
# IAM Module - User, Roles, and Policies
# ============================================

# Data source to get current AWS account ID
data "aws_caller_identity" "current" {}

# ============================================
# IAM User for InfraGuard Scanner (Read-Only)
# ============================================

resource "aws_iam_user" "infraguard_scanner" {
  name = var.scanner_user_name
  path = "/infraguard/"

  tags = merge(
    var.tags,
    {
      Name        = "InfraGuard Scanner User"
      Description = "Read-only user for InfraGuard security scanning"
    }
  )
}

# Attach AWS managed SecurityAudit policy (read-only)
resource "aws_iam_user_policy_attachment" "security_audit" {
  user       = aws_iam_user.infraguard_scanner.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Custom policy for S3 log access
resource "aws_iam_user_policy" "s3_log_access" {
  name = "InfraGuardS3LogAccess"
  user = aws_iam_user.infraguard_scanner.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.logs_bucket_arn,
          "${var.logs_bucket_arn}/*"
        ]
      }
    ]
  })
}

# SNS publish permission for alerts
resource "aws_iam_user_policy" "sns_publish" {
  name = "InfraGuardSNSPublish"
  user = aws_iam_user.infraguard_scanner.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = var.sns_topic_arn
      }
    ]
  })
}

# Create access key for programmatic access
resource "aws_iam_access_key" "infraguard_scanner" {
  user = aws_iam_user.infraguard_scanner.name
}

# Store access key in Secrets Manager (secure)
resource "aws_secretsmanager_secret" "infraguard_credentials" {
  name                    = "infraguard/scanner-credentials"
  description             = "InfraGuard scanner IAM user credentials"
  recovery_window_in_days = 0  # Force immediate deletion to allow recreation

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "infraguard_credentials" {
  secret_id = aws_secretsmanager_secret.infraguard_credentials.id
  secret_string = jsonencode({
    access_key_id     = aws_iam_access_key.infraguard_scanner.id
    secret_access_key = aws_iam_access_key.infraguard_scanner.secret
    user_name         = aws_iam_user.infraguard_scanner.name
  })
}

# ============================================
# IAM Role for Lambda Execution
# ============================================

# Trust policy for Lambda
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

# Lambda execution role
resource "aws_iam_role" "lambda_execution" {
  count              = var.create_lambda_role ? 1 : 0
  name               = var.lambda_role_name
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = merge(
    var.tags,
    {
      Name = "InfraGuard Lambda Execution Role"
    }
  )
}

# Attach AWS managed policies for Lambda
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  count      = var.create_lambda_role ? 1 : 0
  role       = aws_iam_role.lambda_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_security_audit" {
  count      = var.create_lambda_role ? 1 : 0
  role       = aws_iam_role.lambda_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Custom policy for Lambda to access S3 logs and SNS
resource "aws_iam_role_policy" "lambda_custom" {
  count = var.create_lambda_role ? 1 : 0
  name  = "InfraGuardLambdaCustomPolicy"
  role  = aws_iam_role.lambda_execution[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.logs_bucket_arn,
          "${var.logs_bucket_arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = var.sns_topic_arn != "" ? var.sns_topic_arn : "*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.infraguard_credentials.arn
      }
    ]
  })
} 