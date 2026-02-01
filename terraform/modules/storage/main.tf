# ============================================
# Storage Module - S3 Buckets for Logs
# ============================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ============================================
# S3 Bucket for CloudTrail and VPC Flow Logs
# ============================================

resource "aws_s3_bucket" "logs" {
  bucket = var.bucket_name != "" ? var.bucket_name : "infraguard-logs-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    var.tags,
    {
      Name        = "InfraGuard Logs Bucket"
      Description = "CloudTrail and VPC Flow Logs storage"
    }
  )
}

# Enable versioning for audit compliance
resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle policy to delete old logs (cost control)
resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "delete-old-cloudtrail-logs"
    status = "Enabled"

    filter {
      prefix = "cloudtrail/"
    }

    expiration {
      days = var.log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  rule {
    id     = "delete-old-vpc-flow-logs"
    status = "Enabled"

    filter {
      prefix = "vpc-flow-logs/"
    }

    expiration {
      days = var.log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# ============================================
# Bucket Policy for CloudTrail
# ============================================

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  # Allow CloudTrail to check bucket ACL : "Can i(cloudTrail ) enter the bucket ? "
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl"
    ]

    resources = [
      aws_s3_bucket.logs.arn
    ]
  }

  # Allow CloudTrail to write logs
  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:PutObject"
    ]

    resources = [
      "${aws_s3_bucket.logs.arn}/cloudtrail/*"
    ] # CloudTrail Can only write objects to the cloudtrail/ folder 

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    } # This is a security feature that ensures the bucket owner has full control over the objects written by CloudTrail and not cloudtrail service
    # Without this it would mean that cloud trail would own the objects it creates , logs , which is not desirable for security and compliance reasons
  }


  # Allow VPC Flow Logs to write
  statement {
    sid    = "AWSLogDeliveryWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = [
      "s3:PutObject"
    ]

    resources = [
      "${aws_s3_bucket.logs.arn}/vpc-flow-logs/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    } # Same as for cLoudtrail above 
  }

  # Allow VPC Flow Logs to check ACL
  statement {
    sid    = "AWSLogDeliveryAclCheck" # Statement Id for reference 
    effect = "Allow"

    principals {
      type        = "Service" # AWS service not an IAM user 
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl"
    ]

    resources = [
      aws_s3_bucket.logs.arn
    ]
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}
