# Test Terraform configuration with SECURE settings
# This should pass InfraGuard's plan-time scanning with minimal or no issues

provider "aws" {
  region = "us-east-1"
}

# SECURE: S3 bucket with private ACL and encryption
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "test-secure-bucket-${random_id.suffix.hex}"

  tags = {
    Name        = "Test Secure Bucket"
    Environment = "Testing"
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "secure_bucket_block" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Enable versioning
resource "aws_s3_bucket_versioning" "secure_bucket_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

# SECURE: Security group with restricted SSH access
resource "aws_security_group" "restricted_ssh" {
  name        = "test-restricted-ssh"
  description = "Security group with SSH restricted to specific IP"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # SECURE: Restricted to private network
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Test Restricted SSH"
  }
}

# SECURE: IAM policy with least privilege
resource "aws_iam_policy" "restricted_policy" {
  name        = "test-restricted-policy"
  description = "Test policy with least privilege"

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
          "arn:aws:s3:::test-secure-bucket-*",
          "arn:aws:s3:::test-secure-bucket-*/*"
        ]
      }
    ]
  })
}
