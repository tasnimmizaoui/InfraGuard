# Test Terraform configuration with intentional security issues
# This is used to test InfraGuard's plan-time scanning feature

provider "aws" {
  region = "us-east-1"
}

# ISSUE 1: S3 bucket with public ACL (CRITICAL)
resource "aws_s3_bucket" "public_bucket" {
  bucket = "test-public-bucket-${random_id.suffix.hex}"

  tags = {
    Name        = "Test Public Bucket"
    Environment = "Testing"
  }
}

resource "aws_s3_bucket_public_access_block" "public_bucket_block" {
  bucket = aws_s3_bucket.public_bucket.id

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

# ISSUE 2: S3 bucket without encryption (HIGH)
resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "test-unencrypted-bucket-${random_id.suffix.hex}"

  tags = {
    Name        = "Test Unencrypted Bucket"
    Environment = "Testing"
  }
}

# No encryption configuration = HIGH severity

# ISSUE 3: S3 bucket without versioning (MEDIUM)
resource "aws_s3_bucket" "no_versioning_bucket" {
  bucket = "test-no-versioning-bucket-${random_id.suffix.hex}"

  tags = {
    Name        = "Test No Versioning Bucket"
    Environment = "Testing"
  }
}

# ISSUE 4: Security group with SSH open to internet (HIGH)
resource "aws_security_group" "open_ssh" {
  name        = "test-open-ssh"
  description = "Security group with SSH open to internet"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # SECURITY ISSUE: SSH open to internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Test Open SSH"
  }
}

# ISSUE 5: Security group with RDP open to internet (HIGH)
resource "aws_security_group" "open_rdp" {
  name        = "test-open-rdp"
  description = "Security group with RDP open to internet"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # SECURITY ISSUE: RDP open to internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Test Open RDP"
  }
}

# ISSUE 6: IAM policy with admin access (HIGH)
resource "aws_iam_policy" "admin_policy" {
  name        = "test-admin-policy"
  description = "Test policy with admin access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"  # SECURITY ISSUE: All actions
        Resource = "*"  # SECURITY ISSUE: All resources
      }
    ]
  })
}

# Random ID for unique bucket names
resource "random_id" "suffix" {
  byte_length = 4
}
