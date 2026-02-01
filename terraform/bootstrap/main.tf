# ============================================
# Terraform State Backend Bootstrap
# ============================================
# This module creates the S3 bucket and DynamoDB table
# required for Terraform state management.
#
# ⚠️  This is setup to Run ONCE before deploying main infrastructure:
#     cd bootstrap
#     terraform init
#     terraform apply
#
# Then configure backend in ../backend.tf and run:
#     cd ..
#     terraform init

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ============================================
# S3 Bucket for Terraform State
# ============================================

resource "aws_s3_bucket" "terraform_state" {
  bucket = var.state_bucket_name

  tags = {
    Name      = "Terraform State Bucket"
    Purpose   = "InfraGuard Terraform State"
    ManagedBy = "Terraform Bootstrap"
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ============================================
# DynamoDB Table for State Locking
# ============================================

resource "aws_dynamodb_table" "terraform_locks" {
  name         = var.lock_table_name
  billing_mode = "PAY_PER_REQUEST" # Free tier: 25 WCU, 25 RCU
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name      = "Terraform State Lock Table"
    Purpose   = "InfraGuard Terraform State Locking"
    ManagedBy = "Terraform Bootstrap"
  }
}

# ============================================
# Outputs
# ============================================

output "state_bucket_name" {
  description = "Name of the S3 bucket for Terraform state"
  value       = aws_s3_bucket.terraform_state.id
}

output "state_bucket_arn" {
  description = "ARN of the S3 bucket for Terraform state"
  value       = aws_s3_bucket.terraform_state.arn
}

output "lock_table_name" {
  description = "Name of the DynamoDB table for state locking"
  value       = aws_dynamodb_table.terraform_locks.id
}

output "lock_table_arn" {
  description = "ARN of the DynamoDB table for state locking"
  value       = aws_dynamodb_table.terraform_locks.arn
}

output "next_steps" {
  description = "Instructions for configuring backend in main Terraform"
  value       = <<-EOT
    
    ✅ Terraform State Backend Created Successfully!
    
    📋 Next Steps:
    
    1. Update ../backend.tf with these values:
       
       terraform {
         backend "s3" {
           bucket         = "${aws_s3_bucket.terraform_state.id}"
           key            = "infraguard/terraform.tfstate"
           region         = "${var.aws_region}"
           dynamodb_table = "${aws_dynamodb_table.terraform_locks.id}"
           encrypt        = true
         }
       }
    
    2. Navigate to parent directory:
       cd ..
    
    3. Initialize Terraform with backend:
       terraform init
    
    4. Deploy InfraGuard infrastructure:
       terraform plan
       terraform apply
    
     The Terraform state will now be:
       - Stored in S3: ${aws_s3_bucket.terraform_state.id}
       - Locked via DynamoDB: ${aws_dynamodb_table.terraform_locks.id}
       - Encrypted at rest (AES256)
       - Versioned for rollback capability
    
  EOT
}
