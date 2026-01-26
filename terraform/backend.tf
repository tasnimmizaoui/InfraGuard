terraform {
  backend "s3" {
    bucket         = "infraguard-terraform-state"  # From bootstrap output 
    key            = "infraguard/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "infraguard-terraform-locks"  # From bootstrap output 
  }
}