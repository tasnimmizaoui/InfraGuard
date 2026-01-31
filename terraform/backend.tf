terraform {
  backend "s3" {
    bucket         = "infraguard-terraform-state"  # From bootstrap output 
    key            = "infraguard/terraform.tfstate"
    region         = "eu-north-1"
    encrypt        = true
    #dynamodb_table = "infraguard-terraform-locks"  # From bootstrap output 
  }
}