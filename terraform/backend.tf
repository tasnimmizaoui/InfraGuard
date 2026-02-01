terraform {
  backend "s3" {
    bucket  = "infraguard-tfstate-045378075905" # Unique with account ID
    key     = "infraguard/terraform.tfstate"
    region  = "eu-north-1"
    encrypt = true
    #dynamodb_table = "infraguard-terraform-locks"  # From bootstrap output 
  }
}