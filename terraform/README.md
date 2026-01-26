# InfraGuard Terraform Infrastructure

Complete Terraform infrastructure-as-code for deploying InfraGuard AWS security monitoring.

## 🏗️ Architecture

This Terraform configuration deploys:

- **IAM Resources**: Scanner user with SecurityAudit policy + Lambda execution role
- **S3 Storage**: Encrypted bucket for CloudTrail and VPC Flow Logs (90-day lifecycle)
- **CloudTrail**: Multi-region trail with log file validation
- **VPC Flow Logs**: Network traffic monitoring with 10-minute aggregation
- **SNS Alerting**: Email/SMS notifications for security findings
- **Lambda Function** (optional): Automated daily scans at 9 AM UTC
- **EventBridge**: Scheduled Lambda triggers
- **Secrets Manager**: Secure IAM credential storage

## 📋 Prerequisites

1. **AWS Account** with administrator access
2. **AWS CLI** configured with credentials:
   ```bash
   aws configure
   ```
3. **Terraform** >= 1.0 installed:
   ```bash
   # Windows (using Chocolatey)
   choco install terraform
   
   # macOS (using Homebrew)
   brew install terraform
   
   # Linux
   wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
   unzip terraform_1.6.0_linux_amd64.zip
   sudo mv terraform /usr/local/bin/
   ```

## 🚀 Deployment Guide

### Step 1: Bootstrap Terraform State Backend

The Terraform state backend (S3 + DynamoDB) must be created first:

```bash
cd bootstrap
terraform init
terraform plan
terraform apply

# Note the outputs - you'll need these values
cd ..
```

### Step 2: Configure Backend

Update [backend.tf](backend.tf) with the bucket and table names from Step 1:

```hcl
terraform {
  backend "s3" {
    bucket         = "infraguard-terraform-state"  # From bootstrap output
    key            = "infraguard/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "infraguard-terraform-locks"  # From bootstrap output
    encrypt        = true
  }
}
```

### Step 3: Configure Variables

Copy the example variables file and customize:

```bash
cp terraform.tfvars.example terraform.tfvars
```

**Required Configuration** in `terraform.tfvars`:

```hcl
# Your AWS region
aws_region = "us-east-1"

# Email addresses for security alerts (REQUIRED)
alert_email_addresses = [
  "security@example.com",
  "admin@example.com"
]
```

**Optional Configurations**:
- `alert_sms_numbers`: SMS alerts (E.164 format)
- `s3_bucket_name`: Custom bucket name (auto-generated if empty)
- `log_retention_days`: Log retention period (default: 90 days)
- `lambda_schedule`: Scan frequency (default: daily at 9 AM UTC)
- `additional_vpc_ids`: Monitor additional VPCs
- `enable_lambda_deployment`: Disable automated scans (default: true)

### Step 4: Deploy Infrastructure

```bash
# Initialize Terraform with backend configuration
terraform init

# Review planned changes
terraform plan

# Deploy infrastructure
terraform apply
```

Terraform will show you all resources to be created. Type `yes` to proceed.

### Step 5: Confirm SNS Subscriptions

Check your email inbox for SNS subscription confirmation emails and click the confirmation links.

### Step 6: Retrieve Scanner Credentials

Credentials are stored securely in AWS Secrets Manager:

```bash
# Get the secret ARN from Terraform outputs
aws secretsmanager get-secret-value \
  --secret-id $(terraform output -raw credentials_secret_arn) \
  --query SecretString \
  --output text | jq .
```

Or view sensitive outputs directly:

```bash
terraform output -json | jq .
terraform output scanner_access_key_id
terraform output scanner_secret_access_key  # Requires -json flag
```

### Step 7: Configure Local Environment (Optional)

To run InfraGuard scans locally:

```bash
export AWS_ACCESS_KEY_ID="<from step 6>"
export AWS_SECRET_ACCESS_KEY="<from step 6>"
export AWS_REGION="us-east-1"
export INFRAGUARD_S3_BUCKET="$(terraform output -raw logs_bucket_name)"
export INFRAGUARD_SNS_TOPIC_ARN="$(terraform output -raw sns_topic_arn)"

# Run a scan
cd ..
python main.py check-all
```

## 📂 Module Structure

```
terraform/
├── main.tf                    # Root module orchestration
├── variables.tf               # Input variables
├── outputs.tf                 # Output values
├── backend.tf                 # S3 backend configuration
├── terraform.tfvars.example   # Example configuration
├── bootstrap/                 # State backend creation
│   ├── main.tf
│   └── variables.tf
└── modules/
    ├── iam/                   # IAM users, roles, policies
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── storage/               # S3 buckets for logs
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── logging/               # CloudTrail, VPC Flow Logs
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── alerting/              # SNS topics, subscriptions
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    └── lambda/                # Lambda function, EventBridge
        ├── main.tf
        ├── variables.tf
        └── outputs.tf
```

## 🔍 Verifying Deployment

### Check CloudTrail

```bash
aws cloudtrail describe-trails --trail-name-list $(terraform output -raw cloudtrail_id)
```

### Check VPC Flow Logs

```bash
aws ec2 describe-flow-logs
```

### Check Lambda Function

```bash
# View function details
aws lambda get-function --function-name $(terraform output -raw lambda_function_name)

# Invoke manually
aws lambda invoke \
  --function-name $(terraform output -raw lambda_function_name) \
  --payload '{}' \
  response.json

# View recent logs
aws logs tail /aws/lambda/$(terraform output -raw lambda_function_name) --follow
```

### Check EventBridge Schedule

```bash
aws events list-rules --name-prefix infraguard
aws events list-targets-by-rule --rule infraguard-scanner-schedule
```

## 💰 Cost Estimate

**Free Tier Eligible** (first 12 months):
- CloudTrail: First trail free
- S3: 5 GB storage, 20,000 GET requests, 2,000 PUT requests
- Lambda: 1M requests/month, 400,000 GB-seconds compute
- SNS: 1,000 emails/month

**Estimated Monthly Cost** (after free tier):
- VPC Flow Logs: $1-2 (10-minute aggregation reduces costs by 90%)
- S3 Storage: $0.10-0.50 (with 90-day lifecycle policy)
- CloudTrail: Free (first trail)
- Lambda: $0 (daily scans well within free tier)
- **Total: $1-3/month**

## 🔧 Customization

### Change Scan Schedule

Edit `terraform.tfvars`:

```hcl
# Run every 6 hours
lambda_schedule = "rate(6 hours)"

# Run at 2 AM daily
lambda_schedule = "cron(0 2 * * ? *)"

# Run twice daily (9 AM and 9 PM)
lambda_schedule = "cron(0 9,21 * * ? *)"
```

### Monitor Additional VPCs

```hcl
additional_vpc_ids = [
  "vpc-0123456789abcdef0",
  "vpc-0fedcba9876543210"
]
```

### Add Slack Alerts

```hcl
lambda_environment_variables = {
  SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
}
```

### Extend Log Retention

```hcl
log_retention_days = 180  # 6 months
lambda_log_retention_days = 90
```

## 🧹 Cleanup

To destroy all resources:

```bash
# Destroy main infrastructure
terraform destroy

# Destroy state backend (optional)
cd bootstrap
terraform destroy
```

**Note**: S3 buckets with versioning may require manual deletion of all object versions before Terraform can delete them.

## 🔒 Security Best Practices

1. **Least Privilege**: IAM scanner user has read-only SecurityAudit policy
2. **Credential Rotation**: Rotate IAM access keys every 90 days
3. **State Security**: Terraform state is encrypted at rest in S3
4. **Secret Management**: Credentials stored in AWS Secrets Manager, not in code
5. **Multi-Region**: CloudTrail covers all regions by default
6. **Encryption**: All S3 buckets use AES256 encryption
7. **Public Access**: All S3 buckets block public access
8. **Log Validation**: CloudTrail log file integrity validation enabled

## 📊 Monitoring

### Lambda Execution Metrics

```bash
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=$(terraform output -raw lambda_function_name) \
  --start-time $(date -u -d '1 week ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 3600 \
  --statistics Sum
```

### Recent Security Findings

Check SNS topic for recent alerts:

```bash
aws sns list-subscriptions-by-topic --topic-arn $(terraform output -raw sns_topic_arn)
```

## 🐛 Troubleshooting

### Backend Already Exists

If you see "Backend already exists", the state backend was already created. Update [backend.tf](backend.tf) with existing values.

### Lambda Packaging Errors

Ensure `infra_guard/` directory exists at the same level as `terraform/`:

```
InfraGuard/
├── infra_guard/         # Python source code
│   ├── __init__.py
│   ├── config.py
│   ├── utils.py
│   └── ...
└── terraform/           # Terraform configuration
    ├── main.tf
    └── ...
```

### SNS Subscription Not Confirmed

Check spam folder for confirmation emails. Resend confirmation:

```bash
aws sns subscribe \
  --topic-arn $(terraform output -raw sns_topic_arn) \
  --protocol email \
  --notification-endpoint your-email@example.com
```

### No Findings in Logs

Verify Lambda is executing:

```bash
aws lambda invoke \
  --function-name $(terraform output -raw lambda_function_name) \
  --log-type Tail \
  --query 'LogResult' \
  --output text \
  response.json | base64 -d
```

## 📚 Additional Resources

- [AWS Free Tier Details](https://aws.amazon.com/free/)
- [Terraform AWS Provider Docs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [InfraGuard README](../README.md)
- [AWS Security Best Practices](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html)

## 🤝 Contributing

Found an issue or want to improve the Terraform configuration? Please submit an issue or pull request!

## 📄 License

MIT License - see LICENSE file for details
