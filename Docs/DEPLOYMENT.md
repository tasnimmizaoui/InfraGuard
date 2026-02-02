# Deployment Guide

Complete guide for deploying InfraGuard with GitHub Actions CI/CD pipeline.

## Prerequisites

-  AWS Account with admin access
-  GitHub Account
-  Python 3.11+
-  Terraform 1.6+
-  AWS CLI configured locally
-  Git installed

## Deployment Steps

### 1. Fork/Clone Repository

```bash
# Clone the repository
git clone https://github.com/tasnimmizaoui/InfraGuard.git
cd InfraGuard

# Or fork on GitHub and clone your fork
```

### 2. AWS Setup

#### Create OIDC Provider (Recommended - Free)

This allows GitHub Actions to assume an AWS IAM role without storing long-lived credentials.

```bash
# Create OIDC provider
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

#### Create IAM Role for GitHub Actions

Create `github-actions-trust-policy.json`:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:YOUR_GITHUB_USERNAME/InfraGuard:*"
        }
      }
    }
  ]
}
```

Create the role:
```bash
# Create IAM role
aws iam create-role \
  --role-name GitHubActions-InfraGuard \
  --assume-role-policy-document file://github-actions-trust-policy.json

# Attach permissions for security scanning
aws iam attach-role-policy \
  --role-name GitHubActions-InfraGuard \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit

# Attach permissions for Terraform
aws iam attach-role-policy \
  --role-name GitHubActions-InfraGuard \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
```

#### Alternative: Use IAM User with Access Keys

If you prefer access keys instead of OIDC:

```bash
# Create IAM user
aws iam create-user --user-name github-actions-infraguard

# Attach policies
aws iam attach-user-policy \
  --user-name github-actions-infraguard \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit

aws iam attach-user-policy \
  --user-name github-actions-infraguard \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess

# Create access key
aws iam create-access-key --user-name github-actions-infraguard
```

### 3. Bootstrap Terraform Backend

Create S3 bucket and DynamoDB table for Terraform state:

```bash
cd terraform/bootstrap

# Initialize Terraform
terraform init

# Review the plan
terraform plan

# Apply (creates S3 bucket + DynamoDB table)
terraform apply

# Note the bucket name from output
# Example: infraguard-tfstate-1234567891
```

### 4. Configure Terraform Backend

Update `terraform/backend.tf` with your bucket name:

```hcl
terraform {
  backend "s3" {
    bucket         = "infraguard-tfstate-YOUR_ACCOUNT_ID"
    key            = "infraguard/terraform.tfstate"
    region         = "eu-north-1"  # or your preferred region
    encrypt        = true
    dynamodb_table = "infraguard-terraform-locks"
  }
}
```

Update `terraform/terraform.tfvars`:

```hcl
aws_region     = "eu-north-1"  # your region
environment    = "production"
project_name   = "infraguard"
```

### 5. Initialize Terraform with Backend

```bash
cd ../  # Back to terraform/ directory

# Initialize with the S3 backend
terraform init

# Format check
terraform fmt -recursive

# Validate
terraform validate
```

### 6. Configure GitHub Secrets

Go to your GitHub repository → Settings → Secrets and variables → Actions

#### Required Secrets:

**For OIDC (Recommended):**
- `AWS_ROLE_ARN`: `arn:aws:iam::YOUR_ACCOUNT_ID:role/GitHubActions-InfraGuard`

**For Access Keys (Alternative):**
- `AWS_ACCESS_KEY_ID`: Your access key ID
- `AWS_SECRET_ACCESS_KEY`: Your secret access key

**For Terraform:**
- `TF_STATE_BUCKET`: `infraguard-tfstate-YOUR_ACCOUNT_ID`

#### Optional Secrets:

- `INFRAGUARD_SLACK_WEBHOOK`: Your Slack webhook URL for alerts
- `INFRAGUARD_SNS_TOPIC_ARN`: SNS topic ARN for email alerts

#### Variables:

- `AWS_REGION`: `eu-north-1` (or your region)

### 7. Update Workflow Configuration

Review `.github/workflows/security-scan.yml` and ensure:

1. Region matches your setup:
   ```yaml
   aws-region: eu-north-1  # Update if different
   ```

2. Role ARN is correct (for OIDC):
   ```yaml
   role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
   ```

3. Triggers are configured:
   ```yaml
   on:
     push:
       branches:
         - main
         - 'feature/**'
   ```

### 8. Test Locally (Optional but Recommended)

Before pushing to GitHub, test the infrastructure locally:

```bash
# Create a plan
terraform plan -out=tfplan

# Convert to JSON and scan
terraform show -json tfplan > tfplan.json
cd ..
python main.py scan-plan --plan-file terraform/tfplan.json

# If no critical issues, apply locally
cd terraform
terraform apply tfplan
```

### 9. Deploy via GitHub Actions

```bash
# Commit all changes
git add .
git commit -m "Initial InfraGuard deployment setup"

# Push to main branch (triggers pipeline)
git push origin main
```

### 10. Monitor Deployment

1. Go to GitHub repository → Actions tab
2. Watch the workflow run:
   - **security-scan** job: Scans existing AWS infrastructure
   - **deploy-terraform** job: Deploys InfraGuard infrastructure
3. Check for any errors
4. Review security findings in job summary

## Post-Deployment Verification

### 1. Verify Infrastructure

```bash
# List created resources
terraform state list

# Check S3 buckets
aws s3 ls | grep infraguard

# Check Lambda function
aws lambda list-functions | grep infraguard

# Check CloudTrail
aws cloudtrail describe-trails
```

### 2. Test Security Scanner

```bash
# Run manual scan
python main.py check-all --output-file findings.json

# View findings
cat findings.json
```

### 3. Test Lambda Function

```bash
# Get function name
FUNCTION_NAME=$(aws lambda list-functions --query 'Functions[?contains(FunctionName, `infraguard`)].FunctionName' --output text)

# Invoke manually
aws lambda invoke \
  --function-name $FUNCTION_NAME \
  --payload '{}' \
  response.json

# Check output
cat response.json
```

### 4. Verify CloudTrail

```bash
# Check trail status
aws cloudtrail get-trail-status --name infraguard-trail

# List recent events
aws cloudtrail lookup-events --max-results 10
```

### 5. Test Alerting (if configured)

```bash
# Send test notification
aws sns publish \
  --topic-arn YOUR_SNS_TOPIC_ARN \
  --message "InfraGuard deployment successful!" \
  --subject "InfraGuard Test Alert"
```

## Troubleshooting

### Pipeline Fails on Security Scan

**Problem:** Critical security findings block deployment

**Solution:**
1. Review findings in GitHub Actions job summary
2. Fix critical issues in your AWS account:
   - Remove overly permissive security groups
   - Enable CloudTrail
   - Fix public S3 buckets
3. Re-run pipeline

### Terraform Init Fails

**Problem:** Backend configuration issues

**Solution:**
1. Verify S3 bucket exists: `aws s3 ls s3://YOUR_BUCKET_NAME`
2. Check bucket region matches configuration
3. Verify IAM permissions for S3 and DynamoDB
4. Check `backend.tf` configuration

### Secret Already Exists Error

**Problem:** Secrets Manager secret from previous deployment

**Solution:**
```bash
# Force delete existing secret
aws secretsmanager delete-secret \
  --secret-id infraguard/scanner-credentials-v2 \
  --force-delete-without-recovery \
  --region YOUR_REGION
```

### Access Denied Errors

**Problem:** Insufficient IAM permissions

**Solution:**
1. Verify IAM role/user has required policies attached
2. Check OIDC provider trust relationship
3. Verify repository name in trust policy matches exactly

### Region Mismatch

**Problem:** Resources in wrong region

**Solution:**
1. Update `terraform/terraform.tfvars`: `aws_region = "your-region"`
2. Update `terraform/backend.tf`: `region = "your-region"`
3. Update `.github/workflows/security-scan.yml`: `aws-region: your-region`

## Updating Infrastructure

### Making Changes

```bash
# Make changes to Terraform files
# Commit and push
git add terraform/
git commit -m "Update infrastructure configuration"
git push origin main

# Pipeline automatically:
# 1. Scans existing infrastructure
# 2. Creates Terraform plan
# 3. Scans planned changes
# 4. Applies if all checks pass
```

### Manual Updates

```bash
cd terraform

# Pull latest changes
git pull

# Plan changes
terraform plan -out=tfplan

# Scan plan
terraform show -json tfplan > tfplan.json
cd ..
python main.py scan-plan --plan-file terraform/tfplan.json

# Apply if safe
cd terraform
terraform apply tfplan
```

## Destroying Infrastructure

### Complete Teardown

```bash
cd terraform

# Destroy main infrastructure
terraform destroy

# Destroy bootstrap (if needed)
cd bootstrap
terraform destroy
```

⚠️ **Warning:** This deletes all InfraGuard resources including logs and findings!

### Selective Destruction

```bash
# Destroy specific resource
terraform destroy -target=module.lambda.aws_lambda_function.scanner

# Or remove from Terraform and apply
terraform apply
```

## Cost Management

### Current Costs

With default configuration:
- **CloudTrail**: Free (1 trail)
- **S3 Storage**: ~$0.50/month
- **Lambda**: ~$0.20/month
- **CloudWatch Logs**: ~$1/month
- **DynamoDB**: Free (minimal usage)
- **Total**: ~$2/month

### Cost Optimization

1. **Adjust log retention:**
   ```hcl
   # In terraform/modules/storage/main.tf
   lifecycle_rule {
     expiration {
       days = 30  # Reduce from 90
     }
   }
   ```

2. **Reduce Lambda frequency:**
   ```hcl
   # In terraform/modules/lambda/main.tf
   schedule_expression = "rate(7 days)"  # Instead of daily
   ```

3. **Use S3 Intelligent-Tiering:**
   ```hcl
   resource "aws_s3_bucket_intelligent_tiering_configuration" "logs" {
     bucket = aws_s3_bucket.logs.id
     name   = "EntireBucket"
     
     tiering {
       access_tier = "ARCHIVE_ACCESS"
       days = 90
     }
   }
   ```

## Security Best Practices

1. Use OIDC instead of long-lived access keys
2.  Enable MFA for AWS console access
3.  Rotate IAM credentials regularly
4.  Review security findings weekly
5.  Keep Terraform state encrypted
6.  Use branch protection on main
7.  Require pull request reviews
8.  Enable GitHub secret scanning

## Next Steps

1. **Set up Slack notifications** - See [Alerting Guide](ALERTING.md)
2. **Customize security policies** - See [API Reference](API.md)
3. **Add custom checks** - See [Development Guide](DEVELOPMENT.md)
4. **Schedule regular reviews** - Review findings weekly
5. **Document runbooks** - Create incident response procedures

## Support

- **Issues:** Open a GitHub issue
- **Documentation:** See [docs/](.)
- **Examples:** See [test_plan/](../test_plan/)

---

**Deployment complete! 🎉 Your shift-left security pipeline is ready.**
