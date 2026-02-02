# AWS Setup Guide for InfraGuard

This guide walks you through setting up AWS services for InfraGuard monitoring.

## Prerequisites

- AWS Account
- AWS CLI installed and configured
- Appropriate IAM permissions

## Step 1: Create IAM User for InfraGuard

Create a dedicated IAM user with read-only security permissions:

```bash
# Create user
aws iam create-user --user-name infraguard-scanner

# Attach SecurityAudit managed policy (read-only access to security configs)
aws iam attach-user-policy \
  --user-name infraguard-scanner \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit

# Create access keys
aws iam create-access-key --user-name infraguard-scanner
```

Save the Access Key ID and Secret Access Key for later use.

### Additional S3 Permissions (for log analysis)

If you want to analyze CloudTrail/VPC Flow Logs from S3:

```bash
# Create custom policy for S3 log access
cat > infraguard-s3-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::your-logs-bucket",
        "arn:aws:s3:::your-logs-bucket/*"
      ]
    }
  ]
}
EOF

# Create and attach the policy
aws iam create-policy \
  --policy-name InfraGuardS3Access \
  --policy-document file://infraguard-s3-policy.json

aws iam attach-user-policy \
  --user-name infraguard-scanner \
  --policy-arn arn:aws:iam::YOUR-ACCOUNT-ID:policy/InfraGuardS3Access
```

## Step 2: Enable CloudTrail (Free Tier)

CloudTrail provides audit logs of all API calls in your AWS account.

```bash
# Create S3 bucket for logs
aws s3 mb s3://infraguard-logs-YOUR-ACCOUNT-ID --region us-east-1

# Create bucket policy to allow CloudTrail to write
cat > cloudtrail-bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::infraguard-logs-YOUR-ACCOUNT-ID"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::infraguard-logs-YOUR-ACCOUNT-ID/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
EOF

# Apply bucket policy
aws s3api put-bucket-policy \
  --bucket infraguard-logs-YOUR-ACCOUNT-ID \
  --policy file://cloudtrail-bucket-policy.json

# Create CloudTrail trail
aws cloudtrail create-trail \
  --name infraguard-trail \
  --s3-bucket-name infraguard-logs-YOUR-ACCOUNT-ID \
  --is-multi-region-trail \
  --enable-log-file-validation

# Start logging
aws cloudtrail start-logging --name infraguard-trail

# Verify it's working
aws cloudtrail get-trail-status --name infraguard-trail
```

**Cost:** One CloudTrail trail is FREE. Additional trails cost $2/month per region.

## Step 3: Enable VPC Flow Logs (Low Cost)

VPC Flow Logs capture network traffic metadata for security analysis.

```bash
# Get your VPC ID
aws ec2 describe-vpcs --query 'Vpcs[0].VpcId' --output text

# Create flow logs to S3
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-YOUR-VPC-ID \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::infraguard-logs-YOUR-ACCOUNT-ID/vpc-flow-logs/ \
  --max-aggregation-interval 600

# Verify flow logs are active
aws ec2 describe-flow-logs
```

**Cost:** ~$0.50 per million log records. Typically $1-3/month for small environments.

## Step 4: Create SNS Topic for Alerts (Free Tier)

```bash
# Create SNS topic
aws sns create-topic --name infraguard-alerts

# Subscribe your email
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:YOUR-ACCOUNT-ID:infraguard-alerts \
  --protocol email \
  --notification-endpoint your-email@example.com

# Confirm subscription (check your email and click the confirmation link)

# Grant InfraGuard permission to publish
cat > sns-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR-ACCOUNT-ID:user/infraguard-scanner"
      },
      "Action": "SNS:Publish",
      "Resource": "arn:aws:sns:us-east-1:YOUR-ACCOUNT-ID:infraguard-alerts"
    }
  ]
}
EOF

aws sns set-topic-attributes \
  --topic-arn arn:aws:sns:us-east-1:YOUR-ACCOUNT-ID:infraguard-alerts \
  --attribute-name Policy \
  --attribute-value file://sns-policy.json
```

**Cost:** First 1,000 SNS notifications/month are FREE.

## Step 5: Configure InfraGuard

Create a `.env` file or set environment variables:

```bash
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=AKIA... # From Step 1
export AWS_SECRET_ACCESS_KEY=... # From Step 1
export INFRAGUARD_S3_BUCKET=infraguard-logs-YOUR-ACCOUNT-ID
export INFRAGUARD_SNS_TOPIC_ARN=arn:aws:sns:us-east-1:YOUR-ACCOUNT-ID:infraguard-alerts
```

## Step 6: Test InfraGuard

```bash
# Run a quick IAM check
python main.py check-iam

# Run all checks
python main.py check-all

# Analyze CloudTrail (wait a few hours after enabling for logs to accumulate)
python main.py analyze-cloudtrail
```

## Optional: Schedule Automated Scans

### Option A: AWS Lambda (Recommended for Free Tier)

```bash
# Package InfraGuard
cd InfraGuard
zip -r infraguard-lambda.zip infra_guard/ main.py

# Create Lambda execution role
aws iam create-role \
  --role-name InfraGuardLambdaRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach policies
aws iam attach-role-policy \
  --role-name InfraGuardLambdaRole \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit

aws iam attach-role-policy \
  --role-name InfraGuardLambdaRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# Create Lambda function
aws lambda create-function \
  --function-name InfraGuardScanner \
  --runtime python3.11 \
  --role arn:aws:iam::YOUR-ACCOUNT-ID:role/InfraGuardLambdaRole \
  --handler lambda_handler.handler \
  --zip-file fileb://infraguard-lambda.zip \
  --timeout 300 \
  --memory-size 512

# Schedule daily execution (using EventBridge)
aws events put-rule \
  --name InfraGuardDaily \
  --schedule-expression "cron(0 9 * * ? *)"

aws events put-targets \
  --rule InfraGuardDaily \
  --targets "Id"="1","Arn"="arn:aws:lambda:us-east-1:YOUR-ACCOUNT-ID:function:InfraGuardScanner"

# Grant EventBridge permission to invoke Lambda
aws lambda add-permission \
  --function-name InfraGuardScanner \
  --statement-id InfraGuardDailyExecution \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:us-east-1:YOUR-ACCOUNT-ID:rule/InfraGuardDaily
```

**Cost:** Lambda free tier includes 1M requests and 400,000 GB-seconds/month. Daily scans are FREE.

### Option B: GitHub Actions (Free)

See the GitHub Actions example in the README.md.

## Cost Summary

| Service | Free Tier | Expected Monthly Cost |
|---------|-----------|----------------------|
| CloudTrail (1 trail) | FREE | $0 |
| VPC Flow Logs | No free tier | $1-3 |
| S3 Storage (logs) | 5GB free | $0-1 |
| SNS | 1,000 notifications free | $0 |
| Lambda (optional) | 1M requests free | $0 |
| **Total** | | **$1-4/month** |

## Cleanup (if needed)

```bash
# Delete CloudTrail
aws cloudtrail delete-trail --name infraguard-trail

# Delete VPC Flow Logs
aws ec2 delete-flow-logs --flow-log-ids fl-xxxxx

# Delete S3 bucket
aws s3 rb s3://infraguard-logs-YOUR-ACCOUNT-ID --force

# Delete SNS topic
aws sns delete-topic --topic-arn arn:aws:sns:us-east-1:YOUR-ACCOUNT-ID:infraguard-alerts

# Delete IAM user
aws iam delete-access-key --user-name infraguard-scanner --access-key-id AKIA...
aws iam detach-user-policy --user-name infraguard-scanner --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam delete-user --user-name infraguard-scanner
```

---

**You're all set! Run `python main.py check-all` to start monitoring your AWS security.**
