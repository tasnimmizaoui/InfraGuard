# InfraGuard - AWS Cloud Security Monitoring (Free Tier Friendly)

A lightweight Python-based security monitoring tool for AWS infrastructure that detects common security misconfigurations while staying within AWS free tier limits.

## Features

- ✅ **IAM Security Monitoring**
  - Detect unused IAM users
  - Root account access key detection
  - Overpermissive IAM policies
  - Weak password policies

- ✅ **Network Security Monitoring**
  - Security groups open to 0.0.0.0/0
  - Public EC2 instances
  - VPC Flow Logs configuration checks
  - Risky port exposure (SSH, RDP, databases)

- ✅ **S3 Security**
  - Public bucket detection
  - Encryption configuration checks
  - ACL and policy analysis

- ✅ **Audit Log Analysis**
  - CloudTrail log ingestion and analysis
  - VPC Flow Log analysis
  - Root account usage detection
  - Failed authentication attempts
  - Privilege escalation detection

- ✅ **Alerting**
  - AWS SNS integration
  - Slack webhook support
  - Multiple output formats (JSON, CSV, log)

- ✅ **Container Security (Optional)**
  - ECS task definition checks
  - Privileged container detection

## Installation

### Prerequisites

- Python 3.8+
- AWS CLI configured with credentials
- AWS account with appropriate IAM permissions

### Setup

1. **Clone or create the project:**
   ```bash
   cd InfraGuard
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure AWS credentials:**
   ```bash
   aws configure
   ```
   Or set environment variables:
   ```bash
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_REGION=us-east-1
   ```

## Configuration

InfraGuard uses environment variables for configuration:

```bash
# Required
export AWS_REGION=us-east-1

# Optional - for log analysis
export INFRAGUARD_S3_BUCKET=your-logs-bucket

# Optional - for alerts
export INFRAGUARD_SNS_TOPIC_ARN=arn:aws:sns:us-east-1:123456789:infraguard-alerts
export INFRAGUARD_SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Optional - logging
export INFRAGUARD_LOG_LEVEL=INFO
```

## Usage

### Run All Security Checks

```bash
python main.py check-all
```

This runs all enabled security checks and outputs findings in JSON format.

### Check Only IAM

```bash
python main.py check-iam
```

### Check Network Security

```bash
python main.py check-network
```

### Analyze CloudTrail Logs

```bash
# Analyze last 24 hours
python main.py analyze-cloudtrail

# Analyze last 48 hours
python main.py analyze-cloudtrail --hours 48
```

### Analyze VPC Flow Logs

```bash
# Analyze last 24 hours
python main.py analyze-vpc-logs

# Analyze last 12 hours
python main.py analyze-vpc-logs --hours 12
```

### Output Options

```bash
# Save to JSON file
python main.py check-all --output-format json --output-file findings.json

# Save to CSV
python main.py check-all --output-format csv --output-file findings.csv

# Output as logs
python main.py check-all --output-format log --output-file findings.log
```

## AWS Free Tier Considerations

InfraGuard is designed to minimize AWS costs:

### Free Services Used:
- **IAM**: Completely free
- **CloudTrail**: One trail is free
- **VPC Flow Logs**: Logs to S3 are cheap (minimal storage costs)
- **SNS**: First 1,000 notifications/month free
- **S3**: 5GB storage, 20,000 GET requests, 2,000 PUT requests free/month

### Services to Be Careful With:
- **EC2 instances**: Limited to 750 hours/month on t2.micro or t3.micro
- **Lambda**: 1M free requests/month, 400,000 GB-seconds compute
- **CloudWatch Logs**: 5GB ingestion, storage costs apply
- **ECS/EKS**: EKS has hourly cluster costs (~$72/month)

### Cost Optimization Tips:
1. Run InfraGuard checks manually or schedule infrequently (e.g., daily)
2. Avoid enabling ECS/EKS checks unless needed
3. Use S3 for logs instead of CloudWatch Logs
4. Limit CloudTrail to one trail
5. Set max_files and max_events limits in code to control data processing

## IAM Permissions Required

InfraGuard needs the following IAM permissions (minimum):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:GetUser",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:GetAccountSummary",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetAccountPasswordPolicy",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeInstances",
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetObject",
        "s3:ListBucket",
        "cloudtrail:ListTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetTrail",
        "ecs:ListClusters",
        "ecs:ListTaskDefinitions",
        "ecs:DescribeTaskDefinition",
        "sns:Publish"
      ],
      "Resource": "*"
    }
  ]
}
```

For read-only security scanning, you can use the AWS managed policy: `SecurityAudit`

## Setting Up Alerts

### SNS Alerts

1. Create an SNS topic:
   ```bash
   aws sns create-topic --name infraguard-alerts
   ```

2. Subscribe your email:
   ```bash
   aws sns subscribe \
     --topic-arn arn:aws:sns:us-east-1:123456789:infraguard-alerts \
     --protocol email \
     --notification-endpoint your-email@example.com
   ```

3. Set environment variable:
   ```bash
   export INFRAGUARD_SNS_TOPIC_ARN=arn:aws:sns:us-east-1:123456789:infraguard-alerts
   ```

### Slack Alerts

1. Create a Slack Incoming Webhook:
   - Go to https://api.slack.com/messaging/webhooks
   - Create a new app and enable Incoming Webhooks
   - Copy the webhook URL

2. Set environment variable:
   ```bash
   export INFRAGUARD_SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
   ```

## Setting Up CloudTrail and VPC Flow Logs

### Enable CloudTrail (if not already enabled):

```bash
# Create S3 bucket for logs
aws s3 mb s3://your-infraguard-logs --region us-east-1

# Create CloudTrail
aws cloudtrail create-trail \
  --name infraguard-trail \
  --s3-bucket-name your-infraguard-logs

# Start logging
aws cloudtrail start-logging --name infraguard-trail
```

### Enable VPC Flow Logs:

```bash
# Get your VPC ID
aws ec2 describe-vpcs

# Create flow logs to S3
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-xxxxxxxx \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::your-infraguard-logs/vpc-flow-logs/
```

## Example Output

```json
{
  "timestamp": "2026-01-26T10:30:00.000000",
  "total_findings": 3,
  "findings": [
    {
      "timestamp": "2026-01-26T10:30:00.000000",
      "category": "SecurityGroup",
      "severity": "HIGH",
      "description": "Security group 'web-servers' has risky port 22 open to internet",
      "resource": "sg-0123456789abcdef",
      "details": {
        "group_name": "web-servers",
        "vpc_id": "vpc-12345678",
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22
      },
      "recommendation": "Restrict access to specific IP ranges"
    }
  ]
}
```

## Testing Locally

### 1. Test IAM Checks (requires AWS credentials):

```python
from infra_guard.config import Config
from infra_guard.detection_rules import SecurityChecker
from infra_guard.utils import setup_logging

# Setup
setup_logging('DEBUG')
config = Config()
config.aws_region = 'us-east-1'

# Run checks
checker = SecurityChecker(config)
findings = checker.check_iam_unused_users()

print(f"Found {len(findings)} issues")
for finding in findings:
    print(f"  - {finding['description']}")
```

### 2. Test Security Group Checks:

```python
checker = SecurityChecker(config)
findings = checker.check_security_groups()

for finding in findings:
    print(f"[{finding['severity']}] {finding['description']}")
```

### 3. Test CloudTrail Analysis (requires S3 bucket with logs):

```python
from infra_guard.log_ingestion import CloudTrailIngestion, CloudTrailAnalyzer

config.s3_bucket = 'your-logs-bucket'
ingestion = CloudTrailIngestion(config)
analyzer = CloudTrailAnalyzer()

events = ingestion.get_recent_events(hours=24)
root_usage = analyzer.find_root_account_usage(events)

print(f"Root account used {len(root_usage)} times in last 24h")
```

## Scheduling (Optional)

### Run daily via cron (Linux/Mac):

```bash
# Add to crontab (crontab -e)
0 9 * * * cd /path/to/InfraGuard && python main.py check-all --output-file /var/log/infraguard/$(date +\%Y\%m\%d).json
```

### Run via AWS Lambda (advanced):

1. Package InfraGuard as a Lambda function
2. Set CloudWatch Events to trigger daily
3. Use Lambda's built-in AWS credentials
4. Stay within free tier: 1M invocations/month

### Run via GitHub Actions (free):

```yaml
name: InfraGuard Security Scan
on:
  schedule:
    - cron: '0 9 * * *'  # Daily at 9 AM UTC
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: python main.py check-all
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_REGION: us-east-1
          INFRAGUARD_SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
```

## Project Structure

```
InfraGuard/
├── infra_guard/
│   ├── __init__.py           # Package initialization
│   ├── config.py             # Configuration management
│   ├── utils.py              # Helper functions
│   ├── log_ingestion.py      # CloudTrail and VPC Flow Log parsing
│   ├── detection_rules.py    # Security check implementations
│   └── alerting.py           # SNS and Slack alerting
├── main.py                   # CLI entry point
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── .env.example             # Example environment variables
└── tests/                    # Unit tests (optional)
```

## Future Enhancements

1. **Additional AWS Service Checks:**
   - RDS database security (encryption, public access)
   - Lambda function permissions
   - API Gateway security
   - DynamoDB encryption
   - Elasticsearch/OpenSearch public access

2. **Advanced Detection Rules:**
   - Machine learning for anomaly detection
   - Baseline behavior tracking
   - Threat intelligence integration

3. **Compliance Frameworks:**
   - CIS AWS Foundations Benchmark
   - NIST Cybersecurity Framework
   - PCI DSS requirements

4. **Automation:**
   - Auto-remediation for common issues
   - AWS Config Rules integration
   - AWS Systems Manager automation

5. **Reporting:**
   - HTML dashboard generation
   - Trend analysis over time
   - Executive summary reports

## Troubleshooting

### "NoCredentialsError"
- Ensure AWS CLI is configured: `aws configure`
- Or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables

### "AccessDenied" errors
- Verify your IAM user/role has necessary permissions
- Consider using the AWS managed `SecurityAudit` policy

### "S3 bucket not configured"
- Set INFRAGUARD_S3_BUCKET environment variable
- Or skip log analysis commands (check-all still works)

### No findings detected
- This is good! Your AWS infrastructure is properly configured
- Try running with `--log-level DEBUG` to see more details

## Contributing

Contributions are welcome! Please focus on:
- Adding new free-tier-safe security checks
- Improving detection accuracy
- Better documentation
- Unit tests

## License

MIT License - feel free to use and modify for your needs.

## Security Notice

InfraGuard is a monitoring tool and does not make changes to your AWS infrastructure. However:
- Protect your AWS credentials
- Review findings before taking action
- Use read-only IAM policies when possible
- Keep your dependencies updated

## Disclaimer

This tool is provided as-is for security monitoring purposes. Always verify findings before taking remediation actions. The authors are not responsible for any changes made to your AWS infrastructure based on this tool's output.

---

**Built with ❤️ for AWS security best practices**
