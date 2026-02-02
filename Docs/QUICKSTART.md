# Quick Start Guide for InfraGuard

## 1. Install Dependencies

```bash
pip install -r requirements.txt
```

## 2. Configure AWS Credentials

```bash
aws configure
```

Enter your:
- AWS Access Key ID
- AWS Secret Access Key
- Default region (e.g., us-east-1)
- Default output format (json)

## 3. Run Your First Security Scan

```bash
# Check IAM security
python main.py check-iam

# Check network security (security groups, VPCs)
python main.py check-network

# Run all checks
python main.py check-all
```

## 4. (Optional) Setup CloudTrail Log Analysis

If you have CloudTrail logs in S3:

```bash
export INFRAGUARD_S3_BUCKET=your-cloudtrail-bucket
python main.py analyze-cloudtrail
```

## 5. (Optional) Setup Alerts

### For Slack:
```bash
export INFRAGUARD_SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK
python main.py check-all
```

### For SNS (email):
```bash
# Create SNS topic (one-time setup)
aws sns create-topic --name infraguard-alerts

# Subscribe your email (one-time setup)
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:YOUR-ACCOUNT:infraguard-alerts \
  --protocol email \
  --notification-endpoint your-email@example.com

# Set environment variable
export INFRAGUARD_SNS_TOPIC_ARN=arn:aws:sns:us-east-1:YOUR-ACCOUNT:infraguard-alerts

# Run with alerts
python main.py check-all
```

## 6. Save Results to File

```bash
# Save as JSON
python main.py check-all --output-file findings.json

# Save as CSV (for Excel)
python main.py check-all --output-format csv --output-file findings.csv
```

## Common Use Cases

### Daily Security Scan (Manual)
```bash
python main.py check-all --output-file daily-$(date +%Y%m%d).json
```

### Investigate Recent Security Events
```bash
python main.py analyze-cloudtrail --hours 48
```

### Focus on Network Security
```bash
python main.py check-network
```

### Debug Mode
```bash
python main.py check-all --log-level DEBUG
```

## What Gets Checked?

✅ **IAM Security:**
- Unused users (no activity in 90+ days)
- Root account access keys
- Overpermissive policies (admin access)
- Weak password policies

✅ **Network Security:**
- Security groups open to 0.0.0.0/0
- Risky ports exposed (SSH, RDP, databases)
- VPC Flow Logs enabled
- Public EC2 instances

✅ **S3 Security:**
- Public buckets
- Missing encryption
- Public access block settings

✅ **Audit & Compliance:**
- CloudTrail enabled and logging
- Root account usage detection
- Failed authentication attempts
- Privilege escalation attempts

## Troubleshooting

**"NoCredentialsError"**
→ Run `aws configure` to set up credentials

**"AccessDenied"**
→ Your IAM user needs SecurityAudit permissions

**"S3 bucket not configured"**
→ That's OK! You can still run check-all, check-iam, check-network

**No findings found**
→ Great! Your AWS is properly configured ✅

---

For full documentation, see [README.md](README.md)
