# Quick Start Guide for InfraGuard

## Choose Your Setup Method

### Option A: Docker Hub (Fastest - Just Pull & Run) ⚡

No build required! Pull the pre-built image and start scanning immediately.

```bash
# 1. Pull the image (one-time)
docker pull yourusername/infraguard:latest

# 2. Run security scan
docker run --rm \
  -v ~/.aws:/home/infraguard/.aws:ro \
  -e AWS_REGION=eu-north-1 \
  yourusername/infraguard:latest check-all

# That's it! See beautiful colored output 🎨
```

**Windows PowerShell:**
```powershell
# Pull image
docker pull yourusername/infraguard:latest

# Run scan
docker run --rm `
  -v C:\Users\$env:USERNAME\.aws:/home/infraguard/.aws:ro `
  -e AWS_REGION=eu-north-1 `
  yourusername/infraguard:latest check-all
```

**Save scan results:**
```bash
docker run --rm \
  -v ~/.aws:/home/infraguard/.aws:ro \
  -v $(pwd)/scan-results:/app/scan-results \
  -e AWS_REGION=eu-north-1 \
  yourusername/infraguard:latest check-all --output-file /app/scan-results/findings.json
```

### Option B: Docker Compose (For Development)

```bash
# Clone repository
git clone https://github.com/yourusername/InfraGuard.git
cd InfraGuard

# Build and run
docker-compose build
docker-compose run --rm infraguard check-all
```

### Option C: Local Python Installation

#### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

#### 2. Configure AWS Credentials

```bash
aws configure
```

Enter your:
- AWS Access Key ID
- AWS Secret Access Key
- Default region (e.g., eu-north-1)
- Default output format (json)

#### 3. Run Your First Security Scan

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

For full documentation, see [README.md]()
