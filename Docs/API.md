# API Reference

Complete reference for InfraGuard CLI commands and Python API.

## CLI Commands

### check-all

Run all security checks on existing AWS infrastructure.

```bash
python main.py check-all [OPTIONS]
```

**Options:**
- `--output-file PATH`: Save findings to file
- `--output-format FORMAT`: Output format (json|csv|log) [default: json]
- `--region REGION`: AWS region to scan [default: from config]

**Example:**
```bash
python main.py check-all --output-file findings.json --output-format json
```

**Exit Codes:**
- `0`: Success (no critical findings)
- `1`: Critical findings detected

---

### check-iam

Scan IAM users, roles, and policies for security issues.

```bash
python main.py check-iam [OPTIONS]
```

**Checks Performed:**
- Unused IAM users (no activity in 90 days)
- Root account access keys
- Overpermissive IAM policies
- Weak password policies
- MFA disabled

**Example:**
```bash
python main.py check-iam --output-file iam-findings.json
```

---

### check-s3

Scan S3 buckets for security misconfigurations.

```bash
python main.py check-s3 [OPTIONS]
```

**Checks Performed:**
- Public bucket access
- Unencrypted buckets
- Versioning disabled
- Access logging disabled
- Bucket policies allowing public access

**Example:**
```bash
python main.py check-s3 --output-file s3-findings.json
```

---

### check-network

Scan network security configurations.

```bash
python main.py check-network [OPTIONS]
```

**Checks Performed:**
- Security groups open to 0.0.0.0/0
- SSH (port 22) exposed to internet
- RDP (port 3389) exposed to internet
- Database ports exposed
- VPC Flow Logs disabled
- Default security groups in use

**Example:**
```bash
python main.py check-network --output-file network-findings.json
```

---

### scan-plan

Scan Terraform plan before deployment (shift-left security).

```bash
python main.py scan-plan --plan-file PLAN_FILE [OPTIONS]
```

**Arguments:**
- `--plan-file PATH`: Path to Terraform plan JSON file (required)

**Options:**
- `--output-file PATH`: Save findings to file
- `--output-format FORMAT`: Output format (json|csv|log)

**Example:**
```bash
# Create Terraform plan
cd terraform
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Scan the plan
python ../main.py scan-plan --plan-file tfplan.json
```

**Checks Performed:**
- Same checks as runtime scanning, applied to planned resources
- S3 bucket configurations
- Security group rules
- IAM policy permissions
- CloudTrail settings
- VPC Flow Logs

---

## Python API

### SecurityChecker Class

Main class for runtime security scanning.

```python
from infra_guard.detection_rules import SecurityChecker
from infra_guard.config import Config

# Initialize
config = Config()
config.aws_region = 'eu-north-1'
checker = SecurityChecker(config)

# Run checks
findings = checker.check_all()
```

#### Methods

**`check_all() -> list`**

Run all security checks.

```python
findings = checker.check_all()
for finding in findings:
    print(f"[{finding['severity']}] {finding['description']}")
```

**`check_iam_unused_users() -> list`**

Check for unused IAM users.

```python
findings = checker.check_iam_unused_users()
```

**`check_security_groups() -> list`**

Check for overly permissive security groups.

```python
findings = checker.check_security_groups()
```

**`check_s3_buckets() -> list`**

Check S3 bucket configurations.

```python
findings = checker.check_s3_buckets()
```

**`check_cloudtrail() -> list`**

Check CloudTrail configuration.

```python
findings = checker.check_cloudtrail()
```

**`check_vpc_flow_logs() -> list`**

Check VPC Flow Logs configuration.

```python
findings = checker.check_vpc_flow_logs()
```

---

### TerraformPlanScanner Class

Class for plan-time security scanning.

```python
from infra_guard.plan_analyzer import TerraformPlanScanner

# Initialize
scanner = TerraformPlanScanner('tfplan.json')

# Run scan
findings = scanner.scan_all()
```

#### Methods

**`scan_all() -> list`**

Scan all resources in the plan.

```python
findings = scanner.scan_all()
```

**`scan_s3_buckets() -> list`**

Scan planned S3 buckets.

```python
findings = scanner.scan_s3_buckets()
```

**`scan_security_groups() -> list`**

Scan planned security groups.

```python
findings = scanner.scan_security_groups()
```

**`scan_iam_policies() -> list`**

Scan planned IAM policies.

```python
findings = scanner.scan_iam_policies()
```

---

### Policy Engine Functions

Reusable security policy functions.

```python
from infra_guard.policy_engine import (
    is_s3_bucket_public,
    is_s3_bucket_unencrypted,
    is_s3_versioning_disabled,
    is_security_group_overly_permissive,
    is_iam_policy_overpermissive
)
```

**`is_s3_bucket_public(bucket_data, source='boto3') -> tuple`**

Check if S3 bucket allows public access.

```python
# With boto3 data
bucket = s3_client.get_bucket_acl(Bucket='my-bucket')
is_public, message = is_s3_bucket_public(bucket, source='boto3')

# With Terraform plan data
is_public, message = is_s3_bucket_public(resource, source='terraform')
```

**Returns:** `(bool, str)` - (is_issue, description)

**`is_s3_bucket_unencrypted(bucket_data, source='boto3') -> tuple`**

Check if S3 bucket lacks encryption.

```python
is_unencrypted, message = is_s3_bucket_unencrypted(bucket_data)
```

**`is_s3_versioning_disabled(bucket_data, source='boto3') -> tuple`**

Check if S3 bucket versioning is disabled.

```python
is_disabled, message = is_s3_versioning_disabled(bucket_data)
```

**`is_security_group_overly_permissive(sg_data, source='boto3') -> tuple`**

Check for overly permissive security group rules.

```python
is_permissive, message = is_security_group_overly_permissive(sg_data)
```

**`is_iam_policy_overpermissive(policy_data) -> tuple`**

Check for overly permissive IAM policies.

```python
is_permissive, message = is_iam_policy_overpermissive(policy_data)
```

---

### Configuration

```python
from infra_guard.config import Config

config = Config()
config.aws_region = 'eu-north-1'
config.s3_bucket = 'my-logs-bucket'
config.sns_topic_arn = 'arn:aws:sns:...'
config.slack_webhook = 'https://hooks.slack.com/...'
config.log_level = 'INFO'
```

**Environment Variables:**
- `AWS_REGION`: AWS region
- `INFRAGUARD_S3_BUCKET`: S3 bucket for logs
- `INFRAGUARD_SNS_TOPIC_ARN`: SNS topic for alerts
- `INFRAGUARD_SLACK_WEBHOOK`: Slack webhook URL
- `INFRAGUARD_LOG_LEVEL`: Logging level (DEBUG|INFO|WARNING|ERROR)

---

### Alerting

```python
from infra_guard.alerting import send_sns_alert, send_slack_alert

# Send SNS alert
send_sns_alert(
    topic_arn='arn:aws:sns:...',
    subject='Security Alert',
    message='Critical findings detected',
    region='eu-north-1'
)

# Send Slack alert
send_slack_alert(
    webhook_url='https://hooks.slack.com/...',
    message='Critical findings detected',
    findings=[...]
)
```

---

## Finding Format

All checks return findings in this format:

```json
{
  "timestamp": "2026-02-01T12:00:00.000000",
  "category": "S3|IAM|SecurityGroup|CloudTrail|VPC",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "description": "Human-readable description",
  "resource": "Resource identifier (ARN, ID, name)",
  "details": {
    "key": "Additional context"
  },
  "recommendation": "How to fix the issue"
}
```

### Severity Levels

- **CRITICAL**: Immediate security risk requiring urgent action
  - Examples: S3 bucket public, SSH open to world, admin access for all users
  
- **HIGH**: Significant security concern requiring prompt attention
  - Examples: No CloudTrail, weak password policy, unused root access keys

- **MEDIUM**: Moderate security issue that should be addressed
  - Examples: No VPC Flow Logs, old IAM access keys, no MFA

- **LOW**: Best practice recommendation
  - Examples: S3 versioning disabled, access logging off

### Categories

- **S3**: S3 bucket configurations
- **IAM**: Identity and Access Management
- **SecurityGroup**: Network security groups
- **CloudTrail**: Audit logging
- **VPC**: Virtual Private Cloud
- **EC2**: Compute instances
- **Lambda**: Serverless functions

---

## Examples

### Example 1: Custom Security Check

```python
from infra_guard.detection_rules import SecurityChecker
from infra_guard.config import Config

class CustomChecker(SecurityChecker):
    def check_ec2_tags(self):
        """Check if EC2 instances have required tags."""
        findings = []
        ec2 = self.get_client('ec2')
        
        instances = ec2.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                tags = {t['Key']: t['Value'] for t in instance.get('Tags', [])}
                
                if 'Environment' not in tags:
                    findings.append({
                        'timestamp': datetime.now().isoformat(),
                        'category': 'EC2',
                        'severity': 'MEDIUM',
                        'description': 'EC2 instance missing Environment tag',
                        'resource': instance['InstanceId'],
                        'recommendation': 'Add Environment tag to instance'
                    })
        
        return findings

# Use it
config = Config()
checker = CustomChecker(config)
findings = checker.check_ec2_tags()
```

### Example 2: Filter Findings by Severity

```python
findings = checker.check_all()

critical = [f for f in findings if f['severity'] == 'CRITICAL']
high = [f for f in findings if f['severity'] == 'HIGH']

print(f"Critical: {len(critical)}, High: {len(high)}")
```

### Example 3: Export to CSV

```python
import csv

findings = checker.check_all()

with open('findings.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['timestamp', 'severity', 'category', 'description', 'resource'])
    writer.writeheader()
    for finding in findings:
        writer.writerow({
            'timestamp': finding['timestamp'],
            'severity': finding['severity'],
            'category': finding['category'],
            'description': finding['description'],
            'resource': finding['resource']
        })
```

### Example 4: Integration with Monitoring

```python
import time
from infra_guard.detection_rules import SecurityChecker
from infra_guard.alerting import send_slack_alert

def continuous_monitoring(interval_minutes=60):
    """Run security checks continuously."""
    config = Config()
    checker = SecurityChecker(config)
    
    while True:
        findings = checker.check_all()
        critical = [f for f in findings if f['severity'] == 'CRITICAL']
        
        if critical:
            send_slack_alert(
                webhook_url=config.slack_webhook,
                message=f" {len(critical)} critical security issues detected!",
                findings=critical
            )
        
        time.sleep(interval_minutes * 60)

# Run
continuous_monitoring(interval_minutes=60)
```

---

## Error Handling

All functions handle AWS API errors gracefully:

```python
try:
    findings = checker.check_all()
except ClientError as e:
    if e.response['Error']['Code'] == 'AccessDenied':
        print("Insufficient permissions")
    elif e.response['Error']['Code'] == 'UnauthorizedOperation':
        print("Not authorized for this operation")
    else:
        print(f"AWS API error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

---

## Further Reading

- [Architecture Overview](ARCHITECTURE.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Shift-Left Security](SHIFT_LEFT.md)
- [AWS Setup](AWS_SETUP.md)
