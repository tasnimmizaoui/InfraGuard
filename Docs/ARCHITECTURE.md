# InfraGuard Architecture

## System Overview

InfraGuard is a comprehensive AWS security monitoring system with three main components:

1. **Security Scanner** - Python application for detecting security issues
2. **Infrastructure** - Terraform-managed AWS resources for logging and monitoring
3. **CI/CD Pipeline** - Automated security gates and deployments

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Developer                                │
└────────────────────────┬────────────────────────────────────────┘
                         │
                    git push
                         │
┌────────────────────────▼────────────────────────────────────────┐
│                    GitHub Repository                             │
│  • Terraform Code        •Python Scanner        • GitHub Actions│
└────────────────────────┬────────────────────────────────────────┘
                         │
                  Triggers on push
                         │
┌────────────────────────▼────────────────────────────────────────┐
│                GitHub Actions Pipeline                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Job 1: Security Scan (security-scan)                    │  │
│  ├──────────────────────────────────────────────────────────┤  │
│  │  1. Setup Python 3.11                                    │  │
│  │  2. Install dependencies (boto3, etc.)                   │  │
│  │  3. Configure AWS credentials (OIDC or keys)             │  │
│  │  4. Run InfraGuard runtime scan                          │  │
│  │     └─ Queries live AWS resources via boto3             │  │
│  │     └─ Detects security misconfigurations               │  │
│  │  5. Upload findings as artifact                          │  │
│  │  6. Security Gate: Block if CRITICAL findings            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                         │                                        │
│                     Success?                                     │
│                         │                                        │
│  ┌──────────────────────▼──────────────────────────────────┐  │
│  │  Job 2: Deploy Terraform (deploy-terraform)             │  │
│  ├──────────────────────────────────────────────────────────┤  │
│  │  1. Setup Terraform 1.6                                  │  │
│  │  2. Initialize with S3 backend                           │  │
│  │  3. Run terraform fmt check                              │  │
│  │  4. Run terraform validate                               │  │
│  │  5. Create terraform plan                                │  │
│  │  6. Convert plan to JSON                                 │  │
│  │  7. Scan plan (SHIFT-LEFT SECURITY)                      │  │
│  │     └─ Analyzes planned changes                         │  │
│  │     └─ Detects issues BEFORE deployment                 │  │
│  │  8. Security Gate: Block if CRITICAL in plan            │  │
│  │  9. Apply terraform (if gates pass)                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                         │                                        │
└─────────────────────────┼────────────────────────────────────────┘
                          │
                     terraform apply
                          │
┌─────────────────────────▼────────────────────────────────────────┐
│                      AWS Account                                  │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Logging & Monitoring Infrastructure                     │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │  • CloudTrail (audit logging)                            │   │
│  │  • VPC Flow Logs (network traffic)                       │   │
│  │  • S3 Buckets (log storage, encrypted)                   │   │
│  │  • CloudWatch Log Groups                                 │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Automated Scanning Infrastructure                       │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │  • Lambda Function (runs InfraGuard scanner)             │   │
│  │  • EventBridge Schedule (daily trigger)                  │   │
│  │  • IAM Role (least privilege for scanner)                │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Alerting Infrastructure                                 │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │  • SNS Topics (email/SMS notifications)                  │   │
│  │  • Slack Webhook Integration                             │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  State Management                                        │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │  • S3 Bucket (Terraform state)                           │   │
│  │  • DynamoDB Table (state locking)                        │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Python Application Architecture

```
InfraGuard Python Scanner
├── CLI Layer (main.py)
│   ├── check-all        - Run all runtime checks
│   ├── check-iam        - IAM-specific checks
│   ├── check-s3         - S3-specific checks
│   ├── check-network    - Network checks
│   └── scan-plan        - Scan Terraform plans
│
├── Core Libraries (infra_guard/)
│   │
│   ├── config.py - Configuration management
│   │   └── Loads environment variables
│   │   └── AWS credentials handling
│   │
│   ├── detection_rules.py - Runtime scanning
│   │   └── SecurityChecker class
│   │       ├── check_iam_unused_users()
│   │       ├── check_security_groups()
│   │       ├── check_s3_buckets()
│   │       └── check_all()
│   │
│   ├── policy_engine.py - Reusable security policies
│   │   ├── is_s3_bucket_public()
│   │   ├── is_s3_bucket_unencrypted()
│   │   ├── is_s3_versioning_disabled()
│   │   ├── is_security_group_overly_permissive()
│   │   ├── is_iam_policy_overpermissive()
│   │   └── Normalization helpers
│   │
│   ├── plan_analyzer.py - Plan-time scanning
│   │   └── TerraformPlanScanner class
│   │       ├── parse_plan()
│   │       ├── link_resources()
│   │       ├── scan_s3_buckets()
│   │       └── scan_all()
│   │
│   ├── alerting.py - Notifications
│   │   ├── send_sns_alert()
│   │   └── send_slack_alert()
│   │
│   └── utils.py - Helper functions
│       ├── setup_logging()
│       └── Output formatters
│
└── AWS SDK (boto3)
    └── Interacts with AWS services
```

## Terraform Infrastructure Architecture

```
terraform/
├── backend.tf - S3 backend configuration
├── main.tf - Root module
├── variables.tf - Input variables
├── outputs.tf - Output values
├── terraform.tfvars - Variable values
│
├── bootstrap/ - State backend setup
│   ├── main.tf - S3 + DynamoDB
│   └── variables.tf
│
└── modules/
    │
    ├── iam/ - IAM resources
    │   ├── Scanner IAM user
    │   ├── Lambda execution role
    │   ├── Secrets Manager for credentials
    │   └── Least privilege policies
    │
    ├── logging/ - Audit logging
    │   ├── CloudTrail multi-region
    │   ├── CloudWatch Log Groups
    │   ├── Log encryption
    │   └── Access logging
    │
    ├── storage/ - S3 buckets
    │   ├── Findings storage bucket
    │   ├── Logs storage bucket
    │   ├── Versioning enabled
    │   ├── Encryption at rest
    │   └── Public access blocked
    │
    ├── lambda/ - Automated scanning
    │   ├── Lambda function
    │   ├── EventBridge trigger (daily)
    │   ├── Deployment package
    │   └── Environment configuration
    │
    └── monitoring/ - Alerts
        ├── SNS topics
        ├── Subscriptions
        └── CloudWatch alarms
```

## Data Flow

### Runtime Scanning Flow

```
1. Trigger
   ├── Manual: python main.py check-all
   ├── CI/CD: GitHub Actions
   └── Automated: Lambda function (daily)
   
2. Authentication
   └── AWS credentials → boto3 client
   
3. Resource Discovery
   ├── IAM: list_users, get_account_summary
   ├── S3: list_buckets, get_bucket_acl
   ├── EC2: describe_security_groups, describe_vpcs
   └── CloudTrail: describe_trails
   
4. Security Analysis
   └── detection_rules.py + policy_engine.py
       └── Apply security policies to each resource
       
5. Findings Generation
   └── JSON/CSV/Log output
       ├── Severity: CRITICAL, HIGH, MEDIUM, LOW
       ├── Category: IAM, S3, Network, CloudTrail
       └── Recommendations
       
6. Alerting (if configured)
   ├── SNS → Email/SMS
   └── Slack → Webhook
```

### Plan-Time Scanning Flow (Shift-Left)

```
1. Terraform Plan Creation
   └── terraform plan -out=tfplan
   └── terraform show -json tfplan > tfplan.json
   
2. Plan Parsing
   └── plan_analyzer.py reads JSON
   └── Extracts planned_values and resource_changes
   
3. Resource Linking
   └── Connect related resources
       ├── aws_s3_bucket → aws_s3_bucket_public_access_block
       ├── aws_s3_bucket → aws_s3_bucket_server_side_encryption_configuration
       └── aws_security_group → ingress rules
       
4. Security Analysis
   └── policy_engine.py (same policies as runtime)
       └── Analyze planned resources
       
5. Findings Generation
   └── Same format as runtime scanning
   
6. Security Gate
   └── Exit code 1 if CRITICAL findings
       └── Blocks terraform apply
```

## Security Architecture

### Defense in Depth

1. **Network Layer**
   - Security groups with least privilege
   - VPC Flow Logs for traffic analysis
   - No direct internet exposure

2. **Application Layer**
   - Lambda functions with minimal permissions
   - Input validation
   - Error handling

3. **Data Layer**
   - S3 encryption at rest (AES-256)
   - Versioning for data protection
   - Public access blocked
   - Access logging

4. **Access Control**
   - IAM roles with least privilege
   - No long-lived credentials in Lambda
   - Secrets Manager for sensitive data
   - MFA recommended for admin access

5. **Audit & Compliance**
   - CloudTrail for API logging
   - VPC Flow Logs for network traffic
   - Automated security scanning
   - Findings stored securely

## Scalability Considerations

### Current Design (Small-Medium AWS Accounts)
- Synchronous scanning
- Single-threaded execution
- In-memory processing

### Scaling for Large Environments

1. **Parallel Scanning**
   ```python
   # Use ThreadPoolExecutor for concurrent checks
   with ThreadPoolExecutor(max_workers=10) as executor:
       futures = [
           executor.submit(check_iam),
           executor.submit(check_s3),
           executor.submit(check_network)
       ]
   ```

2. **Regional Distribution**
   - Run scanner in each AWS region
   - Aggregate findings centrally

3. **Resource Pagination**
   - Handle large numbers of resources
   - Use AWS SDK paginators

4. **Caching**
   - Cache resource lookups
   - Reduce API calls

5. **Event-Driven Architecture**
   - CloudWatch Events for resource changes
   - Real-time scanning on create/modify

## Cost Architecture

### Free Tier Usage
- CloudTrail: 1 trail free
- S3: First 5GB free
- Lambda: 1M requests/month free
- CloudWatch Logs: 5GB ingestion free

### Paid Services (Minimal)
- S3 storage: ~$0.50/month for logs
- CloudWatch Logs (beyond 5GB): ~$1/month
- Lambda (beyond free tier): ~$0.20/month

### Cost Optimization
1. Log retention: 30-90 days
2. S3 lifecycle policies: Move to Glacier
3. CloudWatch log groups: Set expiration
4. Lambda: Optimize memory allocation
5. Scheduled scanning: Once daily vs. continuous

## High Availability

### Current Design
- Serverless (Lambda) - AWS-managed HA
- Multi-region CloudTrail
- S3 replication available if needed

### Future Enhancements
1. Multi-region deployment
2. Cross-region replication for findings
3. Backup automation
4. Disaster recovery procedures

## Monitoring & Observability

### Application Metrics
- Scan duration
- Findings count by severity
- API call count
- Error rates

### Infrastructure Metrics
- Lambda execution duration
- Lambda error rate
- S3 storage utilization
- CloudWatch Logs ingestion

### Alerting Thresholds
- CRITICAL findings: Immediate alert
- HIGH findings: Daily summary
- Scan failures: Immediate alert
- Cost anomalies: Weekly review

## Integration Points

### Current Integrations
- GitHub Actions (CI/CD)
- AWS Services (boto3)
- Slack (webhooks)
- SNS (email/SMS)


## Technology Stack

### Languages & Frameworks
- Python 3.11
- Terraform 1.6
- GitHub Actions

### AWS Services
- IAM, S3, Lambda, CloudTrail, VPC, CloudWatch, SNS, Secrets Manager, DynamoDB

### Python Libraries
- boto3 (AWS SDK)
- click (CLI)
- python-dotenv (config)
- requests (HTTP)

### Development Tools
- Git (version control)
- VS Code (IDE)
- AWS CLI (testing)

## Further Reading

- [Deployment Guide](DEPLOYMENT.md)
- [Shift-Left Security](SHIFT_LEFT.md)
- [API Reference](API.md)
- [AWS Setup](AWS_SETUP.md)
