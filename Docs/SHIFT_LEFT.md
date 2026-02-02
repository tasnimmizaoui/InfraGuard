# Shift-Left Security Implementation

## Overview

InfraGuard implements **shift-left security** by scanning Terraform plans BEFORE deployment, catching security issues early in the development lifecycle.

## How It Works

### Traditional Approach (Deploy → Find → Fix)
```
Code → Deploy → Security Scan → Find Issues → Rollback → Fix → Deploy Again
```

### Shift-Left Approach (Find → Fix → Deploy)
```
Code → Terraform Plan → Security Scan → Fix Issues → Deploy Secure Infrastructure
```

## Architecture

```
┌──────────────────────────────┐
│    Developer Commits Code    │
└──────────┬───────────────────┘
           │
┌──────────▼───────────────────┐
│  GitHub Actions Triggered    │
└──────────┬───────────────────┘
           │
┌──────────▼───────────────────┐
│  1. Runtime Security Scan    │
│     (Existing Infrastructure)│
└──────────┬───────────────────┘
           │
┌──────────▼───────────────────┐
│  2. Terraform Plan Created   │
│     terraform plan -out=plan │
└──────────┬───────────────────┘
           │
┌──────────▼───────────────────┐
│  3. Plan Security Scan       │
│     (Planned Changes)        │
│     ◄──── SHIFT-LEFT!        │
└──────────┬───────────────────┘
           │
      ┌────▼────┐
      │ Issues? │
      └────┬────┘
           │
    ┌──────┴──────┐
    │             │
   YES           NO
    │             │
┌───▼───┐    ┌───▼─────────────┐
│ BLOCK │    │ Deploy to AWS   │
└───────┘    └─────────────────┘
```

## Implementation

### 1. Policy Engine (`policy_engine.py`)

Reusable security policies that work with both runtime and plan-time data:

```python
# Example: Checking if S3 bucket is public
def is_s3_bucket_public(bucket_data, source='boto3'):
    """
    Detects public S3 buckets.
    Works with both boto3 runtime data and Terraform plan data.
    """
    # Normalize data format
    if source == 'boto3':
        bucket_data = normalize_boto3_s3_bucket(bucket_data)
    elif source == 'terraform':
        bucket_data = normalize_terraform_s3_bucket(bucket_data)
    
    # Apply security policy
    if bucket_data.get('public_access_block_enabled') == False:
        return True, "S3 bucket allows public access"
    
    return False, ""
```

### 2. Plan Analyzer (`plan_analyzer.py`)

Parses Terraform plans and applies security policies:

```python
def scan_terraform_plan(plan_file_path):
    # Parse terraform show -json output
    with open(plan_file_path, 'r') as f:
        plan = json.load(f)
    
    findings = []
    
    # Scan planned resources
    for resource in plan.get('planned_values', {}).get('root_module', {}).get('resources', []):
        if resource['type'] == 'aws_s3_bucket':
            # Apply security policies
            is_public, message = is_s3_bucket_public(resource, source='terraform')
            if is_public:
                findings.append({
                    'severity': 'CRITICAL',
                    'category': 'S3',
                    'description': message,
                    'resource': resource['address']
                })
    
    return findings
```

### 3. GitHub Actions Integration

```yaml
- name: Scan Terraform Plan
  run: |
    # Create Terraform plan in JSON format
    terraform plan -out=tfplan
    terraform show -json tfplan > tfplan.json
    
    # Scan the plan BEFORE applying
    python ../main.py scan-plan --plan-file tfplan.json
    
    # Block deployment if critical issues found
    if [ $? -ne 0 ]; then
      echo "❌ Critical security issues in planned infrastructure!"
      exit 1
    fi

- name: Terraform Apply
  # Only runs if plan scan passed
  run: terraform apply tfplan
```

## Benefits

### 1. Early Detection
- Catch security issues **before** resources are created in AWS
- No cleanup required - fix the code, not the infrastructure

### 2. Cost Savings
- Avoid creating insecure resources
- No rollback costs
- Faster development cycles

### 3. Compliance
- Ensure every deployment meets security standards
- Automated enforcement of security policies
- Audit trail of what was checked and when

### 4. Developer Feedback
- Immediate feedback in pull requests
- Clear error messages explaining the issue
- Recommendations for fixing the problem

## Example Workflow

### Scenario: Developer adds an S3 bucket

**Step 1: Developer writes Terraform code**
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

# Forgot to add public access block!
```

**Step 2: Commit and push to GitHub**
```bash
git add terraform/
git commit -m "Add S3 bucket for data storage"
git push origin feature/add-s3-bucket
```

**Step 3: GitHub Actions runs**
```
✅ Runtime scan passes
✅ Terraform plan created
❌ Plan scan BLOCKS deployment:

CRITICAL: S3 bucket 'aws_s3_bucket.data' allows public access
Recommendation: Add aws_s3_bucket_public_access_block resource

Deployment blocked. Fix the issues and try again.
```

**Step 4: Developer fixes the issue**
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

**Step 5: Push again**
```
✅ Runtime scan passes
✅ Terraform plan created
✅ Plan scan passes - No issues found!
✅ Terraform apply succeeds
🎉 Secure infrastructure deployed!
```

## Security Checks Performed

### S3 Buckets
- ✅ Public access configuration
- ✅ Encryption at rest
- ✅ Versioning enabled
- ✅ Bucket policies

### Security Groups
- ✅ SSH (port 22) exposure to internet
- ✅ RDP (port 3389) exposure to internet
- ✅ Overly permissive rules (0.0.0.0/0)
- ✅ Default security groups

### IAM Policies
- ✅ Overpermissive policies (e.g., `*:*` actions)
- ✅ Admin-level access
- ✅ Resource-level permissions

### CloudTrail
- ✅ Multi-region trails
- ✅ Log validation
- ✅ Encryption configuration

### VPC
- ✅ Flow logs enabled
- ✅ Flow log destination configuration

## Testing

### Test with Intentional Security Issues

```bash
cd test_plan/insecure_test
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
python ../../main.py scan-plan --plan-file tfplan.json
```

**Expected output:**
```
🔍 Scanning Terraform Plan...

CRITICAL Issues Found:
  • S3 bucket allows public access
  • Security group allows SSH from internet
  • IAM policy is overpermissive

❌ Critical security findings detected! Deployment blocked.
```

### Test with Secure Configuration

```bash
cd test_plan/secure_test
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
python ../../main.py scan-plan --plan-file tfplan.json
```

**Expected output:**
```
🔍 Scanning Terraform Plan...

✅ No critical security issues found in planned infrastructure!
Plan is safe to deploy.
```

## Integration with CI/CD

The shift-left security scan is automatically integrated into the GitHub Actions pipeline:

1. **Every push to main** triggers the pipeline
2. **Runtime scan** checks existing infrastructure
3. **Terraform plan** is created
4. **Plan scan** analyzes the planned changes ← **SHIFT-LEFT**
5. **Security gate** blocks deployment if critical issues are found
6. **Terraform apply** only runs if all checks pass

## Further Reading

- [Architecture Overview](ARCHITECTURE.md)
- [Deployment Guide](DEPLOYMENT.md)
- [API Reference](API.md)
- [AWS Setup](AWS_SETUP.md)
