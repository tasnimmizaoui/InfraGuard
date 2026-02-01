# Terraform Plan Testing for InfraGuard

This directory contains test Terraform configurations to verify InfraGuard's plan-time scanning feature.

## Test Files

- **insecure_test/insecure_test.tf**: Contains intentional security issues to test detection
- **secure_test/secure_test.tf**: Contains secure configurations that should pass scanning

## How to Test

### 1. Generate Terraform Plan JSON

For the insecure configuration:
```bash
cd test_plan/insecure_test
terraform init
terraform plan -out=insecure.tfplan
terraform show -json insecure.tfplan > insecure_plan.json
```

For the secure configuration:
```bash
cd test_plan/secure_test
terraform init
terraform plan -out=secure.tfplan
terraform show -json secure.tfplan > secure_plan.json
```

### 2. Scan the Plan with InfraGuard

Scan the insecure plan (should find CRITICAL/HIGH issues):
```bash
cd ..
python main.py scan-plan --plan-file test_plan/insecure_plan/insecure_plan.json
```

Scan the secure plan (should find no or minimal issues):
```bash
python main.py scan-plan --plan-file test_plan/secure_plan/secure_plan.json
```

### 3. Expected Results

**insecure_test.tf should detect:**
- CRITICAL: S3 bucket with public-read ACL
- HIGH: S3 buckets without encryption
- MEDIUM: S3 buckets without versioning
- HIGH: Security group with SSH (port 22) open to 0.0.0.0/0
- HIGH: Security group with RDP (port 3389) open to 0.0.0.0/0
- HIGH: IAM policy with admin access (*:*)

**secure_test.tf should:**
- Pass with no critical issues
- All S3 buckets have encryption, versioning, and public access blocked
- Security groups have restricted access
- IAM policies follow least privilege

## Integration with CI/CD

Add to your GitHub Actions workflow:

```yaml
- name: Generate Terraform Plan
  run: |
    terraform plan -out=tfplan
    terraform show -json tfplan > tfplan.json

- name: Scan Terraform Plan
  run: |
    python main.py scan-plan --plan-file tfplan.json
  # Exit code 1 if critical issues found, blocks deployment
```

## Notes

- Requires `terraform` to be installed
- Requires `random` provider for unique resource names
- Plans are not applied to AWS (no actual resources created)
- Safe to run locally for testing
