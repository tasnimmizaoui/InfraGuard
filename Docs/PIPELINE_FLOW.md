# InfraGuard Pipeline Flow

## 📋 Complete Workflow

### Trigger Events

| Event | Environment | Security Scan | Plan Scan | Deploy |
|-------|-------------|---------------|-----------|--------|
| **Push to main** | Production | ✅ Full (check-all) | ✅ Yes | ✅ Yes (if gates pass) |
| **PR to main** | Production | ✅ Full (check-all) | ❌ No | ❌ No |
| **Push to feature branch** | Development | ⚡ Limited (IAM+Network) | ❌ No | ❌ No |
| **Daily schedule (9 AM UTC)** | Development | ⚡ Limited (IAM+Network) | ❌ No | ❌ No |
| **Manual trigger** | User choice | Depends on env | ❌ No | ❌ No |

---

## 🔄 Push to Main Flow (Complete Deployment)

```
┌─────────────────────────────────────────────────────────┐
│  EVENT: Push to main branch (merge PR)                  │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  JOB 1: security-scan (environment: production)         │
├─────────────────────────────────────────────────────────┤
│  1. Determine Environment → "production"                 │
│  2. Run FULL security scan (check-all)                   │
│     ✓ IAM checks                                         │
│     ✓ Network/Security Groups                            │
│     ✓ S3 buckets                                         │
│     ✓ CloudTrail                                         │
│     ✓ VPC Flow Logs                                      │
│  3. Count findings (total, critical)                     │
│  4. Upload findings artifact                             │
│  5. ⛔ Security Gate: Block if CRITICAL findings         │
└────────────────────┬────────────────────────────────────┘
                     │
                     │ (only if gate passes)
                     ▼
┌─────────────────────────────────────────────────────────┐
│  JOB 2: deploy-terraform (environment: production)      │
├─────────────────────────────────────────────────────────┤
│  1. Terraform Init                                       │
│  2. Terraform Format Check                               │
│  3. Terraform Validate                                   │
│  4. Terraform Plan → tfplan.json                         │
│  5. Upload Plan Artifact                                 │
│                                                           │
│  ┌───────────────────────────────────────────────┐      │
│  │  🛡️ SHIFT-LEFT SECURITY (NEW!)                │      │
│  ├───────────────────────────────────────────────┤      │
│  │  6. Scan Terraform Plan                        │      │
│  │     python main.py scan-plan --plan-file ...   │      │
│  │     ✓ Check planned S3 buckets                 │      │
│  │     ✓ Check planned security groups            │      │
│  │     ✓ Check planned IAM policies               │      │
│  │     ✓ Detect issues BEFORE deployment          │      │
│  │  7. Upload Plan Scan Results                   │      │
│  │  8. ⛔ Security Gate: Block if CRITICAL in plan │      │
│  └───────────────────────────────────────────────┘      │
│                                                           │
│  9. Terraform Apply (only if plan scan passes)          │
│  10. Post-deployment Validation                          │
└─────────────────────────────────────────────────────────┘
```

---

## 🔀 Pull Request Flow (Gate Only)

```
┌─────────────────────────────────────────────────────────┐
│  EVENT: PR to main branch                                │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  JOB 1: security-scan (environment: production)         │
├─────────────────────────────────────────────────────────┤
│  1. Determine Environment → "production"                 │
│  2. Run FULL security scan (check-all)                   │
│  3. Count findings                                       │
│  4. Upload findings artifact                             │
│  5. ⛔ Security Gate: Block PR if CRITICAL findings      │
└─────────────────────────────────────────────────────────┘
                     
                     (deploy-terraform job does NOT run)
```

**Purpose:** Validate existing infrastructure is secure before allowing merge

---

## 🌿 Feature Branch Flow (Development)

```
┌─────────────────────────────────────────────────────────┐
│  EVENT: Push to feature-* branch                         │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  JOB 1: security-scan (environment: development)        │
├─────────────────────────────────────────────────────────┤
│  1. Determine Environment → "development"                │
│  2. Run LIMITED scan (check-iam + check-network)        │
│     ⚡ Cost optimization for dev                        │
│  3. Count findings                                       │
│  4. Upload findings artifact                             │
│  5. No security gate (informational only)                │
└─────────────────────────────────────────────────────────┘

                     (deploy-terraform job does NOT run)
```

**Purpose:** Quick feedback during development without full cost

---

## ⏰ Scheduled Daily Scan

```
┌─────────────────────────────────────────────────────────┐
│  EVENT: Cron schedule (9 AM UTC daily)                   │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  JOB 1: security-scan (environment: development)        │
├─────────────────────────────────────────────────────────┤
│  1. Determine Environment → "development"                │
│  2. Run LIMITED scan (check-iam + check-network)        │
│  3. Send alerts to SNS/Slack                             │
│  4. Upload findings artifact                             │
└─────────────────────────────────────────────────────────┘

                     (deploy-terraform job does NOT run)
```

**Purpose:** Daily monitoring without deployment

---

## 🎯 Security Gates Summary

### Gate 1: Runtime Security (Existing Infrastructure)
**Location:** `security-scan` job  
**Trigger:** PR to main OR push to main  
**Blocks:** If CRITICAL findings in existing AWS resources  
**Why:** Don't deploy into compromised environment

### Gate 2: Plan Security (Planned Changes)  NEW
**Location:** `deploy-terraform` job  
**Trigger:** Only on push to main (when deploying)  
**Blocks:** If CRITICAL findings in Terraform plan  
**Why:** Don't introduce new misconfigurations

### Gate Logic
```python
# Pseudo-code for complete flow
if push_to_main:
    runtime_critical = run_security_scan()  # Full scan
    if runtime_critical > 0:
        BLOCK("Existing infrastructure has critical issues")
        
    plan = terraform_plan()
    plan_critical = scan_plan(plan)  # NEW: Scan before apply
    if plan_critical > 0:
        BLOCK("Planned changes introduce critical issues")
        
    terraform_apply()  # Only if both gates pass
```

---

## 📊 Cost Optimization Strategy

| Scenario | Checks Run | Frequency | Cost Impact |
|----------|------------|-----------|-------------|
| Dev branches | IAM + Network | Per push | 💰 Minimal |
| Daily scan | IAM + Network | Once daily | 💰 Minimal |
| PR to main | Full scan | Per PR | 💰💰 Moderate |
| Deploy to main | Full + Plan scan | Per merge | 💰💰💰 Higher (but infrequent) |

**Design Philosophy:**
- ⚡ Fast feedback in dev (limited checks)
- 🛡️ Comprehensive validation for production
- 💰 Cost-conscious API usage
- 🎯 Security where it matters most

---

## 🚀 Quick Reference

### To test locally:
```bash
# Simulate dev scan
python main.py check-iam

# Simulate production scan
python main.py check-all

# Simulate plan scan
cd terraform && terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
python ../main.py scan-plan --plan-file tfplan.json
```

### To trigger manually:
1. Go to Actions tab in GitHub
2. Select "InfraGuard Security Scan"
3. Click "Run workflow"
4. Choose environment (development/staging/production)

### Expected behavior on merge to main:
1. ✅ Runtime scan runs (full scope)
2. ✅ Terraform plan created
3. ✅ Plan scan runs (shift-left security)
4. ✅ Deployment proceeds only if both gates pass
5. ✅ Post-deployment validation runs

---

## ✨ What Makes This Special

1. **Dual-Mode Scanning:** Catches issues at runtime AND before deployment
2. **Shift-Left Security:** Most issues caught in plan phase (cheaper to fix)
3. **Smart Environment Detection:** Automatic based on branch
4. **Cost Optimized:** Limited scans in dev, full scans in production
5. **Multiple Gates:** Defense in depth approach
6. **Clear Feedback:** Step summaries show exactly what's wrong

