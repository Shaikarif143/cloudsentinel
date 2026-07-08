# CloudSentinel — Enterprise AWS Cloud Security & Compliance Platform

Automated AWS security auditing, compliance scoring, and auto-remediation, built entirely on native AWS services and provisioned with Terraform.

CloudSentinel continuously scans an AWS account for IAM, EC2, Security Group, S3, and EBS misconfigurations, scores the account against a weighted compliance model, auto-fixes a defined set of low-risk findings, and surfaces everything on a live React dashboard.

---

## Architecture

```
GitHub → GitHub Actions → Terraform
                              │
   AWS Config   CloudTrail   Security Hub
        └───────────┼───────────┘
                     │
              EventBridge (rate-based schedule)
                     │
              Scanner Lambda (Python)
              ├─ IAM checks
              ├─ EC2 checks
              ├─ Security Group checks
              ├─ S3 checks
              └─ EBS checks
                     │
         ┌───────────┼────────────┐
         ▼           ▼            ▼
     DynamoDB    CloudWatch      SNS ── Email / Slack
   (findings +               (alerts)
   compliance history)
         │
         ├──▶ Remediation Lambda (auto-fixes registered check_ids)
         │
         ▼
   React Dashboard (Vite) ── compliance score, trend, findings table
```

## Tech stack

| Layer | Tools |
|---|---|
| Cloud | AWS: IAM, EC2, S3, VPC, Security Groups, CloudTrail, CloudWatch, EventBridge, Lambda, DynamoDB, SNS, AWS Config, Security Hub |
| IaC | Terraform (modular: vpc, dynamodb, sns, cloudwatch, config, securityhub, lambda) |
| Backend | Python 3.12, boto3 |
| Frontend | React 18, Vite, Recharts |
| CI/CD | GitHub Actions (test → tf validate → checkov/tfsec → deploy infra → deploy dashboard → smoke test) |

## Repository structure

```
cloudsentinel/
├── terraform/
│   ├── main.tf, variables.tf, outputs.tf
│   ├── environments/dev.tfvars
│   └── modules/{vpc,dynamodb,sns,cloudwatch,config,securityhub,lambda}
├── backend/
│   ├── lambda/scanner/         # scheduled security scanner Lambda
│   │   ├── handler.py
│   │   ├── compliance_engine.py
│   │   └── checks/{iam,ec2,sg,s3,ebs}_checks.py
│   ├── lambda/remediation/     # auto-remediation Lambda
│   │   └── handler.py
│   ├── compliance/             # shared scoring engine (source of truth)
│   └── tests/                  # pytest unit tests
├── frontend/                   # React + Vite dashboard
│   └── src/{App.jsx, api.js, components/}
├── .github/workflows/deploy.yml
└── docs/, architecture/, reports/
```

## What each Lambda does

**Scanner (`backend/lambda/scanner/handler.py`)** — runs on an EventBridge schedule (default every 15 minutes). For each check category it calls the AWS APIs directly (read-only IAM role), collects findings, scores them with the compliance engine, writes findings + a compliance-history snapshot to DynamoDB, publishes a summary to SNS, and — if `AUTO_REMEDIATE=true` — asynchronously invokes the remediation Lambda for any findings whose `check_id` is in the auto-fixable set.

**Remediation (`backend/lambda/remediation/handler.py`)** — receives a list of findings and only acts on `check_id`s explicitly registered in `REMEDIATION_ACTIONS` (currently: block public S3 buckets, delete unused security groups). Everything else is reported, never silently modified — remediation is opt-in per check, not a blanket "fix everything" action.

## Checks implemented

- **IAM**: users without MFA, access keys older than 90 days, `AdministratorAccess` attached directly, users inactive 60+ days, weak/missing account password policy.
- **EC2**: instances with public IPs, missing governance tags, long-stopped instances, stale self-owned AMIs, unattached Elastic IPs.
- **Security Groups**: SSH/RDP/DB ports open to `0.0.0.0/0`, all-traffic-open rules, security groups not attached to any ENI.
- **S3**: publicly accessible buckets, missing default encryption, versioning disabled.
- **EBS**: unencrypted volumes, unattached volumes.

## Compliance scoring

Each finding is mapped to a category (IAM, S3, Networking, Encryption, Monitoring) and a severity (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`). Severities subtract fixed penalties from that category's 100-point baseline; the overall score is a weighted average across categories (IAM 30%, S3 20%, Networking 25%, Encryption 15%, Monitoring 10%). See `backend/compliance/compliance_engine.py`.

## Getting started

### 1. Provision infrastructure

```bash
cd terraform
terraform init \
  -backend-config="bucket=<your-tf-state-bucket>" \
  -backend-config="key=cloudsentinel/terraform.tfstate" \
  -backend-config="region=ap-south-1" \
  -backend-config="dynamodb_table=<your-tf-lock-table>"

terraform plan  -var-file=environments/dev.tfvars
terraform apply -var-file=environments/dev.tfvars
```

You'll need an S3 bucket + DynamoDB table for remote state (create these once, by hand or with a small bootstrap script, before the `init` above).

### 2. Run the scanner locally (optional, for testing)

```bash
cd backend/lambda/scanner
pip install -r requirements.txt
export FINDINGS_TABLE=cloudsentinel-dev-findings
export SNS_TOPIC_ARN=<topic-arn-from-terraform-output>
python handler.py   # requires AWS credentials with the scanner IAM permissions
```

### 3. Run the dashboard locally

```bash
cd frontend
npm install
npm run dev
```

The dashboard falls back to demo data automatically if `VITE_API_BASE_URL` isn't reachable, so it always renders something meaningful.

### 4. Run tests

```bash
pip install pytest boto3
pytest backend/tests -v
```

### 5. CI/CD

Push to `main` and GitHub Actions runs: pytest → `terraform fmt`/`validate` → Checkov/tfsec → `terraform apply` → build & deploy the dashboard to S3/CloudFront → a smoke-test Lambda invocation. Required repo secrets: `AWS_DEPLOY_ROLE_ARN` (OIDC role), `TF_STATE_BUCKET`, `TF_LOCK_TABLE`, `CLOUDSENTINEL_API_URL`, `DASHBOARD_BUCKET`, `CLOUDFRONT_DISTRIBUTION_ID`.

## Notes on scope / what's stubbed for interview purposes

- The dashboard's `api.js` points at a REST API (API Gateway + a small read Lambda over the two DynamoDB tables) that isn't included here — the dashboard ships with realistic mock data so it's demoable standalone. Wiring a thin API Gateway → Lambda → DynamoDB read layer is a natural "next step" talking point.
- PDF report generation (Phase 9) and the daily/weekly/monthly scheduling for it are described in `docs/` as a design doc rather than implemented, to keep this scoped to a working core pipeline.
- Auto-remediation intentionally only covers two check types out of the box — this is a safety choice, not a limitation of the architecture. Extending it is a one-function change (`REMEDIATION_ACTIONS` in `backend/lambda/remediation/handler.py`).

## Resume line

**CloudSentinel – Enterprise AWS Cloud Security & Compliance Platform**
Built a serverless AWS security posture management platform (Terraform, Lambda, DynamoDB, EventBridge, Security Hub, AWS Config) that scans an account every 15 minutes across 5 categories, computes a weighted compliance score, auto-remediates common misconfigurations, and surfaces findings on a React dashboard — with CI/CD via GitHub Actions (pytest, terraform validate, Checkov, tfsec).
