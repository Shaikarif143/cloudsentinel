# Phase 9 — Reporting (design notes)

Not implemented in code yet; documented here as the next build step.

## Goal
Generate a PDF compliance report (daily/weekly/monthly) from the same
data the dashboard uses, for stakeholders who want a static snapshot
instead of a live view.

## Proposed approach
- A third Lambda (`report-generator`) triggered by its own EventBridge
  schedule (cron, not rate-based, so it can run "daily at 08:00 IST" etc).
- Reads the latest N compliance-history rows + findings from DynamoDB
  (same tables the scanner already writes).
- Renders with a lightweight HTML→PDF path (e.g. `weasyprint` in a Lambda
  layer, or offload to a headless Chromium container) using a Jinja2
  template that mirrors the dashboard's score cards + findings table.
- Uploads the PDF to the existing `log_archive` S3 bucket under
  `reports/{daily,weekly,monthly}/YYYY-MM-DD.pdf` and emails a link via
  the existing SNS topic.

## Report structure (target)
```
Cloud Security Report
Overall Score        95%
Critical  1   High  3   Medium  8   Low  21
Passed  176   Failed  12
Recommendations:
 - Enable MFA
 - Encrypt Bucket
 - Remove AdminAccess
```
This maps directly onto `score_findings()` + `top_risks()` in
`backend/compliance/compliance_engine.py` — the report generator would
reuse that module rather than recomputing anything.
