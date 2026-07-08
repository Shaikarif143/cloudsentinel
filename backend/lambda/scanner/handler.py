"""
CloudSentinel Security Scanner Lambda.

Triggered on a schedule (default: every 15 minutes) by EventBridge.
Runs every check module, scores the results, stores findings +
compliance history in DynamoDB, publishes a summary to SNS, and
optionally invokes the remediation Lambda for auto-fixable findings.
"""
import json
import os
import uuid
import datetime
import logging

import boto3

from checks import iam_checks, ec2_checks, sg_checks, s3_checks, ebs_checks
from compliance_engine import score_findings, top_risks

logger = logging.getLogger()
logger.setLevel(logging.INFO)

FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE", "cloudsentinel-dev-findings")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
REMEDIATION_FN_NAME = os.environ.get("REMEDIATION_FN_NAME")
AUTO_REMEDIATE = os.environ.get("AUTO_REMEDIATE", "false").lower() == "true"

# Finding check_ids that the remediation Lambda knows how to fix automatically.
AUTO_FIXABLE_CHECK_IDS = {"S3-001", "SG-005"}

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")
lambda_client = boto3.client("lambda")


def run_scan():
    """Run every check module against live AWS resources and return all findings."""
    iam = boto3.client("iam")
    ec2 = boto3.client("ec2")
    s3 = boto3.client("s3")

    findings = []
    check_modules = [
        ("IAM", lambda: iam_checks.run_all(iam)),
        ("EC2", lambda: ec2_checks.run_all(ec2)),
        ("Security Groups", lambda: sg_checks.run_all(ec2)),
        ("S3", lambda: s3_checks.run_all(s3)),
        ("EBS", lambda: ebs_checks.run_all(ec2)),
    ]

    for label, run_fn in check_modules:
        try:
            module_findings = run_fn()
            logger.info("%s check produced %d finding(s)", label, len(module_findings))
            findings.extend(module_findings)
        except Exception:
            logger.exception("Check module '%s' failed, continuing with remaining checks", label)

    return findings


def persist_findings(findings, scan_timestamp):
    table = dynamodb.Table(FINDINGS_TABLE)
    with table.batch_writer() as batch:
        for finding in findings:
            item = dict(finding)
            item["finding_id"] = f"{finding['check_id']}#{finding['resource_id']}#{uuid.uuid4().hex[:8]}"
            item["scan_timestamp"] = scan_timestamp
            batch.put_item(Item=item)


def persist_compliance_history(score_result, scan_date):
    table = dynamodb.Table(FINDINGS_TABLE.replace("-findings", "-compliance-history"))
    table.put_item(Item={
        "scan_date": scan_date,
        **score_result,
    })


def notify(score_result, risks, scan_timestamp):
    if not SNS_TOPIC_ARN:
        return

    critical = score_result["severity_counts"].get("CRITICAL", 0)
    high = score_result["severity_counts"].get("HIGH", 0)
    subject = f"CloudSentinel scan complete — score {score_result['overall_score']}%"

    if critical or high:
        subject = f"[ACTION NEEDED] {subject} — {critical} critical, {high} high findings"

    lines = [
        f"CloudSentinel scan at {scan_timestamp}",
        f"Overall compliance score: {score_result['overall_score']}%",
        "",
        "Category scores:",
    ]
    for category, value in score_result["categories"].items():
        lines.append(f"  {category}: {value}%")

    lines.append("")
    lines.append(f"Findings by severity: {score_result['severity_counts']}")
    lines.append("")
    lines.append("Top risks:")
    for risk in risks:
        lines.append(f"  [{risk['severity']}] {risk['message']}")

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject[:100],
        Message="\n".join(lines),
    )


def trigger_remediation(findings):
    """Invoke the remediation Lambda asynchronously for auto-fixable findings."""
    if not (AUTO_REMEDIATE and REMEDIATION_FN_NAME):
        return

    fixable = [f for f in findings if f["check_id"] in AUTO_FIXABLE_CHECK_IDS]
    if not fixable:
        return

    logger.info("Invoking remediation Lambda for %d auto-fixable finding(s)", len(fixable))
    lambda_client.invoke(
        FunctionName=REMEDIATION_FN_NAME,
        InvocationType="Event",  # async, fire-and-forget
        Payload=json.dumps({"findings": fixable}).encode("utf-8"),
    )


def lambda_handler(event, context):
    scan_started = datetime.datetime.utcnow()
    scan_timestamp = scan_started.isoformat() + "Z"
    scan_date = scan_started.strftime("%Y-%m-%d")

    findings = run_scan()
    score_result = score_findings(findings)
    risks = top_risks(findings, limit=5)

    persist_findings(findings, scan_timestamp)
    persist_compliance_history(score_result, scan_date)
    notify(score_result, risks, scan_timestamp)
    trigger_remediation(findings)

    result = {
        "scan_timestamp": scan_timestamp,
        "findings_count": len(findings),
        **score_result,
    }
    logger.info("Scan complete: %s", json.dumps(result))

    return {
        "statusCode": 200,
        "body": json.dumps(result),
    }


if __name__ == "__main__":
    # Local smoke test: requires valid AWS credentials in the environment.
    print(json.dumps(lambda_handler({}, None), indent=2))
