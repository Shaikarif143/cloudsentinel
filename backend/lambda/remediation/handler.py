"""
CloudSentinel Auto-Remediation Lambda.

Invoked asynchronously by the scanner Lambda with a payload of
auto-fixable findings:

    {"findings": [{"check_id": "S3-001", "resource_id": "my-bucket", ...}, ...]}

Each check_id maps to a specific, narrow remediation action. Anything
not in REMEDIATION_ACTIONS is only reported, never touched — auto-fix
is opt-in per check, not a blanket "do whatever" action.
"""
import json
import os
import logging
import datetime

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE", "cloudsentinel-dev-findings")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")


def remediate_public_s3_bucket(finding):
    """S3-001: bucket may be publicly accessible -> enable full Block Public Access."""
    s3 = boto3.client("s3")
    bucket = finding["resource_id"]
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return f"Enabled S3 Block Public Access on bucket '{bucket}'."


def remediate_unused_security_group(finding):
    """SG-005: security group unused -> delete it."""
    ec2 = boto3.client("ec2")
    sg_id = finding["resource_id"]
    ec2.delete_security_group(GroupId=sg_id)
    return f"Deleted unused security group '{sg_id}'."


REMEDIATION_ACTIONS = {
    "S3-001": remediate_public_s3_bucket,
    "SG-005": remediate_unused_security_group,
}


def mark_remediated(finding, outcome_message):
    table = dynamodb.Table(FINDINGS_TABLE)
    try:
        table.update_item(
            Key={
                "finding_id": finding["finding_id"],
                "scan_timestamp": finding["scan_timestamp"],
            },
            UpdateExpression="SET remediation_status = :status, remediated_at = :ts, "
                              "remediation_outcome = :outcome",
            ExpressionAttributeValues={
                ":status": "REMEDIATED",
                ":ts": datetime.datetime.utcnow().isoformat() + "Z",
                ":outcome": outcome_message,
            },
        )
    except Exception:
        logger.exception("Failed to update finding %s after remediation", finding.get("finding_id"))


def notify(outcomes):
    if not SNS_TOPIC_ARN or not outcomes:
        return
    lines = ["CloudSentinel auto-remediation actions taken:", ""]
    lines.extend(f"  - {o}" for o in outcomes)
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="CloudSentinel: auto-remediation actions taken",
        Message="\n".join(lines),
    )


def lambda_handler(event, context):
    findings = event.get("findings", [])
    outcomes = []

    for finding in findings:
        check_id = finding.get("check_id")
        action = REMEDIATION_ACTIONS.get(check_id)
        if not action:
            logger.info("No remediation action registered for check_id %s, skipping.", check_id)
            continue

        try:
            outcome = action(finding)
            outcomes.append(outcome)
            if "finding_id" in finding and "scan_timestamp" in finding:
                mark_remediated(finding, outcome)
            logger.info(outcome)
        except Exception:
            logger.exception("Remediation failed for finding %s", finding.get("resource_id"))

    notify(outcomes)

    return {
        "statusCode": 200,
        "body": json.dumps({"remediated": len(outcomes), "details": outcomes}),
    }
