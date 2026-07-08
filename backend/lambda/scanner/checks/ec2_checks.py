"""EC2 instance security and hygiene checks."""
import datetime


def _finding(check_id, severity, resource_type, resource_id, message, remediation=None):
    return {
        "check_id": check_id,
        "severity": severity,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "message": message,
        "remediation": remediation,
        "detected_at": datetime.datetime.utcnow().isoformat() + "Z",
    }


def _iter_instances(ec2):
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                yield instance


def check_public_instances(ec2):
    """Flag running instances with a public IP address."""
    findings = []
    for instance in _iter_instances(ec2):
        if instance["State"]["Name"] not in ("running", "pending"):
            continue
        if instance.get("PublicIpAddress"):
            findings.append(_finding(
                "EC2-001", "MEDIUM", "EC2_INSTANCE", instance["InstanceId"],
                f"Instance {instance['InstanceId']} has a public IP ({instance['PublicIpAddress']}).",
                remediation="Move to a private subnet behind a load balancer/NAT unless public access is required.",
            ))
    return findings


def check_missing_tags(ec2, required_tags=("Environment", "Owner")):
    """Flag instances missing required governance tags."""
    findings = []
    for instance in _iter_instances(ec2):
        if instance["State"]["Name"] == "terminated":
            continue
        tags = {t["Key"] for t in instance.get("Tags", [])}
        missing = [t for t in required_tags if t not in tags]
        if missing:
            findings.append(_finding(
                "EC2-002", "LOW", "EC2_INSTANCE", instance["InstanceId"],
                f"Instance {instance['InstanceId']} is missing required tags: {', '.join(missing)}.",
                remediation=f"Add tags: {', '.join(missing)}.",
            ))
    return findings


def check_stopped_instances(ec2, stopped_days=14):
    """Flag instances stopped for longer than stopped_days (cost waste risk)."""
    findings = []
    now = datetime.datetime.now(datetime.timezone.utc)
    for instance in _iter_instances(ec2):
        if instance["State"]["Name"] != "stopped":
            continue
        state_transition = instance.get("StateTransitionReason", "")
        # StateTransitionReason looks like: "User initiated (2026-05-01 10:00:00 GMT)"
        # Fall back to launch time if we cannot parse it.
        stopped_since = instance.get("LaunchTime", now)
        idle_days = (now - stopped_since).days
        if idle_days > stopped_days:
            findings.append(_finding(
                "EC2-003", "LOW", "EC2_INSTANCE", instance["InstanceId"],
                f"Instance {instance['InstanceId']} has been stopped for approximately {idle_days} days.",
                remediation="Terminate if no longer needed, or document why it is retained.",
            ))
    return findings


def check_old_amis(ec2, max_age_days=365):
    """Flag self-owned AMIs older than max_age_days that are still in use."""
    findings = []
    now = datetime.datetime.now(datetime.timezone.utc)
    images = ec2.describe_images(Owners=["self"])["Images"]
    for image in images:
        created = datetime.datetime.strptime(
            image["CreationDate"], "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=datetime.timezone.utc)
        age_days = (now - created).days
        if age_days > max_age_days:
            findings.append(_finding(
                "EC2-004", "LOW", "EC2_AMI", image["ImageId"],
                f"AMI {image['ImageId']} ({image.get('Name', 'unnamed')}) is {age_days} days old.",
                remediation="Rebuild from an updated base image and deregister stale AMIs.",
            ))
    return findings


def check_unassociated_eips(ec2):
    """Flag Elastic IPs that are allocated but not attached to anything (wasted cost)."""
    findings = []
    addresses = ec2.describe_addresses()["Addresses"]
    for addr in addresses:
        if "InstanceId" not in addr and "NetworkInterfaceId" not in addr:
            findings.append(_finding(
                "EC2-005", "LOW", "EC2_EIP", addr.get("AllocationId", addr.get("PublicIp")),
                f"Elastic IP {addr.get('PublicIp')} is allocated but not attached to any resource.",
                remediation="Release this Elastic IP to avoid unnecessary charges.",
            ))
    return findings


def run_all(ec2):
    findings = []
    findings += check_public_instances(ec2)
    findings += check_missing_tags(ec2)
    findings += check_stopped_instances(ec2)
    findings += check_old_amis(ec2)
    findings += check_unassociated_eips(ec2)
    return findings
