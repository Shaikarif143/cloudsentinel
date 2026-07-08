"""EBS volume security and cost-hygiene checks."""
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


def _iter_volumes(ec2):
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate():
        for volume in page["Volumes"]:
            yield volume


def check_unencrypted_volumes(ec2):
    """Flag EBS volumes that are not encrypted."""
    findings = []
    for volume in _iter_volumes(ec2):
        if not volume.get("Encrypted", False):
            findings.append(_finding(
                "EBS-001", "HIGH", "EBS_VOLUME", volume["VolumeId"],
                f"Volume {volume['VolumeId']} ({volume['Size']} GiB) is not encrypted.",
                remediation="Snapshot the volume, create an encrypted copy, and swap it in.",
            ))
    return findings


def check_unattached_volumes(ec2):
    """Flag EBS volumes not attached to any instance (cost waste)."""
    findings = []
    for volume in _iter_volumes(ec2):
        if volume["State"] == "available":  # available == not attached
            findings.append(_finding(
                "EBS-002", "LOW", "EBS_VOLUME", volume["VolumeId"],
                f"Volume {volume['VolumeId']} ({volume['Size']} GiB) is unattached.",
                remediation="Snapshot and delete if no longer needed.",
            ))
    return findings


def run_all(ec2):
    findings = []
    findings += check_unencrypted_volumes(ec2)
    findings += check_unattached_volumes(ec2)
    return findings
