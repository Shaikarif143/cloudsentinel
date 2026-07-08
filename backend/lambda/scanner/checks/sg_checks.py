"""Security group ingress rule checks."""
import datetime

OPEN_CIDRS = ("0.0.0.0/0", "::/0")

RISKY_PORTS = {
    22: ("SSH", "CRITICAL"),
    3389: ("RDP", "CRITICAL"),
    3306: ("MySQL", "HIGH"),
    5432: ("PostgreSQL", "HIGH"),
    27017: ("MongoDB", "HIGH"),
    6379: ("Redis", "HIGH"),
    9200: ("Elasticsearch", "HIGH"),
}


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


def _is_open_to_world(ip_permission):
    for ip_range in ip_permission.get("IpRanges", []):
        if ip_range.get("CidrIp") in OPEN_CIDRS:
            return True
    for ip_range in ip_permission.get("Ipv6Ranges", []):
        if ip_range.get("CidrIpv6") in OPEN_CIDRS:
            return True
    return False


def check_open_ports(ec2):
    """Flag security groups that expose well-known risky ports to the world."""
    findings = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            for perm in sg.get("IpPermissions", []):
                if not _is_open_to_world(perm):
                    continue

                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")

                # All traffic (no protocol restriction) is its own critical finding
                if perm.get("IpProtocol") == "-1":
                    findings.append(_finding(
                        "SG-003", "CRITICAL", "SECURITY_GROUP", sg["GroupId"],
                        f"Security group {sg['GroupId']} ({sg['GroupName']}) allows ALL traffic from 0.0.0.0/0.",
                        remediation="Restrict to specific ports/protocols and known source ranges.",
                    ))
                    continue

                if from_port is None:
                    continue

                for port, (name, severity) in RISKY_PORTS.items():
                    if from_port <= port <= (to_port or from_port):
                        check_id = "SG-001" if port == 22 else ("SG-002" if port == 3389 else "SG-004")
                        findings.append(_finding(
                            check_id, severity, "SECURITY_GROUP", sg["GroupId"],
                            f"Security group {sg['GroupId']} ({sg['GroupName']}) exposes {name} "
                            f"(port {port}) to the world (0.0.0.0/0).",
                            remediation=f"Restrict port {port} to specific known IP ranges or a bastion/VPN.",
                        ))
    return findings


def check_unused_security_groups(ec2):
    """Flag security groups not attached to any ENI (candidates for cleanup)."""
    findings = []
    all_sgs = {
        sg["GroupId"]: sg
        for page in ec2.get_paginator("describe_security_groups").paginate()
        for sg in page["SecurityGroups"]
    }

    used_sg_ids = set()
    for page in ec2.get_paginator("describe_network_interfaces").paginate():
        for eni in page["NetworkInterfaces"]:
            for group in eni.get("Groups", []):
                used_sg_ids.add(group["GroupId"])

    for sg_id, sg in all_sgs.items():
        if sg["GroupName"] == "default":
            continue  # default SGs are expected to exist even if unused
        if sg_id not in used_sg_ids:
            findings.append(_finding(
                "SG-005", "LOW", "SECURITY_GROUP", sg_id,
                f"Security group {sg_id} ({sg['GroupName']}) is not attached to any network interface.",
                remediation="Delete this security group if it is confirmed unused.",
            ))
    return findings


def run_all(ec2):
    findings = []
    findings += check_open_ports(ec2)
    findings += check_unused_security_groups(ec2)
    return findings
