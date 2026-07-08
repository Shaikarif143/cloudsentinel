"""S3 bucket security checks."""
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


def _list_buckets(s3):
    return s3.list_buckets().get("Buckets", [])


def check_public_buckets(s3):
    """Flag buckets that are publicly accessible (via ACL, policy, or missing block-public-access)."""
    findings = []
    for bucket in _list_buckets(s3):
        name = bucket["Name"]
        is_public = False
        reason = ""

        try:
            status = s3.get_bucket_policy_status(Bucket=name)
            if status["PolicyStatus"]["IsPublic"]:
                is_public = True
                reason = "bucket policy grants public access"
        except s3.exceptions.ClientError:
            pass  # no policy, or access denied — check ACL/block config next

        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all([
                pab.get("BlockPublicAcls"),
                pab.get("BlockPublicPolicy"),
                pab.get("IgnorePublicAcls"),
                pab.get("RestrictPublicBuckets"),
            ]):
                is_public = is_public or False
                if not reason:
                    reason = "public access block is not fully enabled"
        except s3.exceptions.ClientError:
            is_public = True
            reason = "no public access block configuration found"

        if is_public:
            findings.append(_finding(
                "S3-001", "CRITICAL", "S3_BUCKET", name,
                f"Bucket '{name}' may be publicly accessible: {reason}.",
                remediation="Enable S3 Block Public Access at the bucket (or account) level.",
            ))
    return findings


def check_unencrypted_buckets(s3):
    """Flag buckets without default server-side encryption configured."""
    findings = []
    for bucket in _list_buckets(s3):
        name = bucket["Name"]
        try:
            s3.get_bucket_encryption(Bucket=name)
        except s3.exceptions.ClientError:
            findings.append(_finding(
                "S3-002", "HIGH", "S3_BUCKET", name,
                f"Bucket '{name}' has no default server-side encryption configured.",
                remediation="Enable SSE-S3 (AES256) or SSE-KMS by default on this bucket.",
            ))
    return findings


def check_versioning_disabled(s3):
    """Flag buckets without versioning enabled (data-loss / ransomware protection risk)."""
    findings = []
    for bucket in _list_buckets(s3):
        name = bucket["Name"]
        versioning = s3.get_bucket_versioning(Bucket=name)
        if versioning.get("Status") != "Enabled":
            findings.append(_finding(
                "S3-003", "MEDIUM", "S3_BUCKET", name,
                f"Bucket '{name}' does not have versioning enabled.",
                remediation="Enable versioning to protect against accidental deletion/overwrite.",
            ))
    return findings


def run_all(s3):
    findings = []
    findings += check_public_buckets(s3)
    findings += check_unencrypted_buckets(s3)
    findings += check_versioning_disabled(s3)
    return findings
