"""
Compliance scoring engine.

Turns a flat list of findings (as produced by the scanner checks) into
category scores and an overall weighted score, matching the format used
in the CloudSentinel dashboard and PDF reports:

    Overall Score   91%
    IAM             96%
    S3              88%
    Networking      90%
    Encryption      100%
    Monitoring      85%
"""

# Severity penalty weights: how many points a single finding of this
# severity subtracts from that category's score (floored at 0).
SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 12,
    "MEDIUM": 6,
    "LOW": 2,
}

# Maps a finding's resource_type prefix to the dashboard category it counts against.
RESOURCE_TYPE_TO_CATEGORY = {
    "IAM_USER": "IAM",
    "IAM_ACCESS_KEY": "IAM",
    "IAM_ROLE": "IAM",
    "IAM_PASSWORD_POLICY": "IAM",
    "S3_BUCKET": "S3",
    "SECURITY_GROUP": "Networking",
    "EC2_INSTANCE": "Networking",
    "EC2_EIP": "Networking",
    "EC2_AMI": "Monitoring",
    "EBS_VOLUME": "Encryption",
}

CATEGORIES = ["IAM", "S3", "Networking", "Encryption", "Monitoring"]

# Overall score category weights (must sum to 1.0)
CATEGORY_WEIGHTS = {
    "IAM": 0.30,
    "S3": 0.20,
    "Networking": 0.25,
    "Encryption": 0.15,
    "Monitoring": 0.10,
}


def score_findings(findings):
    """
    Given a list of finding dicts (each with 'resource_type' and 'severity'),
    return a dict of category scores (0-100) plus an overall weighted score
    and a severity breakdown, e.g.:

    {
      "overall_score": 91,
      "categories": {"IAM": 96, "S3": 88, "Networking": 90, "Encryption": 100, "Monitoring": 85},
      "severity_counts": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 8, "LOW": 21},
      "total_findings": 33,
    }
    """
    category_scores = {c: 100 for c in CATEGORIES}
    severity_counts = {s: 0 for s in SEVERITY_WEIGHTS}

    for finding in findings:
        severity = finding.get("severity", "LOW")
        resource_type = finding.get("resource_type", "")
        category = RESOURCE_TYPE_TO_CATEGORY.get(resource_type)

        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if category:
            penalty = SEVERITY_WEIGHTS.get(severity, 2)
            category_scores[category] = max(0, category_scores[category] - penalty)

    overall = sum(
        category_scores[c] * weight for c, weight in CATEGORY_WEIGHTS.items()
    )

    return {
        "overall_score": round(overall),
        "categories": {c: round(v) for c, v in category_scores.items()},
        "severity_counts": severity_counts,
        "total_findings": len(findings),
    }


def top_risks(findings, limit=5):
    """Return the highest-severity findings first, capped at `limit`."""
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    ranked = sorted(findings, key=lambda f: order.get(f.get("severity", "LOW"), 9))
    return ranked[:limit]
