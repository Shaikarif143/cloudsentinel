import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda", "scanner"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "compliance"))

from compliance_engine import score_findings, top_risks  # noqa: E402


def make_finding(severity, resource_type, check_id="X-1"):
    return {
        "check_id": check_id,
        "severity": severity,
        "resource_type": resource_type,
        "resource_id": "res-1",
        "message": "test finding",
    }


def test_no_findings_gives_perfect_score():
    result = score_findings([])
    assert result["overall_score"] == 100
    assert all(v == 100 for v in result["categories"].values())
    assert result["total_findings"] == 0


def test_critical_iam_finding_lowers_iam_and_overall():
    findings = [make_finding("CRITICAL", "IAM_USER")]
    result = score_findings(findings)
    assert result["categories"]["IAM"] == 75  # 100 - 25
    assert result["overall_score"] < 100
    assert result["severity_counts"]["CRITICAL"] == 1


def test_score_never_goes_below_zero():
    findings = [make_finding("CRITICAL", "IAM_USER") for _ in range(10)]
    result = score_findings(findings)
    assert result["categories"]["IAM"] == 0
    assert result["overall_score"] >= 0


def test_top_risks_orders_by_severity():
    findings = [
        make_finding("LOW", "EBS_VOLUME"),
        make_finding("CRITICAL", "S3_BUCKET"),
        make_finding("MEDIUM", "EC2_INSTANCE"),
    ]
    ranked = top_risks(findings, limit=2)
    assert ranked[0]["severity"] == "CRITICAL"
    assert len(ranked) == 2


def test_unmapped_resource_type_does_not_crash():
    findings = [make_finding("HIGH", "UNKNOWN_TYPE")]
    result = score_findings(findings)
    assert result["total_findings"] == 1
    assert result["severity_counts"]["HIGH"] == 1
