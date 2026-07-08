"""
IAM security checks.

Each check function takes a boto3 iam client and yields Finding dicts.
Findings are plain dicts so they can be dropped straight into DynamoDB /
JSON without extra serialization work.
"""
import datetime


def _finding(check_id, severity, resource_type, resource_id, message, remediation=None):
    return {
        "check_id": check_id,
        "severity": severity,          # CRITICAL | HIGH | MEDIUM | LOW
        "resource_type": resource_type,
        "resource_id": resource_id,
        "message": message,
        "remediation": remediation,
        "detected_at": datetime.datetime.utcnow().isoformat() + "Z",
    }


def check_users_without_mfa(iam):
    """Flag IAM users that have console access but no MFA device attached."""
    findings = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]

            # Only care about users who can actually log in to the console
            try:
                iam.get_login_profile(UserName=username)
            except iam.exceptions.NoSuchEntityException:
                continue  # no console access, MFA is moot

            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            if not mfa_devices:
                findings.append(_finding(
                    "IAM-001", "HIGH", "IAM_USER", username,
                    f"User '{username}' has console access but no MFA device enabled.",
                    remediation="Enable a virtual or hardware MFA device for this user.",
                ))
    return findings


def check_old_access_keys(iam, max_age_days=90):
    """Flag access keys older than max_age_days that are still Active."""
    findings = []
    paginator = iam.get_paginator("list_users")
    now = datetime.datetime.now(datetime.timezone.utc)

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            for key in keys:
                if key["Status"] != "Active":
                    continue
                age_days = (now - key["CreateDate"]).days
                if age_days > max_age_days:
                    findings.append(_finding(
                        "IAM-002", "MEDIUM", "IAM_ACCESS_KEY", key["AccessKeyId"],
                        f"Access key for '{username}' is {age_days} days old (limit {max_age_days}).",
                        remediation="Rotate this access key and update dependent applications.",
                    ))
    return findings


def check_admin_access_attached(iam):
    """Flag users/roles with the AWS-managed AdministratorAccess policy attached directly."""
    findings = []
    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"

    paginator = iam.get_paginator("list_entities_for_policy")
    entities = paginator.paginate(PolicyArn=admin_arn)
    for page in entities:
        for user in page.get("PolicyUsers", []):
            findings.append(_finding(
                "IAM-003", "CRITICAL", "IAM_USER", user["UserName"],
                f"User '{user['UserName']}' has AdministratorAccess attached directly.",
                remediation="Replace with least-privilege policies or move admin access to a role assumed via SSO.",
            ))
        for role in page.get("PolicyRoles", []):
            findings.append(_finding(
                "IAM-003", "CRITICAL", "IAM_ROLE", role["RoleName"],
                f"Role '{role['RoleName']}' has AdministratorAccess attached directly.",
                remediation="Scope this role down to only the permissions it needs.",
            ))
    return findings


def check_unused_users(iam, unused_days=60):
    """Flag users who haven't used their password or access keys in unused_days."""
    findings = []
    now = datetime.datetime.now(datetime.timezone.utc)
    paginator = iam.get_paginator("list_users")

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            last_used_dates = []

            pwd_last_used = user.get("PasswordLastUsed")
            if pwd_last_used:
                last_used_dates.append(pwd_last_used)

            for key in iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
                key_last_used = iam.get_access_key_last_used(
                    AccessKeyId=key["AccessKeyId"]
                )["AccessKeyLastUsed"].get("LastUsedDate")
                if key_last_used:
                    last_used_dates.append(key_last_used)

            if not last_used_dates:
                # Never used at all — flag using account creation date as reference
                age = (now - user["CreateDate"]).days
                if age > unused_days:
                    findings.append(_finding(
                        "IAM-004", "LOW", "IAM_USER", username,
                        f"User '{username}' has never authenticated ({age} days since creation).",
                        remediation="Confirm this user is still needed; deactivate or delete if not.",
                    ))
                continue

            most_recent = max(last_used_dates)
            idle_days = (now - most_recent).days
            if idle_days > unused_days:
                findings.append(_finding(
                    "IAM-004", "LOW", "IAM_USER", username,
                    f"User '{username}' has been inactive for {idle_days} days.",
                    remediation="Confirm this user is still needed; deactivate or delete if not.",
                ))
    return findings


def check_password_policy(iam, min_length=14, max_age_days=90):
    """Flag a missing or weak account password policy."""
    findings = []
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        findings.append(_finding(
            "IAM-005", "HIGH", "IAM_PASSWORD_POLICY", "account",
            "No IAM account password policy is configured.",
            remediation="Set a password policy with minimum length, complexity, reuse and expiry rules.",
        ))
        return findings

    if policy.get("MinimumPasswordLength", 0) < min_length:
        findings.append(_finding(
            "IAM-005a", "MEDIUM", "IAM_PASSWORD_POLICY", "account",
            f"Minimum password length is {policy.get('MinimumPasswordLength', 0)}, expected >= {min_length}.",
            remediation=f"Increase minimum password length to at least {min_length}.",
        ))

    if not policy.get("ExpirePasswords") or policy.get("MaxPasswordAge", 9999) > max_age_days:
        findings.append(_finding(
            "IAM-005b", "MEDIUM", "IAM_PASSWORD_POLICY", "account",
            "Password expiry is not enforced within the expected window.",
            remediation=f"Require password rotation at least every {max_age_days} days.",
        ))

    if policy.get("PasswordReusePrevention", 0) < 5:
        findings.append(_finding(
            "IAM-005c", "LOW", "IAM_PASSWORD_POLICY", "account",
            "Password reuse prevention is not set to a strong value.",
            remediation="Prevent reuse of at least the last 5 passwords.",
        ))

    if not policy.get("RequireUppercaseCharacters") or not policy.get("RequireNumbers") \
            or not policy.get("RequireSymbols") or not policy.get("RequireLowercaseCharacters"):
        findings.append(_finding(
            "IAM-005d", "LOW", "IAM_PASSWORD_POLICY", "account",
            "Password complexity requirements are incomplete.",
            remediation="Require upper, lower, numeric, and symbol characters.",
        ))

    return findings


def run_all(iam):
    """Run every IAM check and return a flat list of findings."""
    findings = []
    findings += check_users_without_mfa(iam)
    findings += check_old_access_keys(iam)
    findings += check_admin_access_attached(iam)
    findings += check_unused_users(iam)
    findings += check_password_policy(iam)
    return findings
