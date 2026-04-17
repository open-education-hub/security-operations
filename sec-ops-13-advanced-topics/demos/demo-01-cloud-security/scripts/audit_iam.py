#!/usr/bin/env python3
"""
IAM Over-Privilege Audit Script
Checks for overly permissive IAM policies in the mock cloud environment.
"""
import boto3
import json

ENDPOINT = "http://localstack:4566"

session = boto3.Session(
    aws_access_key_id="test",
    aws_secret_access_key="test",
    region_name="eu-west-1"
)
iam = session.client("iam", endpoint_url=ENDPOINT)

HIGH_RISK_POLICIES = [
    "AdministratorAccess",
    "PowerUserAccess",
]
MEDIUM_RISK_POLICIES = [
    "AmazonS3FullAccess",
    "AmazonEC2FullAccess",
    "IAMFullAccess",
]

def get_risk(policy_name):
    if any(p in policy_name for p in HIGH_RISK_POLICIES):
        return "HIGH"
    if any(p in policy_name for p in MEDIUM_RISK_POLICIES):
        return "MEDIUM"
    return "LOW"

print("=" * 60)
print("IAM Over-Privilege Audit")
print("=" * 60)

users = iam.list_users()["Users"]
for user in users:
    username = user["UserName"]
    try:
        policies = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
    except Exception:
        policies = []

    risks = [get_risk(p["PolicyName"]) for p in policies]
    overall = "HIGH" if "HIGH" in risks else ("MEDIUM" if "MEDIUM" in risks else "LOW")

    print(f"\nUser: {username}")
    print(f"  Overall Risk: {overall}")
    for p in policies:
        print(f"  - Policy: {p['PolicyName']}  [Risk: {get_risk(p['PolicyName'])}]")

    if overall == "HIGH":
        print("  [!] REMEDIATION: Replace AdministratorAccess with a least-privilege custom policy")
    elif overall == "MEDIUM":
        print("  [!] REMEDIATION: Scope down to specific resources (e.g. specific S3 bucket ARN)")

print("\n" + "=" * 60)
print("Audit complete.")
