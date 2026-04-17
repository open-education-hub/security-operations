# Demo 01: Cloud Security Misconfiguration Detection

**Estimated time:** 30 minutes

---

## Overview

Simulate a cloud environment using Docker containers to demonstrate common cloud security misconfigurations.
A mock "cloud API" service exposes AWS-style endpoints.
Using `awscli` and Python scripts, you will discover over-permissive IAM roles, publicly accessible storage, and missing audit logging.

---

## Learning Objectives

* Identify common cloud misconfigurations using CLI tools
* Understand the shared responsibility model by examining what is and is not configured
* Run IAM permission audits against a mock cloud environment
* Detect publicly accessible storage buckets

---

## Prerequisites

* Docker installed and running

---

## Setup

```console
cd demos/demo-01-cloud-security
docker compose up --build -d
# Wait ~10 seconds for services to start
docker compose exec audit-tools bash
```

Services started:

* **localstack** — mock AWS environment (IAM, S3, CloudTrail)
* **audit-tools** — container with `awscli` and Python audit scripts

---

## Step 1: Discover IAM Users and Their Policies

```console
aws --endpoint-url=http://localstack:4566 iam list-users
```

Then check the policies attached to the `service-account` user:

```console
aws --endpoint-url=http://localstack:4566 iam list-attached-user-policies \
  --user-name service-account
```

**What to look for:** Any user or role attached to `AdministratorAccess` or wildcard policies (`*:*`).
The `service-account` user has full admin access — a major violation of least privilege.

---

## Step 2: Check S3 Bucket ACLs for Public Access

```console
aws --endpoint-url=http://localstack:4566 s3api list-buckets
aws --endpoint-url=http://localstack:4566 s3api get-bucket-acl \
  --bucket company-data-backup
```

**What to look for:** Any grant to `AllUsers` (public read) or `AuthenticatedUsers`.
The `company-data-backup` bucket has a public-read ACL — simulating one of the most common cloud breach patterns.

---

## Step 3: Verify CloudTrail Logging Status

```console
python3 /scripts/audit_cloudtrail.py
```

The script checks whether CloudTrail is enabled across all regions.
In the demo environment, CloudTrail is disabled in two regions.

**Key insight:** Without CloudTrail, API calls are not logged.
An attacker can operate undetected — exfiltrating data, creating backdoor accounts, changing policies — and you would have no record of it.

---

## Step 4: Run the Full IAM Risk Audit

```console
python3 /scripts/audit_iam.py
```

Expected output:

```text
=== IAM Risk Assessment ===
service-account   [HIGH RISK]   AdministratorAccess — full admin on all services
dev-user          [MEDIUM RISK] S3FullAccess + EC2FullAccess — overly broad
readonly-user     [LOW RISK]    ReadOnlyAccess — acceptable
```

---

## Step 5: Remediation Discussion

For each finding, remediation follows least-privilege:

**service-account:** Replace `AdministratorAccess` with a custom policy granting only the specific `s3:GetObject` and `s3:PutObject` actions on the specific bucket it needs.

**Public S3 bucket:** Enable account-level S3 Block Public Access:

```console
aws --endpoint-url=http://localstack:4566 s3control put-public-access-block \
  --account-id 123456789012 \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

**CloudTrail:** Enable in all regions and configure an S3 bucket with MFA delete and SNS alerts on trail changes.

---

## Discussion Points

1. **Cloud misconfigurations are the leading cause of cloud breaches**: The shared responsibility model places IAM, storage ACLs, and logging configuration entirely under customer control.

1. **Least privilege is harder in cloud**: The richness of cloud IAM makes it tempting to grant broad policies "for convenience." Every overly broad policy is a privilege escalation path.

1. **Logging must be protected**: An attacker who gains admin access will often try to disable CloudTrail first. Protecting the trail (S3 Object Lock, SNS alerts on modifications) is critical.

---

## Clean Up

```console
docker compose down
```
