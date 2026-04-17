# Demo 01: Cloud Security Misconfiguration Detection

## Overview

In this demo, we simulate a cloud environment using Docker containers to demonstrate common cloud security misconfigurations.
A mock "cloud API" service exposes AWS-style endpoints, and students use `awscli` (configured against the local mock) along with Python scripts to discover over-permissive IAM roles, publicly accessible storage, and missing MFA enforcement.

## Learning Objectives

* Identify common cloud misconfigurations using CLI tools
* Understand the shared responsibility model by examining what is and is not configured
* Run IAM permission audits against a mock cloud environment
* Detect publicly accessible storage buckets and remediate them

## Prerequisites

* Docker installed and running

## Setup

```console
cd demos/demo-01-cloud-security
docker compose up --build -d
```

Wait for services to start (about 10 seconds), then:

```console
docker compose exec audit-tools bash
```

## Files

* `docker-compose.yml` — LocalStack (mock AWS) + audit container
* `Dockerfile` — audit tools container with awscli and Python
* `scripts/audit_iam.py` — IAM policy over-privilege checker
* `scripts/audit_storage.py` — S3 bucket public access checker
* `scripts/audit_cloudtrail.py` — CloudTrail logging status checker

## Walk-through

### Step 1: Discover IAM Users and Policies

From inside the audit container:

```console
aws --endpoint-url=http://localstack:4566 iam list-users
```

Expected output: several users including a `service-account` with `AdministratorAccess`.

```console
aws --endpoint-url=http://localstack:4566 iam list-attached-user-policies \
  --user-name service-account
```

**What to look for:** Any user or role attached to `AdministratorAccess` or `*:*` policies.
The `service-account` user has full admin access — a major misconfiguration.

### Step 2: Check S3 Bucket ACLs

```console
aws --endpoint-url=http://localstack:4566 s3api list-buckets
```

```console
aws --endpoint-url=http://localstack:4566 s3api get-bucket-acl \
  --bucket company-data-backup
```

**What to look for:** Any grant to `AllUsers` (public read) or `AuthenticatedUsers`.
The `company-data-backup` bucket has a public-read ACL — simulating the common "misconfigured S3 bucket" breach.

### Step 3: Verify CloudTrail Logging

```console
python3 /scripts/audit_cloudtrail.py
```

The script checks whether CloudTrail is enabled across all regions.
The demo environment has CloudTrail disabled in two regions.

**Key insight:** Without CloudTrail, API calls are not logged and an attacker can operate undetected.

### Step 4: Run the Full IAM Audit

```console
python3 /scripts/audit_iam.py
```

The script lists all IAM policies, checks for wildcard actions (`*`), and scores each user/role by risk level.

**Expected findings:**

* `service-account`: HIGH RISK — AdministratorAccess
* `dev-user`: MEDIUM RISK — S3FullAccess + EC2FullAccess
* `readonly-user`: LOW RISK — ReadOnlyAccess

### Step 5: Remediation Discussion

For each finding, the remediation follows least-privilege:

* Replace `AdministratorAccess` with a custom policy granting only required permissions
* Enable bucket public access block at the account level
* Enable CloudTrail in all regions and configure SNS alerts on trail changes

## Cleanup

```console
docker compose down
```

## Key Takeaways

* Cloud misconfigurations are the leading cause of cloud security incidents
* IAM over-privilege violates least-privilege and is hard to detect without auditing
* CloudTrail must be enabled and monitored — it is the equivalent of the Security Event Log for cloud
* The shared responsibility model means customers are responsible for all these configurations
