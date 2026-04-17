# Solution: Drill 01 — Cloud Security Audit

## Task 1: IAM Policy Analysis

**1.
What is wrong with this policy?**

The policy uses wildcard `Action: "*"` and `Resource: "*"`, granting the Lambda function full administrator access to every AWS service and resource in the account.
This violates the principle of least privilege.
If this Lambda function is compromised (e.g., via a code injection), an attacker gains full control of the entire AWS account.

**2.
What should the policy allow?**

The Lambda processes customer orders stored in DynamoDB table `orders-prod`.
It needs at minimum:

* `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:UpdateItem`, `dynamodb:Query` on the specific table ARN
* Possibly `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` for CloudWatch logging

**3.
Corrected least-privilege policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query"
      ],
      "Resource": "arn:aws:dynamodb:eu-west-1:123456789012:table/orders-prod"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:eu-west-1:123456789012:log-group:/aws/lambda/*"
    }
  ]
}
```

---

## Task 2: CloudTrail Log Analysis

**1.
Are these events concerning?**

Yes — extremely concerning.
All three events occur within 3 minutes, at 03:22 UTC (off-hours), originating from the same user `alice` via a raw `curl` user-agent (not AWS console or normal SDK).

**2.
Likely attack scenario:**

This is a classic **account takeover and cover-tracks-then-exfiltrate** pattern:

1. **Event A**: Attacker (using alice's compromised credentials) creates a new access key for `alice` — establishing persistent programmatic access (even if alice's password is reset, the key still works)
1. **Event B**: Attacker deletes the CloudTrail trail — eliminating future logging (blinding the SOC)
1. **Event C**: Attacker downloads the customer database — exfiltrating high-value data while unmonitored

The source IP `185.220.101.42` is in a known Tor exit node range — characteristic of sophisticated attackers avoiding attribution.

**3.
Immediate actions:**

1. **Disable alice's access keys immediately** — both old and new
1. **Disable alice's console password** until investigation completes
1. **Re-enable CloudTrail** — the trail was deleted; re-create it immediately
1. **Preserve available logs** — CloudTrail logs up to Event B are still in S3; do not delete
1. **Notify the incident response team** — this is a confirmed account takeover + data exfiltration
1. **Assess the exfiltrated file** — `customers_all_2024.csv` likely contains PII → GDPR 72h notification obligation may apply
1. **Check for other activity** — what else did `alice` do between 03:22 and now?

**4.
Detection rule for Event B:**

```text
ALERT: CloudTrail Logging Disabled
SOURCE: cloudtrail.amazonaws.com
EVENTS: DeleteTrail OR StopLogging
SEVERITY: CRITICAL
ACTION: Page on-call immediately
```

This is one of the most critical cloud alerts.
Any deletion of CloudTrail is an attacker trying to blind monitoring.

---

## Task 3: S3 Bucket Audit

**1.
Risky buckets:**

* `company-website-static` — public-read ACL with Block Public Access OFF. Acceptable if it truly hosts only public website assets. **Risk**: if someone accidentally uploads sensitive files, they are publicly accessible.
* `dev-team-experiments` — **CRITICAL RISK**: public-read-write means anyone on the internet can upload to or download from this bucket. This can lead to data exfiltration, malware hosting (using the company's reputation), and cost exploitation.

**2. `dev-team-experiments` specific risk:**

Public write access means anyone can:

* Upload malware and use the URL to distribute it (your company's URL, your reputational damage)
* Upload cryptominer scripts and link them from other websites
* Incur massive S3 storage and transfer costs for your company
* Use it as a data drop for other attacks

**3.
Remediation:**

* `dev-team-experiments`: Immediately enable Block All Public Access, remove public-read-write ACL. Consider deleting the bucket if it is no longer needed.
* `company-website-static`: Enable object-level logging to detect if sensitive files are accidentally uploaded. Review ACL — if only certain paths should be public, use a CloudFront distribution in front of a private bucket instead.
* **Account-wide**: Enable S3 Account Public Access Block at the account level, which overrides all bucket-level settings.

---

## Task 4: CloudTrail Coverage Check

**1.
What is missing?**

* **Single region**: CloudTrail only captures API activity in `eu-west-1`. Any API calls made in other regions (e.g., an attacker launching EC2 instances in `us-east-1`) will not be logged.
* **Log file validation disabled**: Without integrity validation, an attacker (or insider) can modify or delete log files in S3 without detection.
* **No multi-region trail**: Must be enabled to capture global service events (IAM, STS, CloudFront) which are always logged to `us-east-1`.

**2.
Attacker operating in `us-east-1`:**

By operating in an unmonitored region, an attacker can:

* Create IAM users, access keys, and roles
* Launch EC2 instances for mining or C2
* Create new S3 buckets for data staging
* All without any trace in the CloudTrail log

**3.
Recommended configuration:**

```text
- Multi-region trail: ENABLED
- Include global service events: ENABLED (IAM, STS)
- Log file validation: ENABLED
- CloudTrail log bucket: Block all public access ON, MFA delete enabled
- CloudWatch Logs integration: ENABLED (for real-time alerting)
- S3 data events for sensitive buckets: ENABLED
```

---

## Sample Audit Findings Report

**CRITICAL (Immediate action):**

* C1: IAM Lambda function with AdministratorAccess — replace with least-privilege policy
* C2: CloudTrail only in one region — enable multi-region trail immediately

**HIGH (Within 24 hours):**

* H1: `dev-team-experiments` S3 bucket — public read/write — disable immediately
* H2: Log file validation disabled — enable to ensure log integrity

**MEDIUM (Within 1 week):**

* M1: `company-website-static` — public-read with no CloudFront protection — review and move to CloudFront + private bucket
* M2: CloudTrail missing S3 data events for `customer-data-prod` — enable to detect exfiltration
