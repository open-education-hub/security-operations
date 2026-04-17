# Drill 01: Threat Hunting in a Cloud Environment

## Difficulty: Intermediate

## Estimated Time: 50 minutes

## Scenario

Your organisation uses AWS as its primary cloud platform.
A peer organisation in your ISAC has shared a STIX bundle (attached below as JSON) describing a campaign by a threat actor called **GhostCloud** that targets cloud-hosted financial systems.
The campaign uses:

* A custom malware implant called `CloudDrifter` that uses AWS Lambda for persistence
* Exfiltration via S3 presigned URLs
* Lateral movement by assuming IAM roles

Your task is to create a threat hunt hypothesis and translate it into CloudTrail-based hunt queries.

## Objectives

1. Extract relevant IOCs and TTPs from the provided threat intel
1. Write a threat hunt hypothesis
1. Translate TTPs into CloudTrail query logic
1. Identify what additional log sources are needed
1. Document findings in a hunt report template

---

## Threat Intel: GhostCloud Campaign

**Relevant TTPs (ATT&CK):**

| Technique | ID | Description |
|-----------|-----|-------------|
| Cloud Account Discovery | T1087.004 | Lists IAM users, roles, groups |
| Impersonate / Assume Role | T1134.001 | `sts:AssumeRole` to lateral move |
| Lambda Persistence | T1546 | Creates or modifies Lambda functions |
| Exfil via S3 presigned URL | T1567.002 | Generates presigned URL, exfils data |
| Disable Logging | T1562.008 | Deletes or stops CloudTrail |

**Known IOCs:**

* C2 IP: `192.0.2.88` (HTTPS/443)
* Malicious Lambda function name pattern: `aws-update-*`
* User-agent string: `boto3/1.26.0 aws-cli/2.9.0 Python/3.9.0 custom-exfil`
* Unusual IAM username created: `svc-config-mgr` or `svc-lambda-runner`

---

## Task 1: Hunt Hypothesis

A well-formed hypothesis states:

```text
There is evidence of [threat actor/behaviour] using [technique]
because [initial indicator], which would be visible in [log source] as [observable].
```

Write a threat hunt hypothesis for:
a) Lambda persistence
b) IAM role lateral movement
c) Data exfiltration via S3 presigned URL

---

## Task 2: CloudTrail Query Logic

For each hypothesis, write the CloudTrail query logic.
Use the following pseudo-query format:

```text
FILTER eventSource = "X"
  AND eventName = "Y"
  AND requestParameters.* CONTAINS "Z"
  AND (additional conditions)
ORDER BY eventTime DESC
```

**Hypothesis A — Lambda persistence:**
Hint: Look for `lambda.amazonaws.com` events creating or updating functions with names matching `aws-update-*`, especially from unusual user identities or outside business hours.

**Hypothesis B — IAM role lateral movement:**
Hint: Look for `sts.amazonaws.com` AssumeRole calls that chain across multiple accounts or to sensitive roles (e.g., roles named `Admin*`, `*PowerUser*`).

**Hypothesis C — S3 presigned URL exfiltration:**
Hint: Presigned URL generation creates a `GeneratePresignedUrl` event (if logged).
Large GetObject events from unusual IPs shortly after are the exfiltration itself.

---

## Task 3: Additional Log Sources

The threat actor's Lambda persistence technique injects a payload into a Lambda function.
Identify:

1. Is Lambda execution logged in CloudTrail? (Yes/No, and why/why not)
1. What AWS service provides visibility into Lambda function invocations?
1. What would you enable to see the actual code changes to a Lambda function?
1. How would you detect if a Lambda function makes unexpected outbound HTTP calls?

---

## Task 4: Simulated Hunt Results

You run your queries and find the following:

| Query | Result |
|-------|--------|
| Lambda create/update with `aws-update-*` name | 2 hits: `aws-update-certs` (3 days ago) and `aws-update-config` (1 day ago) |
| AssumeRole chains | 5 AssumeRole events, all from a `ci-cd-pipeline` role to `deployment-role` (normal CI/CD) |
| Presigned URL generation | No hits |
| IAM user creation | 1 hit: `svc-config-mgr` created 4 days ago |

**Questions:**

1. Which findings are suspicious and require investigation?
1. Are any findings conclusive evidence of compromise, or just indicators? Explain.
1. What is your next investigation step for the suspicious Lambda functions?
1. What is your next step for `svc-config-mgr`?

---

## Task 5: Hunt Report

Complete the following hunt report template:

```text
THREAT HUNT REPORT
==================
Hunt ID:         HUNT-2024-XX
Date:            [date]
Analyst:         [name]
Duration:        [hours]

Trigger:
  [What initiated this hunt?]

Hypothesis:
  [Your hypothesis statement]

Data Sources Used:
  - [List log sources queried]

Queries Executed:
  - [Summary of queries]

Findings:
  - [Finding 1: suspicious/benign/inconclusive]
  - [Finding 2: ...]

Conclusion:
  [ ] No evidence of compromise
  [ ] Possible indicator — requires further investigation
  [ ] Confirmed compromise — escalate to incident response

Recommended Actions:
  [List]

Detection Rule Improvements:
  [What new rules should be created based on this hunt?]
```
