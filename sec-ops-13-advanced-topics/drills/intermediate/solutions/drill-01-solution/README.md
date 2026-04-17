# Solution: Drill 01 (Intermediate) — Threat Hunting in a Cloud Environment

## Task 1: Hunt Hypotheses

**Hypothesis A — Lambda Persistence:**
There is evidence of GhostCloud Lambda persistence activity if CloudTrail shows `lambda.amazonaws.com` `CreateFunction` or `UpdateFunctionCode` events with function names matching `aws-update-*`, executed by a non-standard identity (not CI/CD service account) or outside business hours, which would appear in CloudTrail management events as `eventSource: lambda.amazonaws.com`.

**Hypothesis B — IAM Role Lateral Movement:**
There is evidence of GhostCloud lateral movement if `sts.amazonaws.com` AssumeRole events show an unusual principal assuming high-privilege roles (names containing `Admin`, `PowerUser`, or `*Full*`) from a user identity that does not normally perform such assumptions, visible in CloudTrail as `eventName: AssumeRole` with unexpected `requestParameters.roleArn`.

**Hypothesis C — S3 Presigned URL Exfiltration:**
There is evidence of data exfiltration if S3 data events show `GetObject` calls on sensitive buckets (`*-prod`, `*-customer*`, `*-data*`) from unusual source IPs immediately following a programmatic `GeneratePresignedUrl` call, where the volume of data retrieved is abnormally high (> 100 MB in a short window).

---

## Task 2: CloudTrail Query Logic

**Hypothesis A — Lambda Persistence:**

```text
FILTER eventSource = "lambda.amazonaws.com"
  AND eventName IN ("CreateFunction", "UpdateFunctionCode", "UpdateFunctionConfiguration")
  AND requestParameters.functionName LIKE "aws-update-%"
ORDER BY eventTime DESC

ALSO ALERT IF:
  userIdentity.userName NOT IN (known-ci-cd-service-accounts)
  OR hourOfDay(eventTime) < 8 OR hourOfDay(eventTime) > 20
```

**Hypothesis B — IAM Role Lateral Movement:**

```text
FILTER eventSource = "sts.amazonaws.com"
  AND eventName = "AssumeRole"
  AND requestParameters.roleArn MATCHES ".*Admin.*|.*PowerUser.*|.*FullAccess.*"
ORDER BY eventTime DESC

LOOK FOR:
  - Multiple AssumeRole calls in short time window from same principal
  - Roles in different accounts (cross-account lateral movement)
  - Source principal is a newly created user (< 30 days old)
```

**Hypothesis C — S3 Presigned URL:**

```text
FILTER eventSource = "s3.amazonaws.com"
  AND eventName = "GetObject"
  AND requestParameters.bucketName IN (sensitive-bucket-list)
  AND (
    sourceIPAddress NOT IN (known-corporate-IPs)
    OR userAgent LIKE "%custom-exfil%"
  )
ORDER BY eventTime DESC

CORRELATE with:
  Total bytes downloaded per sourceIPAddress per hour > 50MB
```

---

## Task 3: Additional Log Sources

**1.
Is Lambda execution logged in CloudTrail?**

Partially.
Lambda management events (create, update, delete) are logged.
Lambda *invocation* events (each time the function runs) are **not** logged in CloudTrail by default.
CloudTrail logs management operations, not data plane operations.

**2.
What provides Lambda invocation visibility?**

Amazon CloudWatch Logs — each Lambda function writes its output to a CloudWatch Log Group (`/aws/lambda/<function-name>`).
You need to subscribe to these logs and ship them to your SIEM.

**3.
Seeing code changes to Lambda:**

Enable **AWS CloudTrail data events for Lambda** (`eventName: Invoke`) and use **AWS Config** to track configuration changes.
For code content changes, `UpdateFunctionCode` in CloudTrail shows *that* code changed but not *what* changed.
You need to pull the function code via `GetFunction` API after detecting an update event, and diff it against a known-good baseline.

**4.
Detecting unexpected outbound HTTP from Lambda:**

* Enable **VPC Flow Logs** on the VPC where the Lambda runs (if it runs in a VPC)
* Enable **AWS Network Firewall** or outbound proxy to log and alert on unexpected domains
* Use **Lambda Insights** (CloudWatch) to monitor network I/O anomalies

---

## Task 4: Simulated Hunt Results Analysis

**Suspicious findings requiring investigation:**

1. **Lambda functions `aws-update-certs` and `aws-update-config`**: These match the known GhostCloud function naming pattern (`aws-update-*`). They must be investigated immediately.
   * Who created them? (`userIdentity` in the CloudTrail event)
   * When? What was the code? Download and analyse.
   * Are they currently active? What trigger do they have?
   * Check CloudWatch logs for their execution history

1. **IAM user `svc-config-mgr` created 4 days ago**: Matches GhostCloud known IOC exactly. Must be investigated.
   * Who created this user? (`userIdentity` in the IAM CreateUser event)
   * What policies are attached?
   * What actions has this user performed since creation?

**Are findings conclusive?**

No — they are **strong indicators but not conclusive** until corroborated.
The Lambda function names match the pattern, but it is possible (though unlikely) that a legitimate admin created functions with these names.
The IAM user name matches exactly, which is more suspicious.
Neither is conclusive without examining the actual code, the creator identity, and subsequent activity.

**Next steps for Lambda functions:**

1. Retrieve function code: `aws lambda get-function --function-name aws-update-certs`
1. Analyse for malicious payload: check for hardcoded IPs (192.0.2.88), unusual imports, HTTP calls
1. Check execution history in CloudWatch Logs
1. Identify the creator from CloudTrail: `eventName=CreateFunction, requestParameters.functionName=aws-update-certs`

**Next steps for `svc-config-mgr`:**

1. List all IAM activity by this user since creation: `eventName=* AND userIdentity.userName=svc-config-mgr`
1. List policies: `aws iam list-attached-user-policies --user-name svc-config-mgr`
1. Check who created it: `eventName=CreateUser AND requestParameters.userName=svc-config-mgr`
1. Temporarily disable the user's access keys while investigating

---

## Task 5: Sample Hunt Report

```text
THREAT HUNT REPORT
==================
Hunt ID:         HUNT-2024-07
Date:            2024-03-15
Analyst:         [name]
Duration:        4 hours

Trigger:
  ISAC threat intelligence sharing: GhostCloud campaign targeting financial cloud
  environments. IOC: Lambda function name pattern aws-update-*, IAM user svc-config-mgr.

Hypothesis:
  If GhostCloud has compromised this environment, CloudTrail will show Lambda
  functions with aws-update-* names created by non-standard identities, and/or
  IAM user svc-config-mgr created recently.

Data Sources Used:
  - CloudTrail management events (all regions, 30-day window)
  - IAM user and policy listing
  - CloudWatch Logs for Lambda functions

Queries Executed:
  - Lambda CreateFunction/UpdateFunctionCode where name LIKE 'aws-update-%'
  - STS AssumeRole for high-privilege roles
  - S3 GetObject > 50MB from non-corporate IPs
  - IAM CreateUser where username = 'svc-config-mgr'

Findings:
  - SUSPICIOUS: Lambda functions aws-update-certs and aws-update-config exist
    (match GhostCloud IOC pattern). Created 1-3 days ago. Code not yet analysed.
  - SUSPICIOUS: IAM user svc-config-mgr created 4 days ago. Matches exact IOC.
  - BENIGN: AssumeRole findings all attributed to known CI/CD pipeline (verified).
  - NEGATIVE: No S3 exfiltration patterns detected.

Conclusion:
  [X] Possible indicator — requires further investigation and escalation
      Two strong IOC matches found. Cannot confirm compromise without code analysis.

Recommended Actions:

  1. Analyse Lambda function code for aws-update-certs and aws-update-config

  2. Disable svc-config-mgr access keys pending investigation
  3. Escalate to incident response if Lambda code confirms malicious payload
  4. Check Lambda execution logs in CloudWatch for past invocations
  5. Share findings with ISAC peer who provided original intel

Detection Rule Improvements:

  1. Alert on ANY Lambda CreateFunction where name matches aws-update-* (already present

     in threat intel — should have been an automated alert, not a manual hunt)
  2. Alert on IAM CreateUser where username matches known IOC list
  3. Implement automatic IOC-to-SIEM-rule pipeline to avoid manual hunting for known IOCs
```
