# Drill: Cloud Log Analysis

**Level:** Basic

**Estimated time:** 45–60 minutes

**Session:** 13 — Advanced Topics in Security Operations

---

## Scenario

You are a cloud security analyst at **NovaTech Logistics**.
The company runs its infrastructure on AWS.
Early this morning the security team received an alert from a GuardDuty-equivalent rule about unusual API activity originating from an unknown IP address.

A snapshot of CloudTrail-style logs has been extracted and placed in your analysis environment.
Your task is to analyse these logs to reconstruct the attacker's actions, identify what resources were accessed or modified, and produce a timeline of events.

The environment runs entirely in Docker — no AWS account is required.

---

## Learning Objectives

* Parse JSON CloudTrail-style log records
* Identify reconnaissance, privilege escalation, and data exfiltration patterns in cloud API calls
* Correlate events by source IP and user identity
* Build an attack timeline from structured logs

---

## Environment Setup

```console
cd demos/demo-01-cloud-security
docker compose up -d
docker compose exec app bash
```

Inside the container you will find:

* Python 3.11 with `pandas`, `rich`, `jmespath` libraries
* Log file at `/data/cloudtrail_sample.json` (a JSON array of CloudTrail-style records)
* Helper script at `/scripts/audit_cloudtrail.py` for reference

---

## Log Format

Each log record follows the CloudTrail JSON structure:

```json
{
  "eventTime": "2024-11-15T03:22:14Z",
  "eventName": "ListBuckets",
  "eventSource": "s3.amazonaws.com",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "aws-cli/2.13.0",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "backup-svc",
    "arn": "arn:aws:iam::123456789012:user/backup-svc"
  },
  "requestParameters": {},
  "responseElements": null,
  "errorCode": null,
  "errorMessage": null
}
```

---

## Tasks

### Task 1 — Load and Explore the Logs

1. Load `/data/cloudtrail_sample.json` using Python (standard `json` library or `pandas`).
1. Count the total number of log records.
1. List all unique `eventSource` services that appear in the logs.
1. List all unique `userIdentity.userName` values (or ARNs for assumed roles).
1. List all unique `sourceIPAddress` values.

**Hint:** Some records may have `userIdentity.type == "AssumedRole"` — extract the role name from the ARN in that case.

### Task 2 — Identify the Suspicious Source IP

1. Count the number of events per `sourceIPAddress`.
1. Identify which IP address is responsible for the most events.
1. List all unique `eventName` values called by that IP address.
1. Note the time range of activity from that IP (first event → last event).

**Expected finding:** One IP will stand out with a concentrated burst of API calls within a short window.

### Task 3 — Reconstruct the Attack Sequence

For the suspicious IP identified in Task 2:

1. Sort all events by `eventTime` (ascending).
1. Categorise each `eventName` into one of these ATT&CK-inspired phases:
   * **Reconnaissance:** `Describe*`, `List*`, `Get*` calls
   * **Privilege Escalation:** `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`, `CreateRole`, `AttachRolePolicy`
   * **Persistence:** `CreateUser`, `CreateLoginProfile`, `UpdateLoginProfile`
   * **Exfiltration:** `GetObject`, `CopyObject`, `GetSecretValue`, `GetParameter`

1. Print a timeline showing: `eventTime | eventName | phase | errorCode`

**Hint:** Use string prefix matching (`eventName.startswith("List")`) for reconnaissance classification.

### Task 4 — Identify Impacted Resources

1. Find all S3 bucket names that were accessed (look in `requestParameters.bucketName`).
1. Find any IAM users or roles created during the incident.
1. Find any secrets or parameters read (from Secrets Manager or SSM Parameter Store).
1. Note which actions succeeded (errorCode is null/absent) vs failed.

**Hint:** `requestParameters` is a nested dict — use `.get()` with fallback to None.

### Task 5 — Write an Incident Summary

Create `/tmp/incident_summary.txt` with:

* Attacker source IP and user identity used
* Estimated attack start and end times
* ATT&CK phases observed (with example events for each)
* Resources accessed or modified
* Recommended immediate containment actions (at least 3)

---

## Deliverables

* Terminal output showing the event timeline (Task 3)
* `/tmp/incident_summary.txt` — written incident summary

---

## Hints

* `eventTime` strings are ISO 8601 format — use `datetime.fromisoformat()` after stripping the trailing `Z` (replace with `+00:00`).
* Not all `responseElements` fields will be populated — don't assume the key exists.
* A `GetObject` call with a `requestParameters.key` showing `.csv` or `.sql` extension is a strong exfiltration indicator.
* Look for `CreateAccessKey` — if an attacker creates a new access key for an existing service account, they have persistent access even after the compromised session ends.

---

## Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| Correctly counted records and unique values (Task 1) | 15 |
| Correctly identified suspicious IP and its event range (Task 2) | 20 |
| Produced a correctly sorted, categorised timeline (Task 3) | 25 |
| Correctly identified impacted resources (Task 4) | 20 |
| Incident summary is accurate, actionable, and complete (Task 5) | 20 |

**Total: 100 points**
