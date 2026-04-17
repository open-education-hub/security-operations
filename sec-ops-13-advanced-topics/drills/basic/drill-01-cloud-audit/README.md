# Drill 01: Cloud Security Audit

## Difficulty: Basic

## Estimated Time: 30 minutes

## Scenario

You are a SOC analyst at a mid-size company that recently migrated 60% of its infrastructure to AWS.
The cloud team has asked you to perform a basic security audit of the AWS environment.
You have been given access to CloudTrail logs and a list of IAM policies.

## Objectives

1. Identify IAM users or roles with overprivileged access
1. Find any S3 buckets with public access
1. Determine whether CloudTrail is fully enabled
1. Identify suspicious CloudTrail events from the provided log excerpt

## Materials

The following log and configuration data is provided below.
You do not need Docker for this drill — answer based on the data provided.

---

## Task 1: IAM Policy Analysis

Review the following IAM policy attached to a Lambda function that processes customer order data:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

**Questions:**

1. What is wrong with this policy?
1. What should the policy allow, given the Lambda processes customer orders stored in DynamoDB table `orders-prod`?
1. Write a corrected policy with least-privilege access.

---

## Task 2: CloudTrail Log Analysis

Review the following CloudTrail events:

**Event A:**

```json
{
  "eventTime": "2024-03-10T03:22:41Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateAccessKey",
  "userIdentity": {"userName": "alice"},
  "sourceIPAddress": "185.220.101.42",
  "userAgent": "curl/7.68.0"
}
```

**Event B:**

```json
{
  "eventTime": "2024-03-10T03:23:05Z",
  "eventSource": "cloudtrail.amazonaws.com",
  "eventName": "DeleteTrail",
  "userIdentity": {"userName": "alice"},
  "requestParameters": {"name": "management-trail"}
}
```

**Event C:**

```json
{
  "eventTime": "2024-03-10T03:25:00Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "GetObject",
  "userIdentity": {"userName": "alice"},
  "requestParameters": {
    "bucketName": "customer-data-prod",
    "key": "exports/customers_all_2024.csv"
  }
}
```

**Questions:**

1. Are these events concerning? Why or why not?
1. What is the likely attack scenario linking Events A, B, and C?
1. What should you do immediately as the SOC analyst?
1. What detection rules should exist to catch Event B in real time?

---

## Task 3: S3 Bucket Audit

The following buckets exist in the account:

| Bucket Name | ACL | Block Public Access Setting |
|-------------|-----|---------------------------|
| company-website-static | public-read | OFF |
| customer-data-prod | private | ON |
| dev-team-experiments | public-read-write | OFF |
| audit-logs-archive | private | ON |

**Questions:**

1. Which buckets represent a security risk?
1. What is the risk associated with `dev-team-experiments` specifically?
1. What remediation steps would you recommend?

---

## Task 4: CloudTrail Coverage Check

The company has one CloudTrail trail configured:

* Region: `eu-west-1` only
* Logging: enabled
* S3 bucket: `audit-logs-archive`
* Multi-region: disabled
* Log file validation: disabled

**Questions:**

1. Is this configuration sufficient? What is missing?
1. What could an attacker do by operating in `us-east-1` instead?
1. What additional CloudTrail settings would you recommend?

---

## Deliverable

Write a short audit findings report (bullet points acceptable) that covers:

* Critical findings (require immediate action)
* High findings (action within 24 hours)
* Medium findings (action within 1 week)
* Recommended remediation for each
