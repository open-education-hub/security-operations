# Guide 01: Cloud Security Fundamentals for SOC Analysts

## Overview

This guide introduces cloud security concepts from the perspective of a SOC analyst.
You will learn the shared responsibility model, common cloud attack vectors, and how to interpret cloud-native logs in a security context.
This knowledge is essential as most organisations now run hybrid or fully cloud environments.

## Learning Objectives

After completing this guide you will be able to:

* Explain the shared responsibility model for IaaS, PaaS, and SaaS
* Identify the top cloud misconfiguration categories
* Describe how SOC monitoring extends to cloud environments
* Read AWS CloudTrail and Azure Activity Log entries for suspicious activity

## Estimated Time

45 minutes

---

## 1. The Cloud Shared Responsibility Model

Every major cloud provider uses a shared responsibility model.
The key principle:

**The provider secures the cloud.
You secure what's in the cloud.**

### IaaS (e.g., AWS EC2, Azure VMs)

| Responsibility | Provider | Customer |
|---------------|----------|----------|
| Physical infrastructure | ✅ | |
| Hypervisor / virtualisation | ✅ | |
| Operating system | | ✅ |
| Applications and runtime | | ✅ |
| Data | | ✅ |
| Identity and access | | ✅ |
| Network configuration | | ✅ |

### SaaS (e.g., Office 365, Salesforce)

The provider manages almost everything.
The customer is responsible only for:

* **Data** (what you store in the service)
* **Identity** (who has access and with what permissions)
* **Access management** (MFA, conditional access policies)

**Key insight for SOC analysts:** Even in SaaS, a compromised account or misconfigured sharing settings can lead to a serious data breach.
You must monitor identity and access events.

---

## 2. Top Cloud Misconfiguration Categories

### 2.1 Overprivileged IAM

The most common cloud security mistake.
Examples:

* A Lambda function with `AdministratorAccess` when it only needs to read one S3 bucket
* A developer user with production database write access
* Service accounts that were never deprovisioned after a project ended

**Principle of least privilege**: every identity should have only the permissions it needs, for only the resources it needs, for only the time it needs them.

### 2.2 Publicly Accessible Storage

Cloud storage defaults vary.
AWS S3 now blocks public access by default, but:

* Older buckets may pre-date this change
* Bucket policies can override the block
* Individual object ACLs can make files public even if the bucket is private

SOC relevance: Public storage with sensitive data is a direct data breach.
You should have continuous monitoring for public bucket misconfigurations.

### 2.3 Exposed Management Interfaces

* No MFA on the cloud console login
* SSH/RDP open to 0.0.0.0/0 in security groups
* Kubernetes API server exposed to the internet

**Detection**: Cloud Security Posture Management (CSPM) tools continuously scan for these misconfigurations.

### 2.4 Missing Logging

Without logs, you cannot detect incidents.
Essential logging to enable:

* **AWS**: CloudTrail (API activity), VPC Flow Logs, GuardDuty
* **Azure**: Activity Log, Azure Defender, Microsoft Sentinel
* **GCP**: Cloud Audit Logs, Cloud Armour

---

## 3. SOC Integration for Cloud

### 3.1 Collecting Cloud Logs in Your SIEM

Cloud logs feed into your SIEM alongside on-premises logs:

```text
CloudTrail → S3 → Lambda → SIEM
Azure Activity Log → Event Hub → SIEM connector
GCP Audit Logs → Cloud Pub/Sub → SIEM
```

### 3.2 Key Events to Alert On

#### AWS CloudTrail

| Event | Significance |
|-------|-------------|
| `ConsoleLogin` with `additionalEventData.MFAUsed: No` | Login without MFA |
| `DeleteTrail` | Attacker disabling logging |
| `StopLogging` | Attacker disabling logging |
| `CreateAccessKey` | Potential persistence (new credential) |
| `AttachUserPolicy` with `AdministratorAccess` | Privilege escalation |
| `PutBucketAcl` with `PublicRead` | Bucket made public |

#### Azure Activity Log

| Operation | Significance |
|-----------|-------------|
| `Microsoft.Authorization/roleAssignments/write` | Role assignment (escalation check) |
| `Microsoft.KeyVault/vaults/secrets/read` | Secret access |
| `Microsoft.Network/networkSecurityGroups/securityRules/write` | Firewall rule change |
| `Delete` on any resource | Potential destructive action |

### 3.3 Reading a CloudTrail Event

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAXXXXXXXXXXXXXXXXX",
    "arn": "arn:aws:iam::123456789012:user/service-account",
    "accountId": "123456789012",
    "userName": "service-account"
  },
  "eventTime": "2024-03-15T02:43:17Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "PutBucketAcl",
  "requestParameters": {
    "bucketName": "company-data-backup",
    "AccessControlPolicy": {
      "Grant": {"Grantee": {"URI": "AllUsers"}, "Permission": "READ"}
    }
  }
}
```

**Analysis:**

* `service-account` made an S3 bucket publicly readable at 02:43 UTC
* This is off-hours (potential indicator of compromise)
* The target bucket is `company-data-backup` — high sensitivity
* **Action**: Immediately revert the ACL, investigate `service-account` activity

---

## 4. Cloud Threat Detection Patterns

### 4.1 Credential Compromise Pattern

```text
Unusual login location → Console login without MFA → IAM enumeration →
CreateAccessKey → Stops logging → Exfiltrates data from S3
```

### 4.2 Cryptomining Pattern (Common Low-Sophistication Attack)

```text
Exposed SSH/API → Unauthorised EC2 RunInstances (GPU instances) →
Unusual outbound network traffic to mining pools
```

### 4.3 Ransomware in Cloud

```text
Compromised account → Enumerates S3 buckets → Copies data out →
Deletes all objects → Demands ransom
```

Detection: S3 `DeleteObjects` events at scale, followed by rapid S3 traffic to external IPs.

---

## 5. CSPM: Cloud Security Posture Management

CSPM tools continuously scan your cloud environment and report misconfigurations:

| Tool | Cloud | Notes |
|------|-------|-------|
| AWS Security Hub | AWS | Aggregates findings from GuardDuty, Inspector, Config |
| Microsoft Defender for Cloud | Azure / multi-cloud | Provides security score |
| Google Security Command Center | GCP | Centralised posture management |
| Prisma Cloud | Multi-cloud | Third-party, comprehensive |
| Prowler | AWS | Open-source CLI scanner |

**For SOC analysts**: CSPM findings should feed into your ticketing system and be treated like vulnerabilities — prioritised by risk and remediated within SLA.

---

## 6. Quick Reference: Cloud Security Checklist

* [ ] MFA enabled for all console logins (especially root/Global Admin)
* [ ] CloudTrail enabled in all regions and protected from deletion
* [ ] No S3 buckets with public read/write ACLs
* [ ] IAM users follow least-privilege; no use of root account for daily work
* [ ] Security groups do not allow 0.0.0.0/0 to SSH (port 22) or RDP (port 3389)
* [ ] Key rotation enforced (IAM access keys, storage account keys)
* [ ] CSPM tool deployed and alerts routed to SOC
* [ ] Cloud logs flowing into SIEM with alerting rules active

---

## Summary

Cloud security monitoring extends the SOC's responsibility beyond the on-premises perimeter.
The shared responsibility model means configuration and identity management are always the customer's responsibility.
Common misconfigurations — overprivileged IAM, public storage, missing logs — are the leading cause of cloud breaches.
SOC analysts must be able to read cloud-native logs (CloudTrail, Azure Activity) and recognise attack patterns specific to cloud environments.
