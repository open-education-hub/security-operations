# Guide 01: Cloud Security Fundamentals for SOC Analysts

**Level:** Basic

**Estimated time:** 45 minutes

**Prerequisites:** Reading for Session 13

---

## Objective

By the end of this guide, you will be able to:

* Explain the shared responsibility model for IaaS, PaaS, and SaaS
* Identify the top cloud misconfiguration categories
* Describe how SOC monitoring extends to cloud environments
* Read AWS CloudTrail and Azure Activity Log entries for suspicious activity

---

## 1. The Cloud Shared Responsibility Model

Every major cloud provider uses a shared responsibility model:

**The provider secures the cloud.
You secure what's in the cloud.**

### IaaS (AWS EC2, Azure VMs)

| Responsibility | Provider | Customer |
|---------------|----------|----------|
| Physical infrastructure | ✅ | |
| Hypervisor / virtualisation | ✅ | |
| Operating system | | ✅ |
| Applications and runtime | | ✅ |
| Data | | ✅ |
| Identity and access | | ✅ |

### SaaS (Office 365, Salesforce)

The provider manages almost everything.
The customer is responsible for:

* **Data** (what you store)
* **Identity** (who has access)
* **Access management** (MFA, conditional access)

**Key insight for SOC analysts:** Even in SaaS, a compromised account or misconfigured sharing setting can cause a serious breach.
You must monitor identity and access events.

---

## 2. Top Cloud Misconfiguration Categories

### Overprivileged IAM

The most common cloud security mistake:

* A service account with `AdministratorAccess` when it needs one specific action
* Developers with production database write access
* Deprovisioned accounts still active

**Principle of least privilege**: every identity → only the permissions it needs → only for the resources it needs.

### Publicly Accessible Storage

AWS S3 now blocks public access by default, but:

* Older buckets may pre-date this default
* Bucket policies can override the block
* Individual object ACLs can expose files even if the bucket is private

SOC relevance: Public storage with sensitive data is a direct data breach — detect misconfigurations continuously.

### Missing Logging

Without logs you cannot detect incidents.
Essential logging:

* **AWS**: CloudTrail, VPC Flow Logs, GuardDuty
* **Azure**: Activity Log, Microsoft Defender for Cloud
* **GCP**: Cloud Audit Logs

### Exposed Management Interfaces

* No MFA on cloud console login
* SSH or RDP open to `0.0.0.0/0` in security groups
* Kubernetes API server exposed to the internet

---

## 3. Interpreting Cloud Logs

### AWS CloudTrail Events to Watch

| Event | Significance |
|-------|-------------|
| `ConsoleLogin` with `MFAUsed: No` | Login without MFA |
| `DeleteTrail` | Attacker disabling logging |
| `CreateAccessKey` | New credential — potential persistence |
| `AttachUserPolicy` with `AdministratorAccess` | Privilege escalation |
| `PutBucketAcl` with `AllUsers` | Bucket made public |

### Reading a CloudTrail Entry

```json
{
  "userIdentity": {
    "userName": "service-account",
    "type": "IAMUser"
  },
  "eventTime": "2026-03-15T02:43:17Z",
  "eventName": "PutBucketAcl",
  "requestParameters": {
    "bucketName": "company-data-backup",
    "Grant": {"Grantee": {"URI": "AllUsers"}, "Permission": "READ"}
  }
}
```

**Analysis:**

* `service-account` made a backup bucket publicly readable at 02:43 UTC (off-hours)
* **Action:** Immediately revert the ACL, investigate `service-account` activity and whether credentials were compromised

### Azure Activity Log

| Operation | Significance |
|-----------|-------------|
| `roleAssignments/write` | Role assignment change — check for escalation |
| `keyvaults/secrets/read` | Secret accessed |
| `securityRules/write` | Firewall rule changed |
| `Delete` on critical resources | Potential destructive action |

---

## 4. Cloud Threat Detection Patterns

**Credential compromise:**

```text
Unusual login location → Console login without MFA →
IAM enumeration → CreateAccessKey → Disables logging → S3 exfiltration
```

**Cryptomining:**

```text
Exposed SSH/API key → Unauthorised GPU VM launch →
High outbound traffic to mining pools
```

**Cloud ransomware:**

```text
Compromised account → Enumerate S3 buckets → Copy data out →
Delete all objects → Demand ransom
```

---

## 5. Cloud Security Checklist

* [ ] MFA enabled for all console logins (especially root/Global Admin)
* [ ] CloudTrail enabled in all regions, protected from deletion
* [ ] No S3 buckets with public read/write access
* [ ] IAM follows least-privilege; root account not used daily
* [ ] Security groups do not allow 0.0.0.0/0 to port 22 or 3389
* [ ] Key rotation enforced
* [ ] CSPM tool deployed and alerts routed to SOC
* [ ] Cloud logs flowing into SIEM with active detection rules

---

## Summary

Cloud security monitoring extends the SOC's responsibility beyond the on-premises perimeter.
The shared responsibility model means configuration and identity management are always the customer's responsibility.
Common misconfigurations — overprivileged IAM, public storage, missing logs — are the leading cause of cloud breaches.
SOC analysts must read cloud-native logs and recognise cloud-specific attack patterns.
