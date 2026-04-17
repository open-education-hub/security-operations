# Guide 01 — Incident Classification

## Objective

By the end of this guide you will be able to:

* Classify a security incident by type (malware, unauthorized access, data breach, etc.)
* Assign a severity level (P1–P5) using a defined criteria set
* Identify mandatory escalation triggers
* Document the initial classification in a case management system

**Estimated time:** 25 minutes

**Level:** Basic

**Prerequisites:** Reading material for Session 10

---

## Classification Framework

### Step 1: Identify the Incident Category

| Category | Description | Examples |
|----------|-------------|---------|
| Malware | Malicious software running on systems | Ransomware, trojan, worm, beacon |
| Unauthorized Access | Access without permission | Account compromise, privilege escalation |
| Data Breach | Unauthorized disclosure or loss of data | Exfiltration, accidental exposure, lost device |
| Denial of Service | Disruption of availability | DDoS, resource exhaustion |
| Social Engineering | Human manipulation attacks | Phishing, BEC, vishing |
| Insider Threat | Malicious or negligent internal actor | Data theft, accidental loss, sabotage |
| Physical Security | Physical access incidents | Stolen laptop, tailgating |
| Supply Chain | Third-party compromise | Backdoored update, vendor breach |

### Step 2: Assign Severity

| Level | Name | Criteria |
|-------|------|----------|
| P1 | Critical | Active spread, production down, confirmed breach with sensitive data, immediate business impact |
| P2 | High | Contained incident with significant risk, single system with high-value credentials, active C2 |
| P3 | Medium | Limited scope, no data loss confirmed, high-risk policy violation |
| P4 | Low | Minimal impact, no data exposure, policy violation |
| P5 | Info | Awareness only, no action required |

---

## Worked Example 1: Ransomware Alert

**Alert details:**

```text
Alert: Mass file rename activity detected — FILESERVER-01
Rule: Multiple files renamed with .crypted extension
Severity: Critical (SIEM assigned)
Time: 2025-04-10 02:15 UTC

Additional context:
- FILESERVER-01 is the primary file server for 300 users
- 847 files renamed in 3 minutes
- VSS shadow copies deleted (vssadmin.exe delete shadows)
- Process tree: explorer.exe → cmd.exe → vssadmin.exe
- User: john.davis@company.com (regular employee)
```

**Classification process:**

Step 1 — Category: **Malware** (ransomware, subcategory)

Step 2 — Severity assessment:

* Active file encryption in progress: YES → P1 criterion
* Production system affected (file server for 300 users): YES → P1 criterion
* VSS deletion (defensive measure bypass): YES → high confidence true positive
* Business impact: immediate — users cannot access files

**Severity: P1 — Critical**

**Classification entry:**

```text
Category: Malware - Ransomware
Severity: P1 - Critical
Status: Identified - Immediate Response Required

Evidence: Mass file rename (.crypted), VSS deletion, unusual process chain
Affected Systems: FILESERVER-01 (primary file server)
Users at Risk: 300 employees
Data at Risk: All data on FILESERVER-01

Immediate Actions Required:

1. Network isolate FILESERVER-01 immediately

2. Check backup integrity before attempting restoration
3. Check for spread to other servers
4. Notify IT management immediately
5. Engage GDPR assessment (customer data may be on file server)
```

---

## Worked Example 2: Phishing Campaign

**Alert details:**

```text
Alert: Multiple employees reported phishing email
Source: User reports (5 employees forwarded to security@company.com)
Time: 2025-04-10 09:30 UTC

Email details:
From: noreply@microsoft-auth-update.com
Subject: Action Required: Microsoft 365 Verification
Body: Link to https://microsoft-update-login.tk/m365

Known clicks: 5 (from reports)
Potentially opened by: ~200 employees (all received the email)
```

**Classification:**

Step 1 — Category: **Social Engineering - Phishing**

Step 2 — Severity:

* Active attack in progress (users still receiving/clicking): potential P2
* 5 confirmed clicks (credentials potentially submitted)
* Email still in all inboxes (200 at risk)
* URL domain is newly registered (.tk domain)
* No confirmed successful logins yet

**Severity: P2 — High** (5 confirmed clicks with credential exposure risk; downgrade to P3 if no successful logins confirmed after 30 min investigation)

**Classification entry:**

```text
Category: Social Engineering - Phishing
Severity: P2 - High
Status: Identified - Response In Progress

Phishing URL: https://microsoft-update-login.tk/m365
Sender domain: microsoft-auth-update.com (newly registered)
Confirmed clicks: 5 employees
Potential exposure: 200 employees

Immediate Actions Required:

1. Remove email from all inboxes (email quarantine)

2. Block URL at web proxy
3. Identify 5 employees who clicked - reset passwords
4. Check AD logs: any successful logins from unusual IPs after 09:15?
5. Notify employees about phishing (post-remediation)
```

---

## Practice Scenarios

Classify each of the following.
Record: Category, Severity, Key Evidence, and Immediate Actions.

**Scenario A:**

```text
Alert: USB device connected - DLP alert
Asset: WORKSTATION-HR-04 (HR department)
User: hr.manager@company.com
Time: Friday 17:45 (after hours)
DLP alert: Large file copy to USB (4.2 GB of documents)
Additional context: HR manager gave notice yesterday that they're leaving
```

**Scenario B:**

```text
Alert: Brute force on RDP service
Asset: SERVER-LEGACY-01 (old Windows Server 2012 — supposed to be decommissioned)
Source IPs: 3 distinct external IPs
Failed attempts: 450 in 20 minutes
One successful login at 14:32 (user: Administrator)
```

**Scenario C:**

```text
Notification from cloud provider: "Unusual API access pattern"
Asset: AWS S3 bucket containing customer order data
Activity: 12,000 GetObject API calls in 4 hours from an IP not in your cloud architecture
Total data: ~18 GB downloaded
```

---

## Classification Quick Reference Card

Print this and keep it at your workstation:

```text
INCIDENT CLASSIFICATION QUICK REFERENCE

IS IT P1? (YES = Immediate all-hands response)
□ Ransomware spreading or encrypting
□ Active data exfiltration in progress
□ Production systems down due to attack
□ Domain controller compromised
□ Customer/patient data confirmed stolen

IS IT P2? (YES = Escalate to Tier 2 now)
□ Confirmed active attacker on network
□ High-privilege account compromised
□ Phishing with confirmed credential submissions
□ C2 communication confirmed
□ Contained breach with potential data exposure

IS IT GDPR-RELEVANT?
□ Any personal data of EU residents involved?
□ If YES: notify DPO immediately → 72h clock starts
```

---

## Knowledge Check

1. A malware alert fires, but the antivirus blocked the file. No execution occurred. What severity?
1. An employee reports seeing their own files renamed with a strange extension on their own workstation. No other systems are affected. What severity?
1. An HR manager's account sends an email to all employees containing a Google Form requesting updated personal information. The manager was on vacation. What category and severity?
1. Your web proxy logs show a single server has made 47,000 DNS queries to a .xyz domain in 6 hours. What category might this be?
