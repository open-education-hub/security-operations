# Guide 01 (Basic): Alert Triage Workflow

## Objective

Learn how to triage a security alert systematically: determine if it is a true positive or false positive, assign severity, and decide the next action.

## Estimated Time

30–40 minutes

## Prerequisites

* Read Session 09 sections 1–4

---

## The Triage Framework

Every alert must be triaged using this decision sequence:

```text
STEP 1: READ the alert
  ↓
STEP 2: ENRICH observables
  ↓
STEP 3: ASSESS context
  ↓
STEP 4: CLASSIFY (TP / FP / Benign TP)
  ↓
STEP 5: ASSIGN severity (P1-P4) if TP
  ↓
STEP 6: ACT (close / investigate / escalate)
```

---

## Step-by-Step Walkthrough

### Step 1: Read the Alert

Open the raw alert and identify:

* **What fired:** Which rule or sensor generated this? (SIEM correlation rule, EDR signature, IDS alert)
* **When:** Timestamp. Is this real-time or retroactive detection?
* **Who:** Which user account or system is involved?
* **What happened:** What activity was detected? (network connection, file creation, authentication)
* **Where:** Which asset? What network zone? (DMZ, corporate, production, PCI)

**Example alert:**

```text
Alert: Suspicious Outbound Network Connection
Rule: OUTBOUND_TOR_CONNECTION
Severity: MEDIUM (rule default)
Time: 2024-11-14 14:22:31 UTC
Host: acct-ws-017 (192.168.10.42)
User: m.chen (Finance Department)
Details: Process chrome.exe connected to 198.98.56.149:9001
         Destination tagged as TOR exit node in threat intel feed
```

### Step 2: Enrich Observables

Check each observable against threat intelligence:

**IP address `198.98.56.149`:**

* VirusTotal: check via https://www.virustotal.com/
* AbuseIPDB: check via https://www.abuseipdb.com/
* Note: port 9001 is a default Tor OR port

**Host `acct-ws-017`:**

* Query CMDB: Owner, role, criticality
* Query EDR: Other recent alerts on this host
* Query SIEM: Any other unusual events in last 24h?

**User `m.chen`:**

* Query Active Directory: Last login, group memberships
* Query HR system: Currently employed? On-site or remote?
* Query SIEM: Normal working hours? Prior incidents?

### Step 3: Assess Context

Ask:

* Is there a legitimate reason for a finance employee to connect to a Tor exit node?
* Has this host or user had prior alerts?
* Is there a pentest or security assessment scheduled?
* What other activity has `chrome.exe` done recently on this host?

### Step 4: Classify

Based on enrichment:

| Finding | Weight |
|---------|--------|
| IP confirmed Tor exit node | +suspicious |
| User is Finance (high-value target) | +severity |
| No prior alerts on this user in 90 days | neutral |
| Chrome as parent (could be malvertising) | +suspicious |
| No known pentest scheduled | +suspicious |

**Classification:** True Positive (likely malicious or high-risk)

### Step 5: Assign Severity

Using the severity matrix:

* Asset: Finance workstation (medium criticality)
* Data risk: Finance user has access to financial data
* TTP: C2 via Tor (active threat actor pattern)
* Scope: Single host so far

**Severity: P2 (High)**

### Step 6: Act

For P2:

* Create a case in the ticketing system
* Assign to Tier 2 analyst
* Document all enrichment findings
* Flag host for monitoring
* Do NOT isolate yet without Tier 2 review

---

## Practice Scenarios

Triage each of the following alerts using the 6-step framework.
Document your reasoning.

### Scenario A

```text
Alert: Multiple Failed SSH Logins
Rule: SSH_BRUTEFORCE_EXTERNAL
Time: 2024-11-14 03:15 UTC
Target: jumphost-01 (external IP 203.0.113.5)
Source: 45.55.88.12 (14 failed attempts in 60 seconds)
```

*Questions: Is this TP/FP?
What severity?
Why?*

### Scenario B

```text
Alert: PowerShell Encoded Command Execution
Rule: POWERSHELL_ENCODED_CMD
Time: 2024-11-14 09:44 UTC
Host: it-ws-033
User: svc-backup (service account)
CommandLine: powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQ...
```

*Questions: Is this TP/FP?
What severity?
Does it matter that the user is a service account?*

### Scenario C

```text
Alert: New Scheduled Task Created
Rule: SCHED_TASK_CREATED_SUSPICIOUS_PATH
Time: 2024-11-14 11:02 UTC
Host: dev-ws-011
User: d.patel (Development)
Task: "UpdateHelper" running C:\Users\d.patel\AppData\Local\Temp\upd.exe
```

*Hint: Check if `C:\Users\...\AppData\Local\Temp\` is a typical location for legitimate scheduled tasks.*

---

## Key Takeaways

1. Triage is a decision-making process, not just alert reading
1. Context transforms raw alerts into meaningful signals
1. The same alert can be P1 or P4 depending on asset/user context
1. Document every step — if you close a case as FP, explain why
