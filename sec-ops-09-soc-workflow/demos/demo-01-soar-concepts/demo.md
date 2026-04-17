# Demo 01: SOAR Concepts Walkthrough

**Duration**: ~30 minutes

**Level**: Beginner

**Format**: Guided walkthrough (no lab environment required — conceptual + diagrams)

---

## Overview

This demo introduces SOAR concepts through visual examples, annotated playbook diagrams, and real-world workflow walkthroughs.
It is designed to be delivered as an instructor-led walkthrough or self-paced review before the hands-on demos.

**What you will see:**

1. How a SOAR platform receives a trigger and executes a workflow
1. Three visual playbook examples with annotated decision logic
1. How SOAR integrates with SIEM, TI, and ticketing
1. The difference between enrichment-only and containment automation
1. A side-by-side comparison of manual vs. automated response timelines

---

## Part 1: How SOAR Receives a Trigger

### Scenario: New phishing alert from Splunk

```text
[SIEM: Splunk]
Rule fires: "Email with suspicious URL from external sender"
Alert data:
  - rule_name: Suspicious_External_Email_URL
  - sender: attacker@evil-domain.xyz
  - recipient: alice@company.com
  - subject: "URGENT: Your account will be suspended"
  - urls_in_email: ["http://evil-domain.xyz/login"]
  - timestamp: 2026-04-06T14:32:11Z
  - alert_id: SPL-20260406-14321
```

**Step 1: SIEM sends webhook to SOAR**

```text
POST http://soar-platform:5001/api/v1/hooks/phishing-triage
Content-Type: application/json

{
  "trigger": "siem_alert",
  "alert_id": "SPL-20260406-14321",
  "rule": "Suspicious_External_Email_URL",
  "data": {
    "sender": "attacker@evil-domain.xyz",
    "recipient": "alice@company.com",
    "urls": ["http://evil-domain.xyz/login"],
    "timestamp": "2026-04-06T14:32:11Z"
  }
}
```

**Step 2: SOAR workflow engine receives webhook → starts phishing playbook**

```text
[SOAR Workflow Engine]
  Received webhook trigger
  Matched trigger type: "siem_alert"
  Matched rule pattern: "*_Email_*"
  Starting workflow: "Phishing Email Response v2.3"
  Execution ID: WF-EX-20260406-001
```

**Step 3: Workflow begins executing actions in sequence (with parallelism)**

```text
Action 1: HTTP Request → VirusTotal URL check
Action 2: HTTP Request → AbuseIPDB domain check     ← These run in parallel
Action 3: HTTP Request → WHOIS domain lookup        ←

[Wait for all parallel actions to complete]

Action 4: Condition check → If any score > 50 → branch "malicious"
Action 5: TheHive → Create Alert (severity based on score)
Action 6: Exchange → Quarantine email (if malicious branch)
Action 7: Slack → Notify SOC channel
```

---

## Part 2: Visual Playbook Examples

### Example A: Simple Linear Playbook (IOC Enrichment)

```text
[Trigger: Manual - Analyst submits IP for enrichment]
                │
                ▼
┌─────────────────────────────────────────┐
│  Action 1: HTTP GET VirusTotal          │
│  URL: /api/v3/ip_addresses/{ip}         │
│  Output: malicious_count, total_engines │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│  Action 2: HTTP GET AbuseIPDB           │
│  URL: /api/v2/check?ipAddress={ip}      │
│  Output: abuseConfidenceScore           │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│  Action 3: HTTP GET Shodan              │
│  URL: /shodan/host/{ip}                 │
│  Output: ports, hostnames, country      │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│  Action 4: Format enrichment report     │
│  Template: "IP {ip} Summary:\n          │
│   VT: {vt.malicious}/{vt.total}\n       │
│   Abuse: {abuse.score}%\n               │
│   Ports: {shodan.ports}"                │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│  Action 5: TheHive → Add observable     │
│  case_id: {input.case_id}              │
│  value: {ip}                            │
│  datatype: ip                           │
│  tags: ["enriched", "auto"]             │
│  message: {enrichment_report}           │
└─────────────────────────────────────────┘
```

**Key concept demonstrated**: Linear workflow — each action feeds into the next.
No branching.
Safe to fully automate (enrichment only, no impact).

---

### Example B: Branching Playbook (Phishing with Decision Logic)

```text
[Trigger: Webhook from Splunk rule "Phishing_Email_Detected"]
                │
     ┌──────────┴──────────┐
     │  Action 1 (parallel)│  Action 2 (parallel)
     │  VirusTotal URL check│  Domain WHOIS lookup
     └──────────┬──────────┘
                │  (both complete)
                ▼
    ┌─────────────────────────┐
    │ Condition: VT score > 50│
    └────────┬────────────────┘
           │        │
         True      False
           │        │
           ▼        ▼
  ┌──────────────┐  ┌────────────────────┐
  │ Action 3a:   │  │ Action 3b:         │
  │ Exchange:    │  │ Update alert:      │
  │ Quarantine   │  │ status = "review"  │
  │ email        │  │ Notify L1 analyst  │
  └──────┬───────┘  └────────────────────┘
         │
         ▼
  ┌──────────────────────────────────────┐
  │ Action 4: TheHive → Create Case      │
  │ title: "Phishing: {sender}"          │
  │ severity: 2 (Medium)                 │
  │ tags: ["phishing", "auto-quarantine"]│
  └──────────────────────────────────────┘
         │
         ▼
  ┌──────────────────────────────────────┐
  │ Action 5: Slack notification         │
  │ channel: #soc-alerts                 │
  │ "🚨 Phishing detected from {sender}  │
  │  Email quarantined. Case: {case_id}" │
  └──────────────────────────────────────┘
```

**Key concept demonstrated**: Conditional branching.
Different actions based on enrichment results.
The "False" branch queues for human review — human-in-the-loop for borderline cases.

---

### Example C: Loop Playbook (Process Multiple IOCs)

```text
[Trigger: TheHive new case with multiple observables]
                │
                ▼
    ┌──────────────────────────────┐
    │ Action 1: TheHive            │
    │ Get all observables from case│
    │ Output: [{type, value}, ...]  │
    └──────────┬───────────────────┘
               │
               ▼
    ┌──────────────────────────────┐
    │ Action 2: LOOP               │
    │ For each observable:         │
    │   If type == "ip":           │
    │     → Run IP enrichment sub  │
    │   If type == "url":          │
    │     → Run URL enrichment sub │
    │   If type == "hash":         │
    │     → Run hash enrichment sub│
    └──────────┬───────────────────┘
               │ (all iterations complete)
               ▼
    ┌──────────────────────────────┐
    │ Action 3: Build summary      │
    │ Aggregate all results        │
    │ Count: malicious/suspicious/ │
    │        clean per IOC type    │
    └──────────┬───────────────────┘
               │
               ▼
    ┌──────────────────────────────┐
    │ Action 4: TheHive            │
    │ Add note to case:            │
    │ "Auto-enrichment complete.   │
    │  {malicious} malicious IOCs  │
    │  found. Details: {summary}"  │
    └──────────────────────────────┘
```

**Key concept demonstrated**: Iterative processing.
Process a variable-length list of items.
Essential for cases with multiple IOCs.

---

## Part 3: Manual vs. Automated Response Timeline

### Phishing Alert — Manual Response (No SOAR)

```text
TIME    ACTION                              ANALYST  TOOL
──────  ──────────────────────────────────  ───────  ────────────────
T+0:00  Alert fires in SIEM                 -        Splunk
T+4:30  Analyst picks up alert from queue   L1       Splunk
T+4:35  Check alert details, extract IOCs   L1       Splunk
T+6:00  Open VirusTotal, check URL          L1       Browser
T+7:30  Open AbuseIPDB, check domain        L1       Browser
T+9:00  WHOIS lookup                        L1       Browser
T+10:30 Determine: malicious                L1       -
T+11:00 Log into Exchange Admin             L1       Exchange
T+13:00 Find and quarantine email           L1       Exchange
T+15:00 Create ticket in Jira               L1       Jira
T+18:00 Notify user by email                L1       Email client
T+19:00 Post to SOC Slack channel           L1       Slack
T+19:30 Complete - ticket closed            L1       Jira

Total time: ~19.5 minutes
Analyst time: ~15 minutes active
```

### Same Alert — Automated Response (With SOAR)

```text
TIME    ACTION                              WHO      TOOL
──────  ──────────────────────────────────  ───────  ────────────────
T+0:00  Alert fires in SIEM                 -        Splunk
T+0:02  SOAR receives webhook trigger       SOAR     Shuffle
T+0:03  VirusTotal URL check (parallel)     SOAR     VT API
T+0:03  AbuseIPDB domain check (parallel)   SOAR     AIPDB API
T+0:03  WHOIS lookup (parallel)             SOAR     WHOIS API
T+0:08  Results received, score = 87        SOAR     -
T+0:09  Exchange: quarantine email          SOAR     Exchange API
T+0:10  TheHive: create case                SOAR     TheHive API
T+0:11  Slack: notify SOC channel           SOAR     Slack API
T+0:12  Execution complete                  SOAR     -

T+2:00  Analyst reviews pre-enriched case   L1       TheHive
T+4:00  Analyst confirms, closes ticket     L1       TheHive

Total wall-clock time: ~4 minutes
Analyst time: ~2 minutes active
Time saved: ~15.5 minutes per phishing alert
```

**Impact calculation:**

* 100 phishing alerts/day × 15.5 minutes saved = 25.8 analyst-hours saved per day
* At 8 FTE analysts × 8h shift = 64 analyst-hours/day
* Phishing automation frees ~40% of daily analyst capacity

---

## Part 4: Integration Architecture Walk-Through

### How Shuffle connects to tools

```text
SHUFFLE WORKFLOW EXECUTION FLOW:

1. Trigger fires (webhook/schedule/manual)

   │
   └── Shuffle Backend receives trigger
       └── Creates workflow execution instance
           └── Queues actions for Orborus (scheduler)
               └── Orborus pulls actions, spins up Worker containers
                   └── Worker executes action:
                       ├── Makes API call to target tool
                       ├── Receives response
                       ├── Parses response using JSONPath / regex
                       └── Passes result to next action

TOOL AUTHENTICATION IN SHUFFLE:
  Each "App" in Shuffle has:
  - Authentication type (API key, OAuth, Basic Auth)
  - Stored credentials (encrypted in Shuffle)
  - Base URL for the tool instance

  Example: VirusTotal App
    Auth type: API Key
    Header: "x-apikey: {api_key}"
    Base URL: https://www.virustotal.com

  Example: TheHive App
    Auth type: API Key
    Header: "Authorization: Bearer {api_key}"
    Base URL: http://thehive:9000

DATA PASSING BETWEEN ACTIONS:
  Actions reference previous action outputs using:
  $action_name.output           → full output
  $action_name.data.field       → specific field
  $action_name.data[0].subfield → array element

  Example: After VirusTotal check:
  $vt_check.data.attributes.last_analysis_stats.malicious
  → Returns the number of malicious detections
```

---

## Part 5: SOAR Pitfall Demonstrations

### Pitfall 1: The Runaway Blocker

**Scenario**: SOC deploys a playbook that auto-blocks any IP with VT score > 5.

```python
# BAD PLAYBOOK LOGIC - DO NOT USE
if virustotal_score > 5:
    firewall.block_ip(source_ip)
```

**What goes wrong**:

* CloudFlare IPs often have 5-10 VT detections (shared hosting)
* CDN edge servers (Fastly, Akamai) get flagged by some VT engines
* Internal monitoring systems scanning the network get flagged
* Result: Mass blocking of legitimate services → business outage

**Correct approach**:

```python
# BETTER PLAYBOOK LOGIC
if virustotal_score > 5:
    # Check against allowlist first
    if source_ip not in ip_allowlist:
        if virustotal_score > 50:
            # High confidence - auto-block
            firewall.block_ip(source_ip)
        else:
            # Low confidence - human review
            ticket.create(priority="medium",
                         notes=f"IP {source_ip} VT score: {virustotal_score}",
                         requires_approval=True)
```

### Pitfall 2: Noise Amplification

**Scenario**: A SIEM rule has a 70% false positive rate.
SOAR auto-creates tickets AND sends Slack notifications for every alert.

**Result**: SOC Slack channel gets 700 FP notifications per day → analysts ignore all Slack alerts → real P1 incident missed.

**Fix**: Add enrichment filter before notification:

```text
Rule fires (70% FP rate)
    │
    └── SOAR: Enrich IP + check asset criticality
        │
        ├── Low risk enrichment → Log only (no ticket, no notification)
        └── High risk enrichment → Create ticket + notify
```

---

## Summary

| Concept | Key Takeaway |
|---------|-------------|
| SOAR triggers | Event-driven (webhooks) or scheduled; map to playbooks |
| Linear playbooks | Safe for enrichment; fully automatable |
| Branching playbooks | Needed for conditional response logic |
| Loop playbooks | Process collections of IOCs or assets |
| Manual vs. automated | SOAR can reduce analyst time from 15+ min to <2 min per alert |
| Integration auth | Credentials stored in SOAR; least-privilege service accounts |
| Pitfalls | Allowlists + confidence thresholds prevent runaway automation |

**Next demo**: Build the phishing response playbook hands-on in Shuffle.
