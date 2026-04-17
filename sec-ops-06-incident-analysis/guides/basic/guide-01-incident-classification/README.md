# Guide 01: Classifying and Prioritizing Security Incidents

**Level:** Basic

**Estimated time:** 20 minutes

**Prerequisites:** Reading — Section 4 (Incident Classification Frameworks), Section 5 (Severity Levels)

---

## Purpose

By the end of this guide, you will be able to:

* Apply NIST and SANS incident category taxonomies to real alerts
* Assign a priority level (P1–P5) using a structured decision framework
* Recognize the key attributes that drive escalation
* Explain the difference between a security *event*, *alert*, and *incident*

---

## Part 1: Events, Alerts, and Incidents

Understanding the hierarchy is critical before attempting classification.

```text
Raw Log Entry              → Security EVENT
  │                            (observable occurrence — no context)
  ▼
Correlation Rule Fires     → Security ALERT
  │                            (event matching a defined pattern)
  ▼
Analyst Confirms Malicious → Security INCIDENT
                               (confirmed or likely policy violation)
```

**Example:**

| Type | Description |
|------|-------------|
| Event | `4625 - Account logon failure for user "admin"` |
| Alert | `10 failed logins for user "admin" in 2 minutes` (brute force rule) |
| Incident | `Confirmed brute force — 847 failures from 45.77.12.9, 2 accounts locked` |

**Not all alerts become incidents.** A large portion of alerts are false positives.
The analyst's job at triage is to determine:

1. Is this alert legitimate (not a false positive)?
1. If legitimate, does it represent a security incident?
1. If an incident, what type and severity?

---

## Part 2: NIST Incident Categories — Quick Reference

| Category | Key Question | Examples |
|----------|-------------|---------|
| Denial of Service | Is a service being made unavailable? | DDoS, resource exhaustion |
| Malicious Code | Is unauthorized software executing? | Malware, ransomware, spyware |
| Unauthorized Access | Is someone accessing something they shouldn't? | Exploitation, stolen creds, privilege escalation |
| Inappropriate Usage | Is an authorized user misusing access? | Data theft, policy violation |
| Multiple Components | Does this involve >1 category? | APT campaign |
| Investigation | Do I need more data to determine? | Anomaly requiring analysis |

---

## Part 3: Severity Assignment — Step by Step

### The Two-Factor Model

Severity is determined by two factors:

1. **Incident type** (what kind of attack?)
1. **Asset criticality** (what is being attacked?)

**Asset Criticality Reference:**

| Criticality | Examples |
|-------------|---------|
| CRITICAL | Domain Controllers, HSMs, SCADA/ICS, core routers, payment systems |
| HIGH | File servers, mail servers, HR systems, privileged workstations |
| MEDIUM | Standard servers, departmental systems, non-privileged workstations |
| LOW | Test systems, legacy isolated systems, non-production |

### Severity Matrix

```text
                    Asset Criticality
Incident Type      LOW   MEDIUM  HIGH  CRITICAL
─────────────────────────────────────────────────
Phishing (no exec) P5    P4      P4    P3
Phishing (exec)    P4    P3      P2    P1
Single malware     P4    P3      P2    P1
Lateral movement   P3    P2      P1    P1
Data exfiltration  P3    P2      P1    P1
Ransomware         P2    P1      P1    P1
Account compromise P4    P3      P2    P1
Brute force (fail) P5    P4      P3    P2
DDoS               P4    P3      P2    P1
Insider data theft P3    P2      P1    P1
```

### Worked Example

**Alert received:**

```text
SIEM Alert: Failed Kerberos pre-authentication (Event 4771)
User: svc_backup
Source IP: 192.168.10.55 (workstation)
Failed attempts: 847 in the last 2 hours
```

**Step 1: Category?**

* Category: Unauthorized Access (attempted)
* Sub-category: Brute force against service account

**Step 2: Asset criticality?**

* `svc_backup` is a service account used for backup operations on the domain controller
* Service accounts with domain access = HIGH criticality

**Step 3: Apply matrix**

* Brute force (failed) + HIGH asset = P3 (Medium)

**Step 4: Escalation factors?**

* 847 attempts suggests systematic attack, not noise
* Service account targeting = attacker may be targeting domain persistence
* → Consider upgrading to P2 based on escalation criteria

**Final classification:** P2 (High) — Account under active brute force, service account privilege, upgrade applied

---

## Part 4: Escalation Triggers to Know by Heart

Memorize these — they require immediate severity upgrade regardless of asset criticality:

1. **Lateral movement confirmed** — attacker is moving between systems → +1 severity
1. **Domain Admin or privileged account compromised** → immediate P1 review
1. **Ransomware deployment or encryption activity** → P1 always
1. **Active data exfiltration** → P1 if >1000 records, P2 if scope unknown
1. **C-suite or executive compromise** → P1 always
1. **SCADA/ICS or OT systems involved** → P1 always
1. **External notification (LE, CERT, partner)** → escalate to CISO immediately
1. **Evidence of APT or nation-state TTPs** → P1 immediately

---

## Part 5: Common Classification Mistakes

### Mistake 1: Classifying by tool, not behavior

Wrong: "This is just a port scan, P5."
Right: "This is reconnaissance from an IP that was also seen brute-forcing our VPN — P3."

Context matters.
The same event can have different classifications depending on what else you know.

### Mistake 2: Under-classifying because no data is confirmed stolen

Wrong: "The attacker was on the file server but we haven't confirmed exfiltration — P3."
Right: "Attacker on the file server with access to customer PII — P1 until exfil confirmed or ruled out."

Classify based on *potential* impact, not only *confirmed* impact.

### Mistake 3: Treating time of detection as time of compromise

An alert firing at 14:00 does not mean the incident started at 14:00.
Check for earlier signs of compromise.
Dwell time analysis may reveal the incident started days or weeks earlier.

### Mistake 4: Ignoring the second system

When you find one compromised host, look for others immediately.
Attackers rarely stay on one system.

### Mistake 5: Alert fatigue over-correction

After a period of many false positives, analysts sometimes become conditioned to dismiss alerts quickly.
Maintain discipline: every alert deserves a triage decision documented with reasoning.

---

## Quick Reference Card

```text
┌─────────────────────────────────────────────────────────────────┐
│           INCIDENT CLASSIFICATION QUICK REFERENCE              │
├─────────────────────────────────────────────────────────────────┤
│  Step 1: Is this a real incident or a false positive?           │
│    → Validate: check raw logs, corroborate with other sources   │
├─────────────────────────────────────────────────────────────────┤
│  Step 2: What CATEGORY is it?                                   │
│    Denial of Service | Malicious Code | Unauthorized Access     │
│    Inappropriate Usage | Multiple Components | Investigation    │
├─────────────────────────────────────────────────────────────────┤
│  Step 3: What is the ASSET CRITICALITY?                         │
│    CRITICAL | HIGH | MEDIUM | LOW                               │
├─────────────────────────────────────────────────────────────────┤
│  Step 4: Apply the SEVERITY MATRIX → P1/P2/P3/P4/P5            │
├─────────────────────────────────────────────────────────────────┤
│  Step 5: Check ESCALATION TRIGGERS — upgrade if any match      │
│    • Lateral movement   • Ransomware   • DA compromise          │
│    • Data exfiltration  • APT TTPs     • External notification  │
├─────────────────────────────────────────────────────────────────┤
│  Step 6: DOCUMENT in ticket immediately                         │
└─────────────────────────────────────────────────────────────────┘
```
