# Demo 03: Alert Triage in Practice

## Overview

This demo walks through real-world alert triage using a set of pre-generated alerts from a simulated environment.
Students learn to distinguish true positives from false positives and apply a severity classification system.

**Duration:** ~20 minutes

**Platform:** Any (browser-based exercise)

**Difficulty:** Beginner

## Objectives

* Apply the P1/P2/P3/P4 severity classification to alerts.
* Identify false positives using context.
* Practice writing triage notes.
* Understand escalation criteria.

## Alert Queue Exercise

Below is a realistic alert queue.
For each alert, students must:

1. Classify the severity (Critical / High / Medium / Low).
1. Determine: True Positive, False Positive, or Needs Investigation.
1. Write a one-line triage note.
1. Decide: Close, Monitor, or Escalate.

---

### Alert #1

```text
Alert ID:    ALT-001
Time:        2024-01-15 14:32:00
Rule:        Antivirus Detection - EICAR Test File
Source:      Endpoint: WIN-DEV-042
User:        it_support
Description: AV detected EICAR test file in C:\Users\it_support\Downloads\eicar.com
Severity:    High (automated)
```

**Instructor hint:** EICAR is a standard antivirus test file used by IT to verify AV is working.
This is almost certainly a false positive.

---

### Alert #2

```text
Alert ID:    ALT-002
Time:        2024-01-15 02:11:00
Rule:        Multiple Failed Logins - Admin Account
Source:      Active Directory
User:        administrator
Description: 47 failed login attempts for 'administrator' from 10.5.5.200 over 3 minutes
Severity:    High (automated)
```

**Instructor hint:** 47 attempts in 3 minutes is brute force. 10.5.5.200 is an internal IP — check if it's a legitimate system (e.g., a scanner or test tool).
Either way, investigate.

---

### Alert #3

```text
Alert ID:    ALT-003
Time:        2024-01-15 09:00:15
Rule:        USB Device Connected
Source:      Endpoint: LAPTOP-HR-005
User:        hr_mary
Description: USB storage device inserted. 2GB Kingston DataTraveler
Severity:    Medium (automated)
```

**Instructor hint:** USB events are common in HR departments (transferring resumes, etc.).
Check company policy.
If USB storage is not allowed, this is a policy violation.
If allowed, it's likely a false positive.

---

### Alert #4

```text
Alert ID:    ALT-004
Time:        2024-01-15 11:45:00
Rule:        DNS Query to Known Malware Domain
Source:      DNS Server
User:        (resolves to machine WKSTN-FIN-012)
Description: DNS query for c2.evil-domain-123.ru (known C2 server per threat intel feed)
Severity:    Critical (automated)
```

**Instructor hint:** This is almost certainly a true positive.
DNS queries to known C2 domains are a strong indicator of compromise.
The machine should be isolated immediately.

---

### Alert #5

```text
Alert ID:    ALT-005
Time:        2024-01-15 16:00:00
Rule:        Large Data Transfer Outbound
Source:      Firewall
User:        N/A (IP: 172.16.0.25)
Description: 4.7GB transferred to 34.120.0.0/24 (Google Cloud) over 30 minutes
Severity:    High (automated)
```

**Instructor hint:** Google Cloud is used by many legitimate services (Google Drive, GCP).
Check if the destination IP belongs to a company-sanctioned service.
Check if 172.16.0.25 is a backup server.
If it's a user workstation, escalate.

---

## Triage Answer Sheet

| Alert | True/False/Needs Inv. | Severity | Action | Notes |
|-------|----------------------|----------|--------|-------|
| ALT-001 | False Positive | Low | Close | EICAR test file used by IT support |
| ALT-002 | Needs Investigation | High | Escalate | Brute force from internal IP — check if scanner |
| ALT-003 | Needs Investigation | Low | Monitor | Check USB policy; likely benign |
| ALT-004 | True Positive | Critical | Escalate | C2 DNS query — isolate WKSTN-FIN-012 immediately |
| ALT-005 | Needs Investigation | Medium | Investigate | Verify if Google Cloud destination is authorized |

## Key Takeaways

* **Context is everything**: the same alert can be critical or benign depending on context.
* **False positive rate management**: tuning alerts to reduce noise is a key SOC function.
* **Speed + accuracy**: triage must be fast enough to catch active threats but accurate enough to avoid over-escalation.
* **Documentation**: every decision should be documented even if the alert is closed.
