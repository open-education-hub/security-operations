# Solution: Drill 02 — Containment Checklists

## Checklist 1: Ransomware Containment

| Step | Action | Rationale | Owner |
|------|--------|-----------|-------|
| 1 | Capture volatile evidence (network connections, processes, open files) and hash outputs | Volatile evidence is lost after isolation/shutdown. Legal requirement. | L2 Analyst |
| 2 | Acquire memory image (DumpIt, winpmem) before any shutdown | Memory contains active malware, injected code, and C2 connections | L2 Analyst |
| 3 | Isolate affected host(s) via EDR network containment | Stop C2 communication and prevent lateral spread. EDR isolation preserves investigation access. | L2 Analyst |
| 4 | [APPROVAL GATE] Confirm isolation with IR Manager before proceeding to step 5 | Prevents cascading problems if additional context changes the strategy | IR Manager |
| 5 | Identify all hosts connected to affected host in past 24 hours (SIEM query) | Assess potential spread before it becomes ransomware-wide encryption | L2 Analyst |
| 6 | Check backup server status — isolate if encryption activity detected | Ransomware specifically targets backups. Loss of backups = no recovery option | IT + L2 |
| 7 | Block known ransomware C2 IP/domain at perimeter firewall and DNS | Prevent other infected hosts (if any) from calling home | IT/Network |
| 8 | Preserve log data from the time window (export from SIEM, ensure no log rotation) | Logs may be overwritten. Need for investigation and regulatory filing. | L2 Analyst |
| 9 | Assess scope: how many systems affected? What data was at risk? | Drives GDPR/regulatory notification decision | IR Manager |
| 10 | If patient/personal data at risk → engage Legal for GDPR assessment | 72h clock started at step 1 | IR Manager → Legal |

---

## Checklist 2: Compromised Credential Containment

| Step | Action | Rationale | Owner |
|------|--------|-----------|-------|
| 1 | Export authentication logs for the compromised account (last 30 days) | Preserve before any account changes that might affect log context | L2 Analyst |
| 2 | Identify all active sessions for the compromised user (AD, VPN, M365, SAML) | Can't revoke what you don't know about | L2 Analyst |
| 3 | Revoke all active sessions and refresh tokens (Azure AD / M365) | Password reset alone doesn't end existing sessions | IT (with L2 guidance) |
| 4 | [APPROVAL GATE] Confirm with manager before disabling a high-privilege account | Disabling a service account or admin may have immediate business impact | IR Manager |
| 5 | Disable the compromised account in Active Directory | Block new logins from the compromised credential | IT |
| 6 | Force password reset on all systems that use shared credentials | Credential reuse means one breach = multiple access points | IT |
| 7 | Revoke VPN certificates or MFA tokens if applicable | MFA bypass / session persistence may remain even after password reset | IT |
| 8 | Notify the affected user's manager and HR | Legal/HR need to know in case of insider threat implications | IR Manager |
| 9 | Preserve evidence of what was accessed (SIEM queries on user activity) | Chain of custody for potential HR or legal proceedings | L2 Analyst |
| 10 | Assess whether attacker created additional backdoor accounts | Attackers commonly create admin accounts for persistence | L2 Analyst |

---

## Checklist 3: Data Exfiltration Containment

| Step | Action | Rationale | Owner |
|------|--------|-----------|-------|
| 1 | Confirm exfiltration is real: verify data volume, destination, and data type | Avoid blocking legitimate transfers (backup, sync) | L2 Analyst |
| 2 | Capture current network flow/connection state | Volatile evidence of active exfiltration. What is being sent RIGHT NOW? | L2 Analyst |
| 3 | Begin monitoring/capture of exfiltration channel (5–15 min passive monitoring) | Understanding WHAT is being exfiltrated is essential for GDPR assessment | L2 Analyst |
| 4 | Identify the data classification of what is being exfiltrated | Does this trigger GDPR? Financial reporting requirements? PCI? | IR Manager + Legal |
| 5 | [APPROVAL GATE] Engage legal before blocking if possible (5 min delay max) | Legal determines notification requirements. Brief pause enables this. | IR Manager |
| 6 | Block the exfiltration channel (firewall rule, DLP block, account disable) | Stop the bleeding. Even if incomplete, limit total exposure. | IT/Network |
| 7 | Isolate the source system if attacker access is confirmed | Prevent the attacker from pivoting to new exfiltration channels | L2 Analyst |
| 8 | Preserve all evidence of what was accessed and exfiltrated | Required for notification letters to individuals and regulators | L2 Analyst |
| 9 | Initiate GDPR assessment immediately if personal data was involved | 72h clock has started. Do not wait for full investigation. | Legal |
| 10 | Search for additional exfiltration channels (DNS, HTTPS, email, USB) | Sophisticated attackers use multiple exfil paths | L2 Analyst |
