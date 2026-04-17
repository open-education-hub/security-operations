# Drill 02 (Intermediate): Ransomware Incident Response

## Scenario

MediCorp (healthcare, 2,000 employees) — it is Saturday 07:00.
The on-call analyst gets an alert: 5 workstations in the radiology department are encrypting files.
Ransom note reads "LOCKBIT3.0 — YOUR NETWORK IS ENCRYPTED".

By 07:15, the number is 23 workstations.
The radiology PACS system (medical imaging, 2.8 TB of patient images) is showing encryption activity.

## Timeline of Known Events

```text
Fri 23:30 - Domain admin account "svc-backup" logs in from unusual IP
Fri 23:45 - PsExec used to deploy files to 8 workstations
Sat 00:20 - WMI used to disable Windows Defender on 8 workstations
Sat 00:45 - Encryption binary deployed to C:\Windows\Temp on 8 workstations
Sat 06:45 - Encryption triggered (possibly timed)
Sat 07:00 - First EDR alert
```

## Available Information

* MediCorp uses CrowdStrike Falcon (EDR) on all workstations
* No EDR on legacy medical devices (PACS system runs on Windows Server 2008)
* Backups: daily backups to NAS. Last backup: Friday 22:00
* PACS backup: weekly, last Saturday. Current backups also show encryption activity.
* IT emergency contact: IT Manager (personal cell)
* Legal counsel available 24/7

## Objectives

### Part A: Immediate Response (30 min)

You are the on-call analyst.
It is 07:00.
Describe, minute-by-minute, what you do in the first 60 minutes.

Your response must:

1. Address what you do in the first 5 minutes
1. Identify who you call and when
1. Address the PACS system (no EDR, legacy OS)
1. Address the Friday 23:30 admin login (how does this change your response?)
1. Address the backup situation

### Part B: Scope Assessment (20 min)

After 60 minutes, you have partial information.
Answer:

1. What is the true scope of the encryption? (What data is at risk?)
1. What is the earliest possible recovery scenario? (What's recoverable?)
1. Is this a ransomware-only incident or is there exfiltration evidence you should look for?
1. What is the regulatory timeline? (GDPR, NIS2 — MediCorp is an essential entity)

### Part C: Post-Incident Analysis (15 min)

After recovery, conduct the root cause analysis:

1. How did the attacker initially access the network?
1. Why was `svc-backup` compromised? What makes service accounts high-value targets?
1. Why wasn't the Friday 23:30 login detected and alerted?
1. Write 3 action items to prevent recurrence

## Hints

* The Friday timeline shows 7+ hours of undetected attacker activity. This is the key root cause question.
* PACS = Patient Archives and Communication System. Contains patient medical images. This is special category data under GDPR Art. 9.
* `svc-backup` was used with PsExec — this suggests the account's credentials were compromised or the attacker has elevated privileges.
* The backup NAS showing encryption activity is catastrophic for recovery. Why would a ransomware attacker target backups?
* NIS2 requires 24-hour early warning for essential entities like hospitals.
