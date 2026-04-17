# Drill 02 (Intermediate) — Ransomware Incident Response

**Estimated time:** 65 minutes

**Difficulty:** Intermediate

**Prerequisites:** Completion of basic drills; understanding of ransomware mechanics, GDPR, NIS2

---

## Scenario

**MediCorp** is a private healthcare provider operating 3 hospitals and 12 outpatient clinics across Germany (2,000 employees, 180,000 patient records).
It is **Saturday 07:00 CET**.

You are the on-call security analyst.
Your phone rings — the IT night shift reports that 5 workstations in the radiology department are encrypting files.
By the time you arrive at your laptop, you receive another alert: 23 workstations are now encrypting.
The ransom note reads:

```text
LOCKBIT3.0 — YOUR NETWORK IS ENCRYPTED
Your data has been exfiltrated. Pay within 72 hours or data will be published.
Contact: [.onion address]
Bitcoin amount: 45 BTC (~€1.8M at current rate)
```

---

## Known Timeline (From Log Analysis)

```text
Friday 23:30 — Domain admin account "svc-backup" logs in from unusual IP (185.220.x.x — Tor exit node)
Friday 23:45 — PsExec used to deploy files to 8 workstations (staging)
Saturday 00:20 — WMI used to disable Windows Defender on 8 workstations
Saturday 00:45 — Encryption binary deployed to C:\Windows\Temp on 8+ workstations
Saturday 06:45 — Encryption triggered (timed execution)
Saturday 07:00 — First EDR alert (CrowdStrike) — too late; encryption already spreading
```

---

## Environment Information

| Item | Details |
|------|---------|
| EDR | CrowdStrike Falcon on all workstations |
| Legacy systems | PACS (radiology imaging) runs on Windows Server 2008 — **NO EDR** |
| PACS data | 2.8 TB of patient medical images (DICOM format) — **special category data, GDPR Art. 9** |
| Daily backup | NAS (last backup: Friday 22:00 — 1 hour before the attack began) |
| PACS backup | Weekly, last Saturday. Current backup NAS also shows encryption activity. |
| Regulatory | MediCorp = **essential entity** under NIS2 (healthcare sector) |
| Contact | IT Manager (mobile, available 24/7); Legal counsel (on-call) |

---

## Tasks

### Part A: Immediate Response — First 60 Minutes (30 minutes)

You are the on-call analyst.
It is 07:00 Saturday.
Describe exactly what you do in the first 60 minutes.
Your answer must be structured as a **minute-by-minute plan** covering:

1. **First 5 minutes** — what three actions do you take before anything else?
1. **Who do you call, and in what order?** Include what you tell each person.
1. **The PACS system** — it is encrypting and has no EDR. How do you handle a legacy system with no endpoint agent?
1. **The Friday 23:30 login** — this changes the scope of the incident dramatically. How does this affect your response? What does it mean that the attacker used a Tor exit node with a domain admin account?
1. **The backup situation** — the daily NAS is showing encryption activity. What does this mean for recovery? What do you do about it?

---

### Part B: Scope and Recovery Assessment (20 minutes)

After 60 minutes of response, you have partial information.
Answer:

1. **True scope of encryption:** Based on the timeline and environment, what data categories are at risk? Categorize by: (a) operational impact and (b) GDPR/regulatory impact.

1. **Earliest recovery scenario:** What is the most optimistic recovery scenario given the backup situation? What is the most realistic scenario? Be specific about what can and cannot be recovered.

1. **Exfiltration assessment:** The ransom note claims data was exfiltrated. Given the Friday timeline, should you treat this as:
   * (a) Likely bluff — typical LockBit3.0 tactic
   * (b) Possible — investigate before deciding
   * (c) Confirmed — prepare for data breach notification

   Justify your choice and describe how you would investigate the exfiltration claim.

1. **Regulatory timeline:** Map out ALL regulatory notification obligations and deadlines for MediCorp. Include: GDPR, NIS2, and any German sector-specific requirements (BSI, BfDI).

---

### Part C: Post-Incident Analysis (15 minutes)

Three weeks after recovery, you facilitate the lessons-learned session.
Answer:

1. **Initial access:** How did the attacker initially compromise the `svc-backup` domain admin account? What are the most likely vectors given the evidence (Tor exit node at 23:30)?

1. **Service account risk:** Why are service accounts like `svc-backup` high-value targets for ransomware operators? What specific properties make them dangerous?

1. **Detection failure:** The attacker had 7+ hours of undetected access (23:30 Friday to 07:00 Saturday). Why wasn't the Friday 23:30 login detected and alerted? What monitoring controls were missing?

1. **Action items:** Write exactly 3 prioritized action items to prevent a recurrence. Each action item must include: what to do, who is responsible, and a target completion date (relative to the incident).

---

## Hints

* The Friday timeline shows 7+ hours of undetected attacker activity — this is the key root cause problem
* `svc-backup` used with PsExec means the attacker had the plaintext or hash of that account's password — how?
* PACS = Picture Archiving and Communication System — contains patient medical images (MRI, X-ray, CT). This is **special category data** under GDPR Art. 9 requiring enhanced protection
* The backup NAS showing encryption activity is catastrophic — why would a ransomware operator specifically target backups?
* NIS2 requires a **24-hour early warning** to the national authority (Germany: BSI) for essential entities in healthcare
* Germany's BfDI is the federal DPA — but hospital data protection may involve the relevant Landesdatenschutzbehörde (state DPA)
* "Domain admin" account in a backup service account is itself a security failure — principle of least privilege violation
