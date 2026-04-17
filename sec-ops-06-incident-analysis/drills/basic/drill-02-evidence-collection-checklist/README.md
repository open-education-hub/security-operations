# Drill 02 (Basic): Evidence Collection Checklist Exercise

**Level:** Basic

**Time:** 25 minutes
**No lab environment required**

---

## Instructions

Three scenarios are described below.
For each scenario:

1. Determine **which type of evidence** is most critical to collect
1. Determine the **correct collection order** for the evidence listed
1. Identify any **chain of custody errors** in the described collection process
1. Complete the **chain of custody form** for Scenario C

Solutions are in `solutions/drill-02-solution/README.md`.

---

## Scenario A: The Active Intruder

**Situation:**
At 14:32 UTC, a SOC analyst confirms active malicious activity on `FINANCE-WS-03`.
The EDR shows a reverse shell process connected to an external IP.
The analyst can see the attacker is still actively running commands — they have not been detected by the attacker.

**Available evidence to collect (in no particular order):**

```text
[ ] Full disk image of C: drive
[ ] Screenshot of the EDR console showing active connection
[ ] Memory dump of the system
[ ] Windows Event Log export from FINANCE-WS-03
[ ] List of running processes (ps aux or tasklist)
[ ] Active network connections (netstat output)
[ ] Contents of the user's Downloads folder
[ ] Current user's clipboard contents
[ ] ARP cache
[ ] List of installed programs
```

**Task A1:** Order these from **most urgent to collect first** to **least urgent**.

**Task A2:** The analyst decides to power off the system immediately to stop the attack.
What critical evidence is lost?
**Task A3:** What is the ONE most important piece of information to capture before deciding whether to isolate or observe the system?

---

## Scenario B: The Chain of Custody Errors

**Situation:**
An analyst collected evidence from a compromised server.
Here is their notes log:

```text
Evidence Collection Log — Analyst: Tom Bradley — 2024-11-15
─────────────────────────────────────────────────────────────
13:45  Arrived at server room. Started collecting evidence.
13:47  Ran 'ps aux' and saved output to notepad.exe on the server itself.
13:51  Ran 'netstat -ano' and saved to the same notepad file on the server.
13:55  Copied the notepad file to my personal USB drive.
13:58  Saved the running process list — realized I should hash it.
       Computed MD5 of the notepad file: a1b2c3d4e5f6...
14:02  Exported Windows event logs by opening Event Viewer,
       filtering for the last hour, and copying relevant events
       manually into a Word document.
14:15  Colleague walked by and asked what I was doing — explained
       the full incident details.
14:20  Left the server room, forgot to lock it behind me.
14:35  Returned to my desk and shared the USB contents via email
       to three team members for analysis.
14:50  Realized I should document who has a copy — sent a follow-up
       email to track recipients.
```

**Task B:** Identify ALL chain of custody errors in this log.
There are at least 7.
For each error: name the error, explain why it is a problem, and describe the correct procedure.

---

## Scenario C: Complete the Chain of Custody Form

**Situation:**
You are Analyst Maria Santos (badge: SOC-7823).
At 09:15 UTC on 2024-11-20, you collected a memory dump from a compromised server (`PAY-SRV-02`, IP: 10.0.2.15, Dell PowerEdge R540, serial number: SVR20240078) as part of incident INC-2024-1201.

You used `avml` to capture the memory to a USB drive (Western Digital 2TB USB, serial number: WD20PASS123456).
The memory dump file is named `PAY-SRV-02-memory-20241120.lime` and is 64 GB in size.

After capturing the memory, you computed the following hashes:

* MD5: `f1e2d3c4b5a69788c7d6e5f4a3b2c1d0`
* SHA-256: `3b4c9e2f1a8d7e6f5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2`

At 10:30 UTC, you transferred the USB to the Evidence Room (signed in by Evidence Custodian Derek Park, badge: EC-1042).

**Task C:** Complete the chain of custody form below with this information.

```text
═══════════════════════════════════════════════════════════════
                    CHAIN OF CUSTODY RECORD
═══════════════════════════════════════════════════════════════

Case Number:        _______________
Incident Ticket:    _______________
Exhibit Number:     _______________

EVIDENCE DESCRIPTION
────────────────────────────────────────────────────────────────
Description:        _______________________________________________
Make/Model (device): ______________________________________________
Serial Number (device): ___________________________________________
Asset Tag:          _______________________________________________
Storage Medium:     _______________________________________________
Storage Serial:     _______________________________________________
File collected:     _______________________________________________
File size:          _______________________________________________

COLLECTION DETAILS
────────────────────────────────────────────────────────────────
Collected by:       _______________________________________________
  Badge/ID:         _______________________________________________
Collection date:    _______________________________________________
Collection time:    _______________ (UTC)
Collection method:  _______________________________________________

INTEGRITY VERIFICATION
────────────────────────────────────────────────────────────────
MD5 Hash:           _______________________________________________
SHA-256 Hash:       _______________________________________________
Hash computed at:   _______________________________________________
Hash computed by:   _______________________________________________

TRANSFER LOG
────────────────────────────────────────────────────────────────
Date/Time    │ Released By     │ Received By     │ Reason         │ Sig
─────────────┼─────────────────┼─────────────────┼────────────────┼────
             │                 │                 │                │

═══════════════════════════════════════════════════════════════
```

---

## Scoring

* **Scenario A:** 5 points (1 per correct ordering decision, 2 for power-off consequence, 2 for key info question)
* **Scenario B:** 7 points (1 per correctly identified error with explanation)
* **Scenario C:** 8 points (1 per correctly completed field)
