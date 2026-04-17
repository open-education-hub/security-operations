# Drill 02 Solution: Evidence Collection Checklist

---

## Scenario A Solution: The Active Intruder

### Task A1 — Correct Collection Order

```text
Priority  Evidence                              Why
────────────────────────────────────────────────────────────────────────────
  1       Clipboard contents                    Most volatile — cleared instantly
  2       Active network connections (netstat)  Changes with each command attacker runs
  3       List of running processes             Attacker may terminate malicious process
  4       ARP cache                             Cleared on reboot, updated frequently
  5       Memory dump of the system             Contains everything in RAM — C2 session,
                                                malware code, credentials in memory
  6       Screenshot of EDR console             Current state of visible attack
  7       Windows Event Log export              Less volatile — logs rotate but persist
  8       Contents of Downloads folder          Survives reboot — not time-critical
  9       List of installed programs            Survives reboot — not time-critical
  10      Full disk image of C: drive           Most persistent, most time-consuming
```

**Key principle:** RAM and network state are lost on power-off or isolation.
Disk images can be taken anytime.

### Task A2 — What is Lost if Powered Off

If the system is powered off:

* **Memory contents** (RAM dump cannot be taken) — this contains the malware code, C2 connection keys, any credentials the malware accessed, and the attacker's current shell session
* **Active network connections** — the C2 IP may not be recoverable if the malware uses domain fronting or ephemeral IPs
* **Clipboard contents** — any data the attacker recently copied
* **Running processes** — the malicious process is gone; its command line arguments are gone unless logged by Sysmon
* **ARP cache** — may contain evidence of lateral movement reconnaissance

### Task A3 — Most Important Pre-Decision Information

The most critical piece of information before deciding to isolate or observe is:

**Is active data exfiltration occurring?**

Check: Is there a large outbound transfer in progress from this host?

* If yes: Isolate immediately — data loss outweighs intelligence value of observation
* If no active exfiltration: You can afford minutes to collect volatile evidence before isolation

Secondary check: Has the attacker discovered they are being watched?
(unlikely, but if an attacker triggers EDR and then immediately starts clearing logs or exfiltrating, they may know)

---

## Scenario B Solution: Chain of Custody Errors

**Error 1: Saving process output to the server itself**

Line: "Ran 'ps aux' and saved output to notepad.exe on the server itself"
Problem: Writing to the live system modifies file metadata (access times, write times).
This contaminates the evidence and may overwrite deleted data in slack space.
A forensically sound method saves output to external media.
Correct: Save to an external write-once drive or SFTP to an evidence collection server.
Use `ps aux > /mnt/usb/processes.txt`.

---

**Error 2: Using notepad.exe as an evidence container**

Line: "saved output to notepad.exe on the server itself"
Problem: Notepad files are not forensically sound containers.
They may be modified, lack metadata about when data was captured, and lack integrity verification.
Correct: Use a dedicated forensic tool (FTK Imager, AVML, dcfldd) that generates hashes during collection.

---

**Error 3: Hash computed after copying to USB — not at collection**

Line: "realized I should hash it.
Computed MD5 of the notepad file"
Problem: The hash was computed AFTER the file was copied to USB, not at the source.
If the file was modified during the copy, the hash won't detect it.
Also, MD5 alone is insufficient.
Correct: Compute SHA-256 of the file immediately after creation at the source.
Verify hash after copy: source hash == copy hash.

---

**Error 4: Using MD5 only**

Line: "Computed MD5 of the notepad file"
Problem: MD5 is cryptographically broken and not sufficient for legal proceedings.
Correct: Use SHA-256 (minimum) or SHA-256 + SHA-1 for legacy compatibility.

---

**Error 5: Manually copying event log entries into a Word document**

Line: "copying relevant events manually into a Word document"
Problem: Manual transcription introduces human error.
Filtering "the last hour" loses context.
Word document has no provenance.
Correct: Export the full event log using `wevtutil export-log Security C:\path\Security.evtx`, then hash the exported file.
Never filter or edit evidence.

---

**Error 6: Discussing the incident with an unauthorized colleague**

Line: "Colleague walked by and asked what I was doing — explained the full incident details."
Problem: Incident details should be communicated on a need-to-know basis.
Discussing openly in a server room may alert the suspect (if it's an insider threat), compromise the investigation, or create unauthorized parties who have access to evidence.
Correct: "I'm working on an authorized IT investigation — I can't discuss the details.
Please direct any questions to the SOC manager."

---

**Error 7: Leaving the server room unlocked**

Line: "Left the server room, forgot to lock it behind me."
Problem: Unattended, unsecured evidence is inadmissible.
Chain of custody requires physical security of evidence at all times.
Correct: Never leave evidence unattended.
If you must leave, secure the room or have another authorized person remain.

---

**Error 8: Sharing evidence via email without hash verification**

Line: "shared the USB contents via email to three team members"
Problem: Email is not a secure evidence sharing method.
Files can be modified in transit or on email servers.
No hash verification means tampering cannot be detected.
No transfer log means the chain of custody is broken.
Correct: Transfer evidence through a secure, audited platform (SFTP, encrypted case management system).
Record each transfer in the chain of custody transfer log.
Send hash values in a separate communication for verification.

---

## Scenario C Solution: Completed Chain of Custody Form

```text
═══════════════════════════════════════════════════════════════
                    CHAIN OF CUSTODY RECORD
═══════════════════════════════════════════════════════════════

Case Number:        CASE-2024-089
Incident Ticket:    INC-2024-1201
Exhibit Number:     E-001

EVIDENCE DESCRIPTION
────────────────────────────────────────────────────────────────
Description:        Memory dump from server PAY-SRV-02, captured
                    during incident INC-2024-1201 investigation.
                    File: PAY-SRV-02-memory-20241120.lime (64 GB)
Make/Model (device):Dell PowerEdge R540
Serial Number (device): SVR20240078
Asset Tag:          PAY-SRV-02
Storage Medium:     Western Digital 2TB USB Drive
Storage Serial:     WD20PASS123456
File collected:     PAY-SRV-02-memory-20241120.lime
File size:          64 GB (68,719,476,736 bytes)

COLLECTION DETAILS
────────────────────────────────────────────────────────────────
Collected by:       Maria Santos
  Badge/ID:         SOC-7823
Collection date:    2024-11-20
Collection time:    09:15 UTC
Collection method:  avml (memory acquisition tool) executed on live
                    system. Server remained running during acquisition.
                    System not powered off — volatile state preserved.

INTEGRITY VERIFICATION
────────────────────────────────────────────────────────────────
MD5 Hash:           f1e2d3c4b5a69788c7d6e5f4a3b2c1d0
SHA-256 Hash:       3b4c9e2f1a8d7e6f5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2
Hash computed at:   2024-11-20 09:48 UTC (immediately after collection completed)
Hash computed by:   Maria Santos (SOC-7823)

TRANSFER LOG
────────────────────────────────────────────────────────────────
Date/Time          │ Released By        │ Received By         │ Reason            │ Sig
───────────────────┼────────────────────┼─────────────────────┼───────────────────┼─────
2024-11-20 10:30   │ M. Santos (SOC-7823)│ D. Park (EC-1042) │ Initial storage   │ [sig]

═══════════════════════════════════════════════════════════════
```

### Marking notes:

* Award 1 point for each of: Case Number, Incident Ticket, Exhibit Number, full description, device serial, USB serial, collection time (UTC), collection method detail, SHA-256 hash, transfer log with correct personnel and timestamp
* Deduct 0.5 if Case Number is missing (can be any reasonable format — INC-2024-1201 would also be acceptable if used for Case Number)
