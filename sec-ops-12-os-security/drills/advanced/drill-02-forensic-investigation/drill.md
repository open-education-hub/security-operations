# Drill 02 (Advanced) — Forensic Investigation

## Scenario

You are a digital forensics investigator at **ClearPath Forensics**, engaged by **Atlas Manufacturing** following a suspected insider threat and data exfiltration incident.
The subject is `mkumar` (Michael Kumar), a former Senior System Administrator who resigned two weeks ago.
His access was revoked at resignation, but:

1. The IT security team found an unknown USB device plugged into **SRV-BUILD-02** (Ubuntu 22.04 build server) three days after his access was revoked
1. Logs show an SSH connection from an IP registered to a VPN provider at 02:14 UTC — 11 days after revocation
1. A large archive file (`build_artifacts_export.tar.gz`, ~2.1 GB) was created and then deleted from `/home/mkumar/`
1. The HR team reports that mkumar had access to source code repositories, CI/CD pipelines, and deployment keys

**Your mission:** Conduct a forensic investigation of the acquired disk image and memory snapshot artifacts to:

1. Establish a timeline of unauthorized activity
1. Identify what data was accessed or exfiltrated
1. Determine how access was maintained after revocation
1. Produce a forensic report suitable for use in legal proceedings

**Estimated time:** 90–120 minutes

**Difficulty:** Advanced

**Prerequisites:** Intermediate drills completed; familiarity with Volatility, timeline analysis, deleted file recovery concepts, and chain of custody principles.

---

## Legal / Chain of Custody Note

In a real investigation, you must:

* Document acquisition hash (MD5/SHA256) before and after imaging
* Use write blockers for physical media
* Never work on the original — always on a verified copy
* Document every action with timestamps
* Maintain an evidence log

For this drill, evidence is pre-acquired.
The SHA256 of each evidence package is provided in `/forensics/evidence/hashes.txt`.

---

## Environment Setup

```console
docker compose up -d
docker exec -it forensics-lab bash

# Verify evidence integrity
cat /forensics/evidence/hashes.txt
sha256sum /forensics/evidence/*.img /forensics/evidence/*.mem 2>/dev/null || \
    sha256sum /forensics/evidence/*.json 2>/dev/null

# Load analysis helpers
python3 /forensics/scripts/load-tools.py
```

---

## Evidence Package

| Artifact | Location | Description |
|----------|----------|-------------|
| Disk image (simulated) | `/forensics/evidence/disk_timeline.json` | MFT/ext4 timeline from `mkumar`'s home and system paths |
| Memory snapshot (simulated) | `/forensics/evidence/memory_snapshot.json` | Process list, network connections, open files at collection time |
| Auth log | `/forensics/evidence/auth.log` | SSH + sudo activity |
| Bash history | `/forensics/evidence/bash_history` | mkumar's bash history |
| auditd log | `/forensics/evidence/audit.log` | syscall-level audit trail |
| USB device log | `/forensics/evidence/usb_events.log` | udev/dmesg USB events |
| Network captures | `/forensics/evidence/netflow.json` | Outbound connection summaries (not full pcap) |
| Deleted file metadata | `/forensics/evidence/deleted_files.json` | Recovered inode metadata from deleted entries |
| SSH known_hosts | `/forensics/evidence/ssh_known_hosts` | mkumar's known_hosts file |
| Crontab | `/forensics/evidence/mkumar_crontab` | mkumar's crontab at time of collection |
| /proc snapshot | `/forensics/evidence/proc_snapshot.json` | Process tree snapshot |

---

## Tasks

### Task 1: Evidence Integrity and Initial Triage

```console
# Verify hashes
cat /forensics/evidence/hashes.txt
sha256sum /forensics/evidence/*.json /forensics/evidence/*.log

# Review collection metadata
cat /forensics/evidence/collection_metadata.txt

# Quick disk timeline scan
python3 /forensics/scripts/timeline.py --summary
```

**Questions:**

1. Are all evidence hash values consistent? (Document any discrepancies)
1. What is the collection date and time? What is the time delta between the alleged incident and collection?
1. What were the 10 most recently modified files in mkumar's home directory?
1. Are there any files with suspicious timestamps (e.g., timestomped — created after last access)?

---

### Task 2: Unauthorized Access — How Did mkumar Return?

```bash
# SSH authentication events
grep -E "(Accepted|Failed|Invalid)" /forensics/evidence/auth.log

# Check for SSH keys
python3 /forensics/scripts/timeline.py --path "/home/mkumar/.ssh"
python3 /forensics/scripts/timeline.py --path "/root/.ssh"

# Check authorized_keys
cat /forensics/evidence/authorized_keys_mkumar
cat /forensics/evidence/authorized_keys_root

# Examine crontab for persistence
cat /forensics/evidence/mkumar_crontab
```

**Questions:**

1. From which IP did the unauthorized SSH connection originate? What is notable about this IP?
1. What authentication method was used (password vs key)? If key-based, is the key still in authorized_keys?
1. Was mkumar's account still active when the SSH connection occurred? (Check `/etc/passwd` and `/etc/shadow` entries)
1. Was any backdoor persistence left? (Cron, additional SSH keys, other accounts)

---

### Task 3: Activity Reconstruction — What Was Done?

```console
# Bash history analysis
cat /forensics/evidence/bash_history

# Auditd analysis — file access
grep "type=OPEN\|type=EXECVE" /forensics/evidence/audit.log | grep "mkumar\|uid=1001"

# File creation/modification timeline
python3 /forensics/scripts/timeline.py --user mkumar --window "2024-01-04T02:00:00,2024-01-04T04:00:00"

# Large file detection
python3 /forensics/scripts/timeline.py --size-gt 100000000
```

**Questions:**

1. What commands did mkumar run during the unauthorized session?
1. What directories/repositories were accessed?
1. What is the evidence for data staging (collecting data for exfiltration)?
1. Was any tool downloaded or installed during the session?

---

### Task 4: Data Exfiltration Analysis

```bash
# Deleted file analysis
python3 /forensics/scripts/deleted.py --list
python3 /forensics/scripts/deleted.py --details build_artifacts_export.tar.gz

# Network flow analysis
python3 /forensics/scripts/netflow.py --summary
python3 /forensics/scripts/netflow.py --during "2024-01-04T02:00:00,2024-01-04T04:00:00"

# USB device analysis
cat /forensics/evidence/usb_events.log
python3 /forensics/scripts/usb.py --list
```

**Questions:**

1. What was in `build_artifacts_export.tar.gz`? (Use deleted file metadata to reconstruct)
1. When was it created and when was it deleted?
1. Was the file copied to the USB device or exfiltrated over the network (or both)?
1. What is the estimated size of data exfiltrated? From what source directories?
1. Can you determine the destination of the exfiltration (IP address, USB device identifier)?

---

### Task 5: Memory Forensics

```bash
# Process analysis
python3 /forensics/scripts/memory.py --processes
python3 /forensics/scripts/memory.py --network-connections
python3 /forensics/scripts/memory.py --open-files

# Look for suspicious injected code / hidden processes
python3 /forensics/scripts/memory.py --suspicious

# Extract command-line arguments from processes
python3 /forensics/scripts/memory.py --cmdline
```

**Questions:**

1. Were any processes running at collection time that were not expected on a build server?
1. Were there any network connections to unusual destinations?
1. Were any files open in memory that had been deleted from disk?
1. Was any evidence of anti-forensic activity visible in memory (e.g., clearing history, shredding files)?

---

### Task 6: Forensic Report

Produce a formal forensic report containing:

1. **Case Summary** — subject, dates, scope
1. **Evidence Inventory** — all items with hashes
1. **Timeline of Events** — chronological, with evidence citations
1. **Findings** — what was accessed, what was exfiltrated
1. **Backdoors/Persistence** — any remaining access mechanisms
1. **Attribution** — confidence level that mkumar performed the unauthorized access
1. **Recommendations** — immediate remediation and long-term security improvements

```console
# Report template helper
python3 /forensics/scripts/generate-report.py --output /tmp/forensic_report.md
cat /tmp/forensic_report.md
```

---

## Scoring

| Task | Points | Description |
|------|--------|-------------|
| Task 1 | 10 | Evidence integrity verified, triage complete |
| Task 2 | 20 | Access method and persistence fully identified |
| Task 3 | 20 | Complete activity reconstruction with evidence |
| Task 4 | 25 | Exfiltration method, size, and destination identified |
| Task 5 | 15 | Memory forensics findings documented |
| Task 6 | 10 | Report quality, citation accuracy, attribution confidence |
| **Total** | **100** | |

---

## Hints

* **Task 1**: Check the `mtime`/`atime`/`ctime` relationships. Timestomping leaves `ctime` (inode change time) later than `mtime` — a red flag.
* **Task 2**: Even after account deletion/lockout, SSH key authentication works if the key file persists. Check `/root/.ssh/authorized_keys` — admins sometimes backdoor root.
* **Task 3**: Bash history can be tampered with, but auditd syscall logs (especially `EXECVE`) are harder to fake and more authoritative.
* **Task 4**: Large files created and then deleted leave inode metadata (creation time, size, path) in the filesystem journal and audit log even after deletion.
* **Task 5**: Processes with deleted binaries (`/proc/<pid>/exe → deleted`) indicate binaries that were run and removed — a classic anti-forensics technique.
* **Task 6**: For legal proceedings, state the **confidence level** for each attribution assertion. Distinguishing "beyond reasonable doubt" from "balance of probabilities" matters.
