# Demo 03 — Forensic Evidence Preservation and Chain of Custody

## Overview

This demo covers the practical aspects of digital forensics in incident response: collecting volatile evidence, creating forensic disk images, and maintaining chain of custody.

**Duration:** 40 minutes

**Tools:** Docker (forensics environment), Python, dd concepts

**Key skills:** Memory analysis with Volatility, disk imaging, evidence documentation

---

## Setup

```console
# Start the forensics demo environment
docker compose up -d

# Environment includes:
# - Linux container simulating a compromised host
# - Pre-loaded with simulated forensic artifacts
# - Volatility framework installed
# Access at: docker exec -it forensics-demo bash
```

---

## Part 1: Order of Volatility in Practice (10 minutes)

### Why collect in the right order?

Evidence exists at different volatility levels.
The most volatile disappears first (when power is lost or connections close).

```text
Most volatile                              Least volatile
    │                                           │
    ▼                                           ▼
CPU regs → RAM → Network → Processes → Disk → Backup tapes
(lost in   (lost   (changes  (changes   (stable  (offline,
 ms)        on      rapidly)  on        for      months)
            power           restart)   years)
            off)
```

### Simulate the scenario

Our compromised host: `forensics-demo` container

```bash
# Access the simulated compromised host
docker exec -it forensics-demo bash

# Step 1: Collect network connections (before they change)
echo "=== Network Connections ===" > /evidence/network.txt
ss -tnap >> /evidence/network.txt
echo "Collected at: $(date -u)" >> /evidence/network.txt

# Step 2: Collect running processes
echo "=== Running Processes ===" > /evidence/processes.txt
ps auxf >> /evidence/processes.txt
echo "Collected at: $(date -u)" >> /evidence/processes.txt

# Step 3: Collect open files
echo "=== Open Files ===" > /evidence/open_files.txt
lsof >> /evidence/open_files.txt

# Step 4: System information
echo "=== System Info ===" > /evidence/sysinfo.txt
uname -a >> /evidence/sysinfo.txt
hostname >> /evidence/sysinfo.txt
date -u >> /evidence/sysinfo.txt
uptime >> /evidence/sysinfo.txt

echo "Volatile evidence collected successfully"
```

---

## Part 2: Memory Analysis Concepts (15 minutes)

### What's in a memory dump?

A RAM dump contains everything the OS and running programs have in memory:

```text
Memory contents (simplified):
├── OS kernel structures
├── Running processes
│   ├── Process metadata (PID, PPID, name, command line)
│   ├── Loaded DLLs
│   ├── Heap (data the process is working with)
│   └── Stack (function call history)
├── Network sockets (active connections)
├── File handles (open files)
├── Cached credentials (LSASS)
└── Encryption keys (if encryption is active)
```

### Simulated Volatility analysis

```python
# volatility_sim.py — simulates Volatility output analysis
# (Volatility itself requires a real memory image)

import json
from datetime import datetime

# Simulated pslist output (would come from: vol -f memory.raw windows.pslist)
SIMULATED_PROCESSES = [
    {"pid": 4, "ppid": 0, "name": "System", "create_time": "2025-04-10 09:00:00", "suspicious": False},
    {"pid": 756, "ppid": 4, "name": "smss.exe", "create_time": "2025-04-10 09:00:01", "suspicious": False},
    {"pid": 1024, "ppid": 756, "name": "csrss.exe", "create_time": "2025-04-10 09:00:02", "suspicious": False},
    {"pid": 1200, "ppid": 1, "name": "svchost.exe", "create_time": "2025-04-10 09:01:00", "suspicious": False},
    {"pid": 2048, "ppid": 1200, "name": "WINWORD.EXE", "create_time": "2025-04-10 14:29:45", "suspicious": False},
    # Suspicious: Word spawning cmd.exe
    {"pid": 3112, "ppid": 2048, "name": "cmd.exe", "create_time": "2025-04-10 14:30:10",
     "cmdline": "cmd.exe /c powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdA==",
     "suspicious": True},
    # The PowerShell process
    {"pid": 3244, "ppid": 3112, "name": "powershell.exe", "create_time": "2025-04-10 14:30:11",
     "cmdline": "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdA==",
     "suspicious": True},
    # Cobalt Strike injected into svchost
    {"pid": 1568, "ppid": 1200, "name": "svchost.exe", "create_time": "2025-04-10 14:30:15",
     "note": "INJECTED — Cobalt Strike beacon (detected via malfind)",
     "suspicious": True},
]

def analyze_processes(processes):
    """Analyze process list for suspicious patterns."""
    print("=== PROCESS TREE ANALYSIS ===\n")

    suspicious = [p for p in processes if p.get("suspicious")]

    print(f"Total processes: {len(processes)}")
    print(f"Suspicious processes: {len(suspicious)}\n")

    print("SUSPICIOUS PROCESSES:")
    for proc in suspicious:
        print(f"\n  PID: {proc['pid']} | Parent PID: {proc['ppid']}")
        print(f"  Name: {proc['name']}")
        if "cmdline" in proc:
            print(f"  Command: {proc['cmdline'][:80]}...")
        if "note" in proc:
            print(f"  Note: {proc['note']}")

    # Detect parent-child anomalies
    print("\n\nPARENT-CHILD ANOMALY DETECTION:")
    anomalies = [
        (2048, 3112, "WINWORD.EXE spawning cmd.exe — Office macro execution"),
        (3112, 3244, "cmd.exe spawning powershell.exe with encoded argument"),
        (1200, 1568, "svchost.exe with injected code — process hollowing/injection"),
    ]
    for parent_pid, child_pid, description in anomalies:
        parent = next((p for p in processes if p["pid"] == parent_pid), None)
        child = next((p for p in processes if p["pid"] == child_pid), None)
        if parent and child:
            print(f"\n  [ANOMALY] {description}")
            print(f"  Parent: PID {parent['pid']} ({parent['name']})")
            print(f"  Child:  PID {child['pid']} ({child['name']})")

analyze_processes(SIMULATED_PROCESSES)
```

Run: `python volatility_sim.py`

### Key Volatility commands (reference)

```bash
# Real Volatility 3 usage (requires actual memory image)

# List processes with parent info
vol -f memory.raw windows.pstree

# Network connections
vol -f memory.raw windows.netstat

# Find injected code (Cobalt Strike, shellcode)
vol -f memory.raw windows.malfind

# Command history
vol -f memory.raw windows.cmdline

# Extract files from memory
vol -f memory.raw windows.dumpfiles --pid 3244

# LSASS credential dump detection
vol -f memory.raw windows.lsadump
```

---

## Part 3: Chain of Custody Documentation (15 minutes)

### The Evidence Log

Every piece of evidence must have a documented chain of custody.
We'll create one for our simulated incident:

```python
# chain_of_custody.py

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List
import hashlib
import json

@dataclass
class EvidenceItem:
    """Represents a single piece of digital evidence."""
    case_id: str
    item_number: str
    description: str
    collected_by: str
    collection_time: str
    collection_location: str
    sha256_hash: str
    custody_log: List[dict] = field(default_factory=list)

    def transfer(self, from_person: str, to_person: str, purpose: str):
        """Record a custody transfer."""
        self.custody_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "from": from_person,
            "to": to_person,
            "purpose": purpose
        })

    def to_report(self) -> str:
        """Generate chain of custody report."""
        lines = [
            f"CHAIN OF CUSTODY REPORT",
            f"{'='*50}",
            f"Case ID:      {self.case_id}",
            f"Item #:       {self.item_number}",
            f"Description:  {self.description}",
            f"Collected by: {self.collected_by}",
            f"Collected at: {self.collection_time}",
            f"Location:     {self.collection_location}",
            f"SHA-256:      {self.sha256_hash}",
            f"",
            f"CUSTODY LOG:",
            f"{'─'*50}",
        ]
        for entry in self.custody_log:
            lines.append(
                f"{entry['timestamp']} | "
                f"{entry['from']} → {entry['to']} | "
                f"{entry['purpose']}"
            )
        return "\n".join(lines)

# Create evidence items for our incident

# Evidence 1: Disk image
disk_image = EvidenceItem(
    case_id="INC-2025-04712",
    item_number="E-001",
    description="Forensic disk image — WORKSTATION-FINANCE-03 (500GB SSD, serial WD-ABC123)",
    collected_by="Alice Analyst, Senior IR Analyst",
    collection_time="2025-04-10T15:30:00Z",
    collection_location="Finance Dept, Building A, Room 212, MedSupply GmbH HQ",
    sha256_hash="a665a45920422f9d417e4867efdc4fb8a663c84a8093f6d52ff28b9a32fcd27e"
)

# Record custody transfers
disk_image.transfer("---", "Alice Analyst", "Initial collection")
disk_image.transfer("Alice Analyst", "Evidence Safe (SOC)", "Secure storage after collection")
disk_image.transfer("Evidence Safe", "Bob Forensics", "Forensic analysis")
disk_image.transfer("Bob Forensics", "Evidence Safe", "Return after analysis")

# Evidence 2: Memory dump
memory_dump = EvidenceItem(
    case_id="INC-2025-04712",
    item_number="E-002",
    description="RAM memory dump — WORKSTATION-FINANCE-03 — 16GB",
    collected_by="Alice Analyst, Senior IR Analyst",
    collection_time="2025-04-10T14:53:00Z",
    collection_location="Finance Dept, Building A, Room 212",
    sha256_hash="b94f53a9d7439c59a6f26cc37a965c77a8d9e2f1f3b5c7d9a0e2f4b6d8f0a2c4"
)
memory_dump.transfer("---", "Alice Analyst", "Memory captured before isolation")
memory_dump.transfer("Alice Analyst", "Evidence Safe (SOC)", "Secure storage")

# Print reports
print(disk_image.to_report())
print()
print(memory_dump.to_report())
```

Run: `python chain_of_custody.py`

### Legal admissibility checklist

```text
For evidence to be admissible in legal proceedings:

□ Authenticity: Hash values computed at collection and verified before analysis
□ Integrity: Write blockers used for disk evidence (no modifications)
□ Chain of custody: Complete from collection to court (no gaps)
□ Authorization: Collection was authorized (IR manager sign-off)
□ Methodology: Standard forensic tools and procedures used
□ Documentation: Every action logged with who/when/what
```

---

## Cleanup

```console
docker compose down -v
```
