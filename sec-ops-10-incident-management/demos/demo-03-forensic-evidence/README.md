# Demo 03: Forensic Evidence Collection with Volatility

## Overview

This demo demonstrates memory forensics using Volatility 3.
Students see a pre-acquired memory image analyzed to extract attacker artifacts: running processes, network connections, injected code, and command history.

## Learning Objectives

* Understand what information is preserved in a memory image
* Use Volatility 3 plugins to extract forensic artifacts
* Identify evidence of process injection and C2 activity in memory
* Document findings in chain-of-custody format

## Setup

```console
docker compose up -d
# Memory image is pre-loaded inside the container
```

## Demo Walkthrough

### 1. Verify Evidence Integrity

```console
docker exec volatility bash -c "sha256sum /evidence/memory.raw && cat /evidence/memory.raw.sha256"
```

Confirm hashes match — this demonstrates chain of custody verification.

### 2. List Processes

```console
docker exec volatility python3 /vol3/vol.py \
  -f /evidence/memory.raw windows.pslist
```

Point out `svchost.exe` with unusual parent process, and `powershell.exe` with a suspicious command line.

### 3. Check Network Connections

```console
docker exec volatility python3 /vol3/vol.py \
  -f /evidence/memory.raw windows.netstat
```

Show the established connection to C2 IP `185.220.101.5:443`.

### 4. Process Tree

```console
docker exec volatility python3 /vol3/vol.py \
  -f /evidence/memory.raw windows.pstree
```

Visual tree shows `msiexec.exe` → `powershell.exe` → `svchost.exe (injected)`.

### 5. Extract Suspicious Process Memory

```console
docker exec volatility python3 /vol3/vol.py \
  -f /evidence/memory.raw windows.malfind
```

`malfind` identifies memory regions with executable code that wasn't originally loaded from disk — classic sign of shellcode injection.

## Key Teaching Points

1. Memory forensics reveals what was running, even if malware deleted its files from disk
1. Memory images must be taken before shutdown — volatile evidence is lost permanently
1. Hash verification at every step is mandatory for legal admissibility
1. The `malfind` plugin shows injected code that file-based AV would miss

## Note on Memory Image

The memory image in this demo is a synthetically generated file that simulates typical memory forensics artifacts for educational purposes.
Real memory forensics should be performed on legally acquired evidence only.

## Teardown

```console
docker compose down -v
```
