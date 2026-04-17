# Solution: Drill 01 — Windows Security Audit

## Expected Findings

### Task 1: Users and Groups

```powershell
Get-LocalUser | Select-Object Name, Enabled, PasswordNeverExpires
Get-LocalGroupMember -Group "Administrators"
```

**Expected findings in this demo container:**
| Account | Issue | Severity |
|---------|-------|---------|
| Guest | Enabled (should be disabled) | Medium |
| bob | Non-expiring password (regular user) | Medium |
| serviceacct | Member of Administrators (should not be) | High |

### Task 2: Services

**Expected findings:**
| Service | Issue | Severity |
|---------|-------|---------|
| TlntSvr (Telnet) | Running and auto-start | High |
| RemoteRegistry | Running | Medium |
| XboxGipSvc | Running (unnecessary on server) | Low |

### Task 3: Firewall

**Expected findings:**
| Profile | Issue | Severity |
|---------|-------|---------|
| Public Profile | Disabled | High |
| Domain Profile | Inbound: Allow (should be Block) | High |

### Task 4: Legacy Protocols

**Expected findings:**
| Protocol | Issue | Severity |
|---------|-------|---------|
| SMBv1 | Enabled | Critical (EternalBlue) |
| AutoRun | Enabled for all drives | Medium |

### Task 5: Registry Persistence

**Expected findings:**

```text
HKCU\...\Run:
  UpdateService: C:\Users\bob\AppData\Local\Temp\update.exe  ← SUSPICIOUS!

HKLM\...\Run:
  SecurityHealth: C:\Windows\System32\SecurityHealthSystray.exe (normal)
  OneDriveSetup: ... (normal)
```

The `update.exe` in AppData\Local\Temp is suspicious — legitimate updates don't run from user temp directories.

---

## Findings Table

| # | Issue | Location | Severity | Fix |
|---|-------|---------|---------|-----|
| 1 | SMBv1 enabled | Registry/Service | Critical | `Set-SmbServerConfiguration -EnableSMB1Protocol $false` |
| 2 | Guest account enabled | Local Users | Medium | `Disable-LocalUser -Name Guest` |
| 3 | Public firewall disabled | Firewall | High | `Set-NetFirewallProfile -Profile Public -Enabled True` |
| 4 | Telnet service running | Services | High | `Stop-Service TlntSvr; Set-Service TlntSvr -StartupType Disabled` |
| 5 | serviceacct in Admins | Local Groups | High | `Remove-LocalGroupMember -Group "Administrators" -Member serviceacct` |
| 6 | Suspicious Run key (update.exe) | Registry | High | Investigate and remove if malicious |
| 7 | bob has non-expiring password | Local Users | Medium | `Set-LocalUser -Name bob -PasswordNeverExpires $false` |
| 8 | RemoteRegistry running | Services | Medium | `Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled` |

---

## Top 3 Prioritized Remediation Actions

**1.
Fix SMBv1 immediately (Critical)**
SMBv1 enables the EternalBlue exploit (used by WannaCry, NotPetya).
No legitimate business use case justifies it remaining enabled.

```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
```

**2.
Investigate and remove suspicious Run key entry (High)**
The update.exe in AppData\Local\Temp is a strong indicator of malware persistence.
Investigate the file, check its hash against VirusTotal, and remove the Run key entry if malicious.

```powershell
Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "UpdateService"
```

**3.
Enable firewall on all profiles and remove serviceacct from Admins (High)**
Public profile firewall disabled allows direct inbound attacks.
The service account in Admins creates privilege escalation risk.

```powershell
Set-NetFirewallProfile -Profile Public,Domain,Private -Enabled True -DefaultInboundAction Block
Remove-LocalGroupMember -Group "Administrators" -Member "serviceacct"
```
