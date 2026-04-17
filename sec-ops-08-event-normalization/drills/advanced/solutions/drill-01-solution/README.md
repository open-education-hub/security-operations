# Drill 01 Solution (Advanced): Full Detection Engineering Workflow

---

## Part 1 Solution: Threat Modeling

### Q1.1: Three Common DLL Injection API Call Sequences

**Classic DLL Injection:**

```text
OpenProcess(PROCESS_ALL_ACCESS, targetPID)
→ VirtualAllocEx(targetHandle, NULL, dllPathLen, MEM_COMMIT, PAGE_READWRITE)
→ WriteProcessMemory(targetHandle, allocatedMem, dllPath, dllPathLen)
→ GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA")
→ CreateRemoteThread(targetHandle, NULL, 0, LoadLibraryAddr, allocatedMem)
```

**Reflective DLL Injection:**

```text
OpenProcess(PROCESS_ALL_ACCESS, targetPID)
→ VirtualAllocEx(targetHandle, NULL, dllSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
→ WriteProcessMemory(targetHandle, allocatedMem, reflectiveDLLBuffer, dllSize)
→ CreateRemoteThread(targetHandle, NULL, 0, reflectiveLoaderEntryPoint, NULL)
```

No LoadLibrary call — the DLL loads itself without touching disk.

**APC (Asynchronous Procedure Call) Injection:**

```text
OpenProcess/OpenThread(targetThread)
→ VirtualAllocEx + WriteProcessMemory (same as above)
→ QueueUserAPC(funcPtr, threadHandle, argPtr)
```

No CreateRemoteThread — execution happens when target thread enters alertable wait state.

### Q1.2: Malware Using DLL Injection (from ATT&CK)

1. **Cobalt Strike** — Beacon uses reflective DLL injection for staging and post-exploitation
1. **Metasploit** — Meterpreter uses reflective DLL injection via `migrate` command
1. **FinFisher/FinSpy** — Uses classic injection to persist in legitimate processes
1. **Carbanak/FIN7** — Uses process injection to hide malicious activity in browsers

### Q1.3: Key Differences

| Technique | How it works | What's on disk? | Detection signal |
|-----------|-------------|----------------|-----------------|
| **Classic DLL Injection** | LoadLibraryA loads DLL from disk into target | DLL file on disk | CreateRemoteThread + DLL load event |
| **Reflective DLL Injection** | DLL maps itself into memory without LoadLibrary | Nothing (memory only) | CreateRemoteThread only (no file event) |
| **Process Hollowing** (T1055.012) | Target process is created suspended, its memory replaced | Hollow process (wrong image) | Process created + memory write + resume |

### Q1.4: Legitimate Uses of CreateRemoteThread

* **Debuggers** (WinDbg, Visual Studio, OllyDbg) — attach to and inject into debugged processes
* **JIT compilers** (Java, .NET CLR) — inject JIT-compiled code
* **Antivirus products** (many AV vendors) — inject their scanning DLLs for in-process scanning
* **System monitoring tools** (Process Monitor, APM agents) — inject hooks
* **Application performance monitoring** (Dynatrace, AppDynamics, New Relic)

This matters because: a naive rule blocking all CreateRemoteThread would generate massive FPs from AV, debuggers, and monitoring agents.

---

## Part 2 Solution: Data Source Mapping

### Q2.1: Data Source Coverage Matrix

| API Call | Sysmon EID | Win Security | EDR | Notes |
|----------|-----------|--------------|-----|-------|
| `OpenProcess` | EID 10 (GrantedAccess) | — | API hook | EID 10 fires on any process access, very noisy |
| `VirtualAllocEx` | — | — | API hook | No native Windows event for this |
| `WriteProcessMemory` | — | — | API hook | No native Windows event for this |
| `CreateRemoteThread` | **EID 8** | — | API hook | Best signal: source+target+entry point logged |
| LoadLibrary (result) | EID 7 (ImageLoaded) | — | API hook | DLL load visible but extremely high volume |

### Q2.2: Highest-Fidelity Event for DLL Injection

**Sysmon EventID 8 (CreateRemoteThread)** provides the highest-fidelity signal because:

1. It directly captures the injection mechanism (CreateRemoteThread is the triggering action)
1. It logs BOTH the source process (injector) and target process (victim)
1. It captures the `StartAddress` (where in the target process execution begins)
1. Lower volume than EID 7 (ImageLoaded) or EID 10 (ProcessAccess)
1. The source-target relationship is critical: `cmd.exe → notepad.exe` is suspicious; `WinDbg.exe → notepad.exe` is a debugger

### Q2.3: EID 7 vs EID 8 Tradeoffs

| | Sysmon EID 7 (ImageLoaded) | Sysmon EID 8 (CreateRemoteThread) |
|--|--------------------------|----------------------------------|
| **Volume** | Extremely high (every DLL load) | Low-medium |
| **Coverage** | Detects DLL loaded in any process | Detects the injection mechanism directly |
| **Reflective injection** | Misses it (no file = no image load event) | Catches it (RemoteThread still created) |
| **False positives** | High (AV, .NET, Java DLL loads) | Lower, but still needs filtering |
| **Best for** | Detecting known-bad DLL hashes (blocklist) | Detecting injection behavior |

**Recommendation:** Use EID 8 as primary, EID 7 for secondary hash-based detection.

---

## Part 3 Solution: Rules

### Task 3.1: Primary Detection Rule (CreateRemoteThread)

```yaml
title: DLL Injection via CreateRemoteThread to Non-Child Process
id: f1a2b3c4-d5e6-f7a8-b9c0-d1e2f3a4b5c6
status: stable
description: |
  Detects DLL injection via the classic CreateRemoteThread API when the target
  process is not a child of the injecting process. Legitimate parent→child
  thread creation is normal; cross-process injection from unrelated processes
  indicates malicious injection (Cobalt Strike, Metasploit migrate, etc.).

  Covers ATT&CK T1055.001 - Process Injection: Dynamic-link Library Injection.
references:
  - https://attack.mitre.org/techniques/T1055/001/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/
author: SOC Team
date: 2024/12/14
modified: 2024/12/14
tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1055
  - attack.t1055.001
logsource:
  product: windows
  category: create_remote_thread
detection:
  selection:
    EventID: 8
  # Exclude known-legitimate remote thread sources
  filter_av_products:
    SourceImage|contains:
      - '\MsMpEng.exe'        # Windows Defender
      - '\MsSense.exe'        # Defender for Endpoint
      - '\CSFalconService.exe' # CrowdStrike
      - '\cbsensor.exe'       # Carbon Black
  filter_debuggers:
    SourceImage|contains:
      - '\dbghost.exe'
      - '\devenv.exe'         # Visual Studio
      - '\windbg.exe'
      - '\x64dbg.exe'
      - '\OllyDbg.exe'
  filter_dotnet_jit:
    SourceImage|endswith: '\mscorsvw.exe'
    TargetImage|endswith: '\mscorsvw.exe'
  filter_system_processes:
    SourceImage|endswith:
      - '\csrss.exe'
      - '\werfault.exe'
  filter_apm_tools:
    SourceImage|contains:
      - '\dynatracer'
      - '\oneagentwatchdog'
      - '\datadog-agent'
  condition: selection and not 1 of filter_*
fields:
  - SourceImage
  - TargetImage
  - StartAddress
  - StartModule
  - StartFunction
falsepositives:
  - Antivirus software not covered in filter (add specific paths)
  - APM / observability agents that inject hooks
  - Software debuggers or profilers
  - JVM or .NET runtime thread management
level: high
```

### Task 3.2: Supporting Indicator Rule (Suspicious Module Load)

```yaml
title: Unsigned DLL Loaded into Sensitive Process
id: g2h3i4j5-k6l7-m8n9-o0p1-q2r3s4t5u6v7
status: stable
description: |
  Detects loading of an unsigned (no valid digital signature) or unknown DLL
  into a sensitive process (lsass, svchost, explorer, browser processes).

  This complements the CreateRemoteThread rule by catching reflective DLL
  injection and other injection methods that bypass CreateRemoteThread but
  still result in a foreign DLL loaded into a target process.
references:
  - https://attack.mitre.org/techniques/T1055/001/
author: SOC Team
date: 2024/12/14
tags:
  - attack.defense_evasion
  - attack.t1055
  - attack.t1055.001
logsource:
  product: windows
  category: image_load
detection:
  selection_target:
    Image|endswith:
      - '\lsass.exe'
      - '\svchost.exe'
      - '\explorer.exe'
      - '\chrome.exe'
      - '\firefox.exe'
      - '\MicrosoftEdge.exe'
  selection_unsigned:
    Signed: 'false'
  filter_windows_paths:
    ImageLoaded|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
      - 'C:\Program Files\Windows Defender\'
  condition: selection_target and selection_unsigned and not filter_windows_paths
fields:
  - Image
  - ImageLoaded
  - Signed
  - Signature
  - SignatureStatus
falsepositives:
  - Third-party browser extensions loading unsigned DLLs
  - Legacy applications with unsigned DLLs in Program Files
  - Development/testing environments
level: medium
```

### Task 3.3: YARA-L Correlation Rule

```yara-l
rule dll_injection_two_signal_correlation {
  meta:
    author = "SOC Team"
    description = "Correlates CreateRemoteThread (primary) with unsigned DLL load in sensitive process (secondary) for high-confidence DLL injection detection"
    severity = "CRITICAL"
    mitre_attack_technique = "T1055.001"
    confidence = "high"
    references = "https://attack.mitre.org/techniques/T1055/001/"

  events:
    /* Signal 1: CreateRemoteThread from suspicious source to target */
    $crt.metadata.event_type = "PROCESS_INJECTION"
    $crt.metadata.product_event_type = "8"    /* Sysmon EID 8 */
    $crt.principal.process.file.full_path != /(?i)(MsMpEng|CSFalcon|devenv|windbg)/
    $crt.target.process.pid = $target_pid
    $crt.principal.hostname = $hostname

    /* Signal 2: Unsigned DLL loaded into same target process */
    $dll_load.metadata.event_type = "PROCESS_MODULE_LOAD"
    $dll_load.metadata.product_event_type = "7"   /* Sysmon EID 7 */
    $dll_load.principal.process.pid = $target_pid
    $dll_load.target.file.security_context.is_signed = false
    $dll_load.principal.hostname = $hostname

  match:
    $hostname, $target_pid over 5m

  condition:
    $crt and $dll_load

  outcome:
    $risk_score = 95
    $summary = strings.concat(
      "DLL Injection: RemoteThread from ",
      $crt.principal.process.file.full_path,
      " into PID ",
      strings.to_string($target_pid),
      " loaded unsigned DLL: ",
      $dll_load.target.file.full_path
    )
}
```

---

## Part 4 Solution

### Task 4.1: Atomic Red Team Test Mapping

| # | Test Name | Expected Rule to Fire |
|---|-----------|----------------------|
| 1 | Process Injection via mavinject.exe | Primary (CreateRemoteThread via mavinject) |
| 2 | Shared Libraries Injection via /etc/ld.so.preload | Neither (Linux-only) |
| 3 | Loaded library injection on macOS | Neither (macOS-only) |
| 4 | Inject DLL into running process using Powersploit's Invoke-DllInjection | Primary (CreateRemoteThread) + Supporting (unsigned DLL load) |

### Task 4.2: Test Cases

**True Positives (should fire):**

| Test | Expected Trigger |
|------|-----------------|
| `mavinject.exe [PID] /INJECTRUNNING malicious.dll` | Primary rule (CreateRemoteThread via mavinject → target process) |
| PowerShell Invoke-DllInjection into notepad.exe | Primary + Supporting (unsigned DLL loaded) |
| Reflective injection via Meterpreter migrate | Primary only (no file → only EID 8 fires) |

**True Negatives (should NOT fire):**

| Scenario | Why It Should Not Alert |
|----------|------------------------|
| VS Code debugger attaching to Node.js | `filter_debuggers` exclusion for devenv.exe pattern |
| Windows Defender scanning with MsMpEng.exe | `filter_av_products` exclusion |
| .NET CLR JIT compiling code | `filter_dotnet_jit` exclusion |
| Chrome loading its own unsigned extension | Rule only fires on SENSITIVE processes (not in extension context) |

---

## Part 5 Solution

### Task 5.1: ATT&CK Navigator Layer

```json
{
  "name": "DLL Injection Coverage Layer - Session 08",
  "versions": { "attack": "14", "navigator": "4.9" },
  "domain": "enterprise-attack",
  "description": "Detection coverage for T1055 after implementing drill-01 rules",
  "techniques": [
    {
      "techniqueID": "T1055.001",
      "score": 1,
      "color": "#52BE80",
      "comment": "Covered by: DLL-INJ-001 (CreateRemoteThread) + DLL-INJ-002 (Unsigned DLL Load)"
    },
    {
      "techniqueID": "T1055.002",
      "score": 0,
      "color": "#E74C3C",
      "comment": "GAP: Portable Executable Injection - no rule yet. Need EID 8 analysis for PE-in-memory patterns."
    },
    {
      "techniqueID": "T1055.003",
      "score": 0,
      "color": "#E74C3C",
      "comment": "GAP: Thread Execution Hijacking - needs EID 10 with THREAD_SET_CONTEXT access"
    },
    {
      "techniqueID": "T1055.004",
      "score": 0,
      "color": "#E74C3C",
      "comment": "GAP: Asynchronous Procedure Call (QueueUserAPC) - no detection"
    },
    {
      "techniqueID": "T1055.012",
      "score": 0.5,
      "color": "#F39C12",
      "comment": "PARTIAL: Process Hollowing - CreateRemoteThread rule may catch, but process creation analysis needed"
    },
    {
      "techniqueID": "T1055",
      "score": 0.2,
      "color": "#F39C12",
      "comment": "Parent technique - covered for sub-technique 001 only"
    }
  ]
}
```

### Task 5.2: Detection Gaps

| Sub-technique | Gap | Required Data Source |
|--------------|-----|---------------------|
| T1055.002 PE Injection | No detection for shellcode/PE injection without CreateRemoteThread | EDR API telemetry (VirtualAllocEx with EXEC permission) |
| T1055.003 Thread Hijacking | Thread context modification not captured | Sysmon EID 10 with `THREAD_SET_CONTEXT` access rights |
| T1055.004 APC Injection | QueueUserAPC not logged by Sysmon | ETW (Event Tracing for Windows) - NtQueueApcThread |
| T1055.005 Thread Local Storage | TLS callback injection not detected | Custom ETW consumer or EDR |
| T1055.013 Process Doppelgänging | NTFS transactions abuse not in Sysmon | Kernel driver or EDR with TxF monitoring |

---

## Part 6 Solution: Detection Package README

```markdown
# Detection Package: DLL Injection (T1055.001)
**Package ID:** DET-PKG-2024-0042
**ATT&CK Technique:** T1055.001 — Process Injection: DLL Injection
**Created:** 2024-12-14
**Last Updated:** 2024-12-14
**Status:** Stable
**ATT&CK Coverage:** T1055.001 (High confidence)

## Summary
This detection package provides two complementary rules for detecting DLL injection:

1. **Primary Rule** (DLL-INJ-001): Detects the injection mechanism via CreateRemoteThread

2. **Supporting Rule** (DLL-INJ-002): Detects the result via unsigned DLL loads in sensitive processes
3. **Correlation Rule** (DLL-INJ-CORR-001): High-confidence alert when both signals fire

## Deployment

### Prerequisites
- Sysmon ≥ 14.0 with configuration enabling EID 7 and EID 8
- ECS-normalized index in Elasticsearch or Sigma-compatible SIEM
- Privilege to create index templates and saved searches

### Sysmon Configuration Required
```

<RuleGroup name="CreateRemoteThread" groupRelation="or">
  <CreateRemoteThread onmatch="include">
    <Rule groupRelation="and">
      <!-- Exclude known-good sources -->
    </Rule>
  </CreateRemoteThread>
</RuleGroup>

```text
### Installation
1. Copy Sigma rules to your detection rule repository

2. Compile for your SIEM: `sigma convert -t [backend] rules/`
3. Deploy compiled rules
4. Populate `tuning/whitelist.csv` with environment-specific exclusions
5. Run validation: `python3 tests/validate.py`

## Tuning Notes
The primary rule includes filters for common AV products and debuggers.
Review `tuning/whitelist.csv` to add environment-specific exclusions.
Do NOT add overly broad exclusions (e.g., excluding all of C:\Program Files).

## Known Limitations
- Does not detect APC injection (QueueUserAPC)
- Reflective DLL injection with suspended thread resume may evade EID 8 in some cases
- Very high-volume environments may need Sysmon EID 8 sampling

## Validation
Run Atomic Red Team T1055.001 Test 4 (PowerSploit Invoke-DllInjection) to validate.
Expected: DLL-INJ-001 and DLL-INJ-002 both fire within 30 seconds.
```
