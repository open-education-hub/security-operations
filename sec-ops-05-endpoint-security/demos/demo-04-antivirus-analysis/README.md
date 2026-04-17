# Demo 04: Antivirus Analysis with ClamAV

## Overview

This demo uses **ClamAV** (an open-source antivirus engine) in a Docker container to demonstrate:

* How antivirus signature scanning works
* The difference between signature-based and behavioral detection
* How to interpret AV scan results
* The limitations of AV against modern threats

**What you will learn:**

* How ClamAV scans files and what its output means
* The concept of YARA rules and AV signatures
* Why AV misses fileless malware and LOLBin abuse
* How to create custom YARA rules for known-bad indicators

**Time required:** 25 minutes

**Prerequisites:** Docker installed

---

## Files

```text
demo-04-antivirus-analysis/
├── docker-compose.yml
├── Dockerfile
├── scan_targets/
│   ├── benign_script.ps1        ← normal PowerShell script
│   ├── malicious_macro.vba      ← simulated VBA macro (EICAR-free)
│   ├── eicar.com                ← EICAR test file (standard AV test)
│   ├── encoded_payload.b64      ← base64-encoded "payload" (simulated)
│   └── lolbin_abuse.bat         ← certutil + mshta abuse (no malware, just pattern)
├── custom_rules.yara            ← custom YARA rules for detection
├── run_demo.sh                  ← orchestrates the full demo
└── README.md                    ← this file
```

---

## Part 1: What ClamAV Detects

ClamAV uses several detection methods:

### 1. Hash Signatures (MD5, SHA-1, SHA-256)
Known-bad file hashes in `.hdb` database files:

```text
# Format: hash:filesize:signaturename
44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature
```

### 2. Byte Pattern Signatures
Hex patterns in `.ndb` database files:

```text
# Format: SignatureName:TargetType:Offset:HexSignature
Win.Trojan.Agent:0:*:4d5a90000300000004000000ffff0000b8000000
```

### 3. YARA Rules
Flexible pattern matching:

```yara
rule Suspicious_PowerShell_Download {
    meta:
        description = "Detects PowerShell downloading and executing code"
    strings:
        $s1 = "DownloadString" nocase
        $s2 = "IEX" nocase
        $s3 = "Invoke-Expression" nocase
    condition:
        2 of ($s1, $s2, $s3)
}
```

### 4. Heuristic Analysis
Pattern-based heuristics for macro analysis, PE structure anomalies.

---

## Part 2: The EICAR Test File

The **EICAR test file** is an industry-standard file for testing AV engines.
It is **not malware** — it is a specially crafted file that all compliant AV products detect as malicious for testing purposes.

```text
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

This is a valid COM-format executable that prints "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" when run.

**ClamAV output when scanning EICAR:**

```text
/scan_targets/eicar.com: Win.Test.EICAR_HDB-1 FOUND
```

---

## Part 3: Running the Demo

```bash
# Build and run the full demo
docker-compose up --build

# Interactive mode
docker-compose run clamav-demo bash

# Inside container:
# 1. Update signatures
freshclam

# 2. Scan with verbose output
clamscan -r -v /scan_targets/

# 3. Scan with YARA rules
clamscan --database=/custom_rules.yara /scan_targets/

# 4. Generate report
clamscan -r --log=/tmp/scan_report.txt /scan_targets/
cat /tmp/scan_report.txt
```

---

## Part 4: AV Detection Results — What Gets Caught

### File: eicar.com (EICAR Standard Test)

```text
/scan_targets/eicar.com: Win.Test.EICAR_HDB-1 FOUND
```

**Result:** DETECTED — Standard signature match.

### File: malicious_macro.vba (Simulated VBA Macro)

```text
/scan_targets/malicious_macro.vba: OK
```

**Result:** NOT DETECTED — Our simulated macro doesn't match any signatures because it's new.
This is the **zero-day problem**.

### File: lolbin_abuse.bat (LOLBin Abuse Pattern)

```text
/scan_targets/lolbin_abuse.bat: OK
```

**Result:** NOT DETECTED — Using `certutil.exe` to download a file is a legitimate operation.
AV cannot tell the difference from file content alone.

### File: encoded_payload.b64 (Base64-Encoded Simulated Payload)

```text
/scan_targets/encoded_payload.b64: OK
```

**Result:** NOT DETECTED — Base64 encoding bypasses simple string matching.
The payload is obfuscated.

---

## Part 5: Custom YARA Rules

YARA rules allow you to write custom detections based on patterns you've observed.
This is how threat analysts add detection for new malware families.

See `custom_rules.yara` for our detection rules.
When run with ClamAV's YARA support:

```console
clamscan --database=/custom_rules.yara /scan_targets/
```

Expected output with custom rules:

```text
/scan_targets/malicious_macro.vba: YARA.Suspicious_Office_Macro.UNOFFICIAL FOUND
/scan_targets/lolbin_abuse.bat: YARA.LOLBin_CertUtil_Download.UNOFFICIAL FOUND
```

The custom YARA rules catch what ClamAV signatures miss!

---

## Part 6: AV Limitations — The Full Picture

```text
┌─────────────────────────────────────────────────────────────┐
│               What AV Catches vs. What It Misses           │
├────────────────────────────┬────────────────────────────────┤
│         CATCHES            │           MISSES               │
├────────────────────────────┼────────────────────────────────┤
│ Known malware hashes       │ Zero-day malware               │
│ Known byte patterns        │ Polymorphic malware            │
│ EICAR test files           │ Fileless malware               │
│ Old commodity malware      │ LOLBin abuse                   │
│ Macro patterns (limited)   │ Process injection              │
│ Phishing documents (some)  │ Memory-only payloads           │
│                            │ Encrypted/packed malware       │
│                            │ Living-off-the-land attacks    │
└────────────────────────────┴────────────────────────────────┘
```

### The Malware Evasion Arsenal

**Polymorphic malware:** Changes its byte signature on each infection.
A simple hash or byte pattern doesn't match.

**Encrypted/packed malware:**

```text
Original malware → encrypt with random key → dropper decrypts in memory → AV sees encrypted blob
```

**Fileless malware:** Never written to disk.
PowerShell in-memory execution has no file for AV to scan.

**LOLBins:** Legitimate signed Microsoft binaries used maliciously.
AV won't flag `certutil.exe` — it's trusted.

---

## Part 7: EDR vs AV — Side by Side

| Scenario | AV | EDR |
|----------|-----|-----|
| Known malware hash | ✅ Detected | ✅ Detected |
| Zero-day executable | ❌ Missed | ✅ Behavioral alert |
| Encoded PowerShell download | ❌ Missed | ✅ Script block logging |
| certutil downloading payload | ❌ Missed | ✅ Network connection alert |
| Process injection into svchost | ❌ Missed | ✅ CreateRemoteThread alert |
| LSASS memory access | ❌ Missed | ✅ Process access alert |
| Registry run key persistence | ❌ Missed | ✅ Registry monitoring alert |

**Conclusion:** AV is a necessary but insufficient control.
It provides fast, cheap protection against commodity threats but requires complementary behavioral monitoring (Sysmon, EDR, auditd) for comprehensive coverage.

---

## Key Takeaways

1. **AV signature databases require constant updates.** A signature added today won't detect malware from tomorrow until the database is updated.

1. **YARA rules extend AV capabilities.** Custom YARA rules let you detect patterns based on your organization's threat intelligence.

1. **The detection gap is real.** Modern attackers routinely test their tools against AV before deployment (using VMs, VirusTotal API negation, etc.).

1. **AV + EDR + SIEM is the defense-in-depth formula.** Each layer catches what the others miss.

1. **ClamAV is production-quality for email/file scanning** (used by many mail servers). It is not typically deployed as a host-based endpoint AV for desktops — but it's excellent for file server scanning and email gateway use.
