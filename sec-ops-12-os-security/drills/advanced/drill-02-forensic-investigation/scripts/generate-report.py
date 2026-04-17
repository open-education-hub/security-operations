#!/usr/bin/env python3
"""Generate forensic report template for advanced drill 02."""
import argparse, json, os
from datetime import datetime

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    args = p.parse_args()

    report = """# FORENSIC INVESTIGATION REPORT

**Case Number:** CF-2024-0042  
**Classification:** CONFIDENTIAL — Attorney-Client Privileged  
**Examiner:** [Student Name]  
**Report Date:** {date}  
**Subject:** Michael Kumar (mkumar), former Senior System Administrator  
**Organization:** Atlas Manufacturing  
**System Examined:** SRV-BUILD-02 (Ubuntu 22.04.3 LTS)

---

## 1. Case Summary

[TO COMPLETE: Brief description of the incident, scope, and objectives]

---

## 2. Evidence Inventory

| Item | Description | SHA256 | Status |
|------|-------------|--------|--------|
| disk_timeline.json | Disk filesystem timeline | a3f8b1... | Verified |
| memory_snapshot.json | Memory snapshot at collection | b4c5d6... | Verified |
| auth.log | SSH authentication log | c5d6e7... | Verified |
| audit.log | auditd syscall log | d6e7f8... | Verified |
| bash_history | Reconstructed bash history | e7f8a9... | Verified |
| usb_events.log | USB device events | f8a9b0... | Verified |

---

## 3. Timeline of Events

| Time (UTC) | Event | Evidence Source | Significance |
|------------|-------|-----------------|--------------|
| [TO COMPLETE] | | | |

---

## 4. Findings

### 4.1 Unauthorized Access
[TO COMPLETE: How did mkumar access the system after revocation?]

### 4.2 Data Accessed
[TO COMPLETE: What files/directories were accessed?]

### 4.3 Data Exfiltration
[TO COMPLETE: What was exfiltrated, via which method, to where?]

### 4.4 Anti-Forensics Activity
[TO COMPLETE: What attempts were made to cover tracks?]

---

## 5. Backdoors / Persistence Remaining

[TO COMPLETE: Any mechanisms still present at collection time]

---

## 6. Attribution

**Confidence Level:** [High / Medium / Low]

**Evidence Supporting Attribution to mkumar:**
1. [List evidence items]
2. 
3. 

**Caveats / Alternative Hypotheses:**
[TO COMPLETE]

---

## 7. Recommendations

### Immediate Remediation (within 24 hours):
1. [TO COMPLETE]

### Short-term (within 1 week):
1. 

### Long-term:
1. 
""".format(date=datetime.utcnow().strftime("%Y-%m-%d"))

    with open(args.output, 'w') as f:
        f.write(report)
    print(f"Report template written to {args.output}")
    print(f"Edit it to fill in your findings.")

if __name__ == "__main__":
    main()
