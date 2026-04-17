# Guide 03 (Basic): Evidence Handling and Chain of Custody

## Objective

Collect, hash, and document digital evidence correctly.
Create a chain of custody record.

## Estimated Time: 20–30 minutes

## The Chain of Custody Principle

Every piece of evidence must be accounted for from collection to court (or case closure).
Any gap in the chain makes evidence potentially inadmissible and calls your investigation into question.

**The 5 Requirements:**

1. **Identify** — what is the evidence?
1. **Collect** — acquire it without modification
1. **Preserve** — protect its integrity
1. **Document** — record who touched it and when
1. **Verify** — hash at every step

## Evidence Collection Best Practices

### Do NOT modify the original

* For disk images: use a **write blocker** (hardware) or `dd` with `conv=noerror,sync`
* For memory: use specialized tools (WinPmem, DumpIt, LiME) not manual copying
* Never run antivirus or any program on the evidence that wasn't there before

### Hash immediately after collection

```console
# For a memory dump (memory.raw):
sha256sum memory.raw > memory.raw.sha256

# For a disk image:
sha256sum disk_image.dd > disk_image.dd.sha256

# Record: who, when, what tool
echo "Collected by: J. Garcia" >> memory.raw.sha256
echo "Time: $(date -u)" >> memory.raw.sha256
echo "Tool: winpmem_mini_x64.exe" >> memory.raw.sha256
```

## Chain of Custody Form

Complete this form for every piece of evidence collected:

```text
═══════════════════════════════════════════════════════════════
          CHAIN OF CUSTODY RECORD — DIGITAL EVIDENCE
═══════════════════════════════════════════════════════════════
Evidence ID:     EVID-[CASE]-[SEQ]
Case ID:         INC-YYYY-NNNN
Description:     [Type, file name, size]
                 Example: Memory image from finance-ws-042, 16 GB
Hash (SHA-256):  [Complete hash value]
Collection Date: [YYYY-MM-DD HH:MM UTC]
Collected By:    [Full name, role]
Collection Tool: [Tool name and version]
Storage:         [Path/location where stored]
───────────────────────────────────────────────────────────────
TRANSFERS:
  Transfer #1
  From:     [Name, role]
  To:       [Name, role]
  Date:     [YYYY-MM-DD HH:MM UTC]
  Reason:   [Why transferred: analysis, storage, review]
  Hash Verified: YES / NO  [If yes, by whom]
  Notes:

  Transfer #2
  From:
  To:
  Date:
  Reason:
  Hash Verified: YES / NO
  Notes:
═══════════════════════════════════════════════════════════════
```

## Practice Exercise

### Scenario

You are collecting evidence from `finance-ws-042` involved in a ransomware incident.
You have collected:

1. A memory dump: `finance-ws-042_memory_20241114.raw` (16,384 MB)
1. A disk image: `finance-ws-042_disk_20241114.dd` (256 GB)
1. Network capture: `finance-ws-042_traffic_20241114.pcap` (2.3 GB)

**SHA256 hashes (pre-calculated for this exercise):**

* Memory: `a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890`
* Disk: `b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f678901b`
* PCAP: `c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890c1c2`

**Task 1:** Complete three chain of custody forms (one per evidence item).

**Task 2:** Evidence is being transferred from you (J.
Garcia, Tier 2 Analyst) to M.
Forensics (DFIR Analyst) for analysis.
Record this transfer on each CoC form.

**Task 3:** Answer these questions:

* Why must you verify the hash again after transfer to M. Forensics?
* What happens if the hash doesn't match after transfer?
* Should you collect the disk image before or after the memory dump? Why?

## Key Takeaways

1. SHA-256 is the minimum acceptable hash algorithm for legal proceedings
1. Every transfer must be documented with hash verification
1. Collect volatile evidence (memory) before static evidence (disk)
1. The chain of custody is part of the incident record — it stays with the case forever
