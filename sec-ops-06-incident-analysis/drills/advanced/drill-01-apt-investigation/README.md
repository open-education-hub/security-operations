# Drill 01 (Advanced): APT Multi-Stage Investigation

**Level:** Advanced

**Time:** 90–120 minutes

**Environment:** Docker (multi-source log investigation environment)

---

## Overview

This drill simulates a real-world Advanced Persistent Threat (APT) investigation.
Unlike simpler incidents, this APT campaign:

* Had a 45-day dwell time before detection
* Used living-off-the-land techniques (LOLBins)
* Avoided triggering most standard detection rules
* Maintained multiple persistence mechanisms
* Conducted systematic, stealthy data collection

You are a senior analyst conducting a **compromise assessment** — you've been asked to determine the full scope of a suspected APT breach following an external tip-off from a threat intel partner.

---

## Lab Setup

```console
cd drills/advanced/drill-01-apt-investigation
docker compose up -d
```

Access: Kibana http://localhost:5603 (elastic / changeme)

**Note:** This lab includes 45 days of log data.
Efficient query design is essential.

---

## Background

**Organization:** DefenseCo — a defense contractor with classified project contracts

**Environment:** `defenceco.local`, Windows, Azure AD hybrid

**Alert:** A threat intel partner notified DefenseCo that their domain was mentioned in an actor forum alongside a leaked document classified as "internal only"

**Key personnel:**

```text
j.henderson  — CTO (has access to all technical projects)
k.ortiz      — Lead Engineer, Project REDSTONE
a.wright     — Senior Admin (Domain Admin, system architect)
svc_azure    — Service account for Azure AD sync
```

**The intelligence tip stated:**

* Threat actor: suspected nation-state nexus ("SILVERLEAF" — attributed to country redacted)
* TTPs: Custom implant, C2 via DNS and HTTPS, credential theft, ADFS targeting
* Leaked document: `REDSTONE_Phase2_Architecture.pdf` — classified project document

---

## Investigation Part 1: Establish the Breach Timeline

### 1.1 — Find the earliest suspicious activity

SILVERLEAF is known for spear-phishing with weaponized PDFs.
Check email logs going back 45 days:

```text
index=email
| where (spf_result="FAIL" OR dkim_result="FAIL")
| where like(attachment_name, "%.pdf") OR like(attachment_name, "%.docx")
| stats min(_time) as first_seen, count, values(to_address) as recipients
    by from_address, sender_domain
| sort first_seen
```

**Task 1.1a:** Find the earliest suspicious phishing email.

**Task 1.1b:** Identify all recipients across the entire campaign.

### 1.2 — DNS-based C2 detection

SILVERLEAF is known to use DNS tunneling for C2 communication.
Hunt for DNS tunneling indicators:

```text
index=dns
| eval domain_length = len(query)
| eval subdomains = len(split(query, ".")) - 2
| where domain_length > 40 OR subdomains > 4
| stats count, avg(domain_length) as avg_len, values(query) as sample_queries
    by src_ip, tostring(floor((_time / 86400)) * 86400)
| where count > 10
| sort -count
```

**Task 1.2a:** Identify which hosts are generating high-entropy DNS queries.

**Task 1.2b:** Extract the base domain being queried.
This is the attacker's DNS C2 domain.

### 1.3 — ADFS targeting detection

SILVERLEAF specifically targets ADFS (Active Directory Federation Services) for golden SAML attacks:

```text
index=winlogs
| where EventCode IN (1200, 1202, 1203, 1000, 1001, 1007)
| where like(lower(Message), "%adfs%") OR like(lower(Message), "%federation%")
| table _time, ComputerName, EventCode, Account_Name, Message
| sort _time
```

Also check for ADFS token signing certificate access:

```text
index=sysmon EventID=1
| where like(CommandLine, "%ADFSService%") OR
        like(CommandLine, "%Get-ADFSProperties%") OR
        like(CommandLine, "%Export-AADIntADFSCertificates%") OR
        like(CommandLine, "%TokenSigningCertificate%")
| table _time, Computer, User, CommandLine
```

---

## Investigation Part 2: Map the Full Kill Chain

### 2.1 — Identify initial access and exploitation

Once you've found the earliest phishing email, trace the exploitation:

```text
index=sysmon EventID=1
| where like(Image, "%Acrobat%") OR like(Image, "%AcroRd32%")
| where like(CommandLine, "%pdf%")
| eval suspicious = if(
    like(CommandLine, "%-Enc%") OR
    like(Image, "%powershell%") OR
    like(ParentImage, "%Acrobat%"),
    "SUSPICIOUS", "OK"
  )
| where suspicious="SUSPICIOUS"
| table _time, Computer, User, Image, CommandLine, ParentImage
```

### 2.2 — Identify living-off-the-land execution

SILVERLEAF is known for using Microsoft-signed binaries (LOLBins) to avoid detection:

```text
index=sysmon EventID=1
| where Image IN (
    "*certutil.exe*", "*mshta.exe*", "*regsvr32.exe*", "*rundll32.exe*",
    "*cmstp.exe*", "*wmic.exe*", "*bitsadmin.exe*", "*msiexec.exe*",
    "*ieexec.exe*", "*msbuild.exe*", "*installutil.exe*"
  )
| where like(CommandLine, "%http%") OR like(CommandLine, "%-urlcache%") OR
        like(CommandLine, "%download%") OR like(CommandLine, "%execute%")
| table _time, Computer, User, Image, CommandLine, ParentImage
| sort _time
```

### 2.3 — Map all C2 methods

SILVERLEAF uses multiple C2 channels (redundancy).
Search for:

* DNS tunneling (found in 1.2)
* HTTPS C2 (check for beaconing patterns)
* Potential steganography in image requests

```text
index=proxy
| stats count, avg(bytes_in) as avg_bytes_in, avg(bytes_out) as avg_bytes_out,
        dc(_time) as unique_hours
    by src_ip, dest_domain
| where unique_hours > 20
| where avg_bytes_out < 1000 AND avg_bytes_in < 5000
| sort -unique_hours
```

Small, regular requests over many hours = C2 beaconing pattern.

---

## Investigation Part 3: Credential Access and Privilege Escalation

### 3.1 — Domain account enumeration

```text
index=sysmon EventID=1
| where like(CommandLine, "%Get-ADUser%") OR
        like(CommandLine, "%Get-ADGroupMember%") OR
        like(CommandLine, "%nltest%") OR
        like(CommandLine, "%LDAP%")
| table _time, Computer, User, CommandLine
| sort _time
```

### 3.2 — Kerberoasting detection

Kerberoasting (T1558.003) — requesting TGS tickets for service accounts to crack offline:

```text
index=winlogs EventCode=4769
| where Ticket_Encryption_Type="0x17"
| stats count, values(Account_Name) as requesting_accounts
    by Service_Name, Client_Address
| where count > 5
| sort -count
```

`0x17` = RC4 encryption = Kerberoasting indicator (RC4 is weaker and crackable).

### 3.3 — DCSync detection

DCSync (T1003.006) — replicating domain controller data to extract all password hashes:

```text
index=winlogs EventCode=4662
| where like(Properties, "%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%")
| where NOT Account_Name LIKE "%$"
| table _time, Account_Name, ComputerName, Properties
```

The GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` = `DS-Replication-Get-Changes-All` — only DCs and replication accounts should trigger this.

---

## Investigation Part 4: Data Collection and Exfiltration

### 4.1 — Find the target document

The leaked document was `REDSTONE_Phase2_Architecture.pdf`.
Trace all access:

```text
index=sysmon EventID=11 OR EventID=15
| where like(TargetFilename, "%REDSTONE%")
| table _time, Computer, User, TargetFilename
| sort _time
```

Also check file access events:

```text
index=winlogs EventCode=4663
| where like(Object_Name, "%REDSTONE%")
| table _time, Account_Name, ComputerName, Object_Name, Access_Mask
| sort _time
```

### 4.2 — Find the exfiltration path

Once you know when and from where the document was accessed, trace the exfiltration:

```text
index=firewall
| where src_ip IN ["[compromised host IPs]"]
| where NOT cidrmatch("10.0.0.0/8", dest_ip)
| eval size_kb = round(bytes_out / 1024, 1)
| where size_kb > 50
| table _time, src_ip, dest_ip, dest_port, size_kb
| sort _time
```

---

## Investigation Part 5: Persistence Mechanisms

SILVERLEAF is known to install multiple persistence mechanisms.
Hunt for each:

### 5.1 — Registry persistence

```text
index=sysmon EventID=13
| where like(TargetObject, "%Run%") OR
        like(TargetObject, "%RunOnce%") OR
        like(TargetObject, "%Image File Execution Options%") OR
        like(TargetObject, "%AppCertDlls%")
| table _time, Computer, User, TargetObject, Details
```

### 5.2 — WMI subscription persistence (advanced)

```text
index=sysmon EventID=19 OR EventID=20 OR EventID=21
| table _time, Computer, User, EventID, Operation, Name, Query, Consumer
| sort _time
```

### 5.3 — Service installation

```text
index=winlogs EventCode=7045
| where NOT Account_Name IN ("SYSTEM", "NT AUTHORITY\\SYSTEM")
| table _time, ComputerName, Account_Name, ServiceName, ServiceFileName
```

---

## Investigation Part 6: Full ATT&CK Map

Based on all findings, complete the ATT&CK mapping:

```text
Tactic               | Technique ID | Technique Name              | Confidence | Evidence
─────────────────────┼──────────────┼─────────────────────────────┼────────────┼─────────
Reconnaissance       |              |                             |            |
Resource Development |              |                             |            |
Initial Access       |              |                             |            |
Execution            |              |                             |            |
Persistence          |              |                             |            |
Privilege Escalation |              |                             |            |
Defense Evasion      |              |                             |            |
Credential Access    |              |                             |            |
Discovery            |              |                             |            |
Lateral Movement     |              |                             |            |
Collection           |              |                             |            |
C2                   |              |                             |            |
Exfiltration         |              |                             |            |
```

---

## Investigation Part 7: Intelligence Product

Produce a **Threat Intelligence Report** on the SILVERLEAF actor based on your findings:

1. **Campaign summary**: What did they want? How did they get it?
1. **TTP profile**: Key techniques used (ATT&CK mapped)
1. **Infrastructure**: C2 IPs, domains, DNS tunneling domain
1. **Targeting**: Who was targeted? What made them a target?
1. **Dwell time and stealth techniques**: How did they avoid detection for 45 days?
1. **Recommended detections**: Top 5 detection rules to catch this actor in the future
1. **IOC list**: All indicators extracted (IPs, domains, hashes, tool names)

---

## Scoring Rubric

| Task | Points | Description |
|------|--------|-------------|
| Establish breach timeline (correct first date) | 15 | Within 2 days of actual first compromise |
| DNS tunneling domain identified | 10 | Correct domain name |
| LOLBins identified | 10 | At least 3 LOLBin uses documented |
| All persistence mechanisms found | 15 | At least 3 of 4 |
| DCSync detection | 10 | Correct technique and evidence |
| REDSTONE document exfil traced | 15 | Complete exfil path documented |
| Full ATT&CK map | 15 | Minimum 10 techniques correctly mapped |
| Intelligence report quality | 10 | Clear, actionable, TI format |
