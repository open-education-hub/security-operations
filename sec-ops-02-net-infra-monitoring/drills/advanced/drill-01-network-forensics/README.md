# Drill 01 (Advanced): Network Forensics Investigation

**Level:** Advanced

**Duration:** 90–120 minutes

**Format:** Forensic investigation scenario

**Prerequisites:** All session 02 material; familiarity with Zeek logs and PCAP analysis

---

## Scenario: Incident Response at Volta Financial

**Background:**
You are a member of the incident response team at Volta Financial Services.
On Tuesday morning, a threat intelligence service issued an alert: IP address `185.220.101.35` (categorised as a known Tor exit node used by a ransomware group) communicated with your network on Monday.

The security team has retrieved the following artefacts:

* Zeek log extracts from Monday (below)
* A brief Wireshark PCAP summary
* Firewall block/allow logs

Your task is to reconstruct the full attack timeline, determine the scope of compromise, and write an incident report.

---

## Artefact 1: Zeek conn.log (Monday, relevant entries)

```text
ts             uid           id.orig_h       id.orig_p  id.resp_h       id.resp_p  proto  service   duration   orig_bytes  resp_bytes  conn_state
1705363200.00  CaA1B2C3D4E5  185.220.101.35  49234      10.0.1.10       443        tcp    ssl        0.23       1890        512         SF
1705363220.00  CaF6G7H8I9J0  185.220.101.35  38291      10.0.1.10       443        tcp    ssl        0.21       1905        509         SF
1705363240.00  CaK1L2M3N4O5  185.220.101.35  29384      10.0.1.10       443        tcp    ssl        0.24       1893        511         SF
[... pattern continues every 20 seconds for 45 minutes ...]
1705365870.00  CbZ9Y8X7W6V5  185.220.101.35  11234      10.0.1.10       443        tcp    ssl        0.22       1901        510         SF

[90-minute gap in connections from 185.220.101.35]

1705372200.00  CcA1B2C3D4E5  10.0.1.10       56234      185.220.101.35  4444       tcp    -          1843.22    24891034    512         SF
1705372200.00  CcB2C3D4E5F6  10.0.1.10       56235      8.8.8.8         53         udp    dns        0.01       78          94          SF

[Series of internal connections]
1705372450.00  CdA1B2C3D4E5  10.0.1.10       34521      10.10.1.5       445        tcp    smb        12.44      45234       892345      SF
1705372455.00  CdB2C3D4E5F6  10.0.1.10       34522      10.10.1.6       445        tcp    smb        9.23       44123       754321      SF
1705372460.00  CdC3D4E5F6G7  10.0.1.10       34523      10.10.1.7       445        tcp    smb        11.01      43891       823455      SF
1705372465.00  CdD4E5F6G7H8  10.0.1.10       34524      10.10.1.20      22         tcp    ssh        0.00       74          0           S0
1705372466.00  CdE5F6G7H8I9  10.0.1.10       34525      10.10.1.21      22         tcp    ssh        0.00       74          0           S0
[22 more S0 connections to 10.10.1.x:22...]
1705372890.00  CeA1B2C3D4E5  10.0.1.10       38291      10.10.5.100     3389       tcp    rdp        7234.01    891234034   234891034   SF

1705380124.00  CfA1B2C3D4E5  10.10.5.100     45123      52.1.2.100      443        tcp    ssl        3601.44    4198305120  512         SF
1705380134.00  CfB2C3D4E5F6  10.10.5.100     45124      185.220.101.35  443        tcp    ssl        3599.12    4201098432  509         SF
```

---

## Artefact 2: Zeek dns.log (Monday, relevant entries)

```text
ts             uid           id.orig_h    id.orig_p  id.resp_h  id.resp_p  query                                              qtype_name  rcode_name  answers
1705372201.00  CcB2C3D4E5F6  10.0.1.10    56235      8.8.8.8    53         whoami.internal.volta-finance.com                  A           NXDOMAIN    -
1705372205.00  CcC3D4E5F6G7  10.0.1.10    56236      8.8.8.8    53         dc01.internal.volta-finance.com                   A           NXDOMAIN    -
1705372210.00  CcD4E5F6G7H8  10.0.1.10    56237      8.8.8.8    53         fileserver01.internal.volta-finance.com            A           NXDOMAIN    -
1705372215.00  CcE5F6G7H8I9  10.0.1.10    56238      8.8.8.8    53         mail.internal.volta-finance.com                   A           NXDOMAIN    -
1705372220.00  CcF6G7H8I9J0  10.0.1.10    56239      8.8.8.8    53         backup.internal.volta-finance.com                  A           NXDOMAIN    -
1705372225.00  CcG7H8I9J0K1  10.0.1.10    56240      8.8.8.8    53         payroll.internal.volta-finance.com                 A           NXDOMAIN    -
1705372230.00  CcH8I9J0K1L2  10.0.1.10    56241      8.8.8.8    53         trading.internal.volta-finance.com                 A           NXDOMAIN    -
1705372235.00  CcI9J0K1L2M3  10.0.1.10    56242      8.8.8.8    53         bRt7kXpY9mNq2wVs4uLe6iOa1dFh8jCg.relay.stealdata.pw  TXT    NOERROR     "STAGE2:download:http://185.220.101.35/implant.bin"
```

---

## Artefact 3: Zeek http.log (Monday, relevant entries)

```text
ts             uid           id.orig_h    id.resp_h       method  host                   uri                     status_code  user_agent              request_body_len  response_body_len
1705372245.00  CgA1B2C3D4E5  10.0.1.10    185.220.101.35  GET     185.220.101.35         /implant.bin            200          -                       0                 2408960
1705372250.00  CgB2C3D4E5F6  10.0.1.10    185.220.101.35  GET     185.220.101.35         /stage3.ps1             200          -                       0                 14336
1705372920.00  ChA1B2C3D4E5  10.10.5.100  52.1.2.100      POST    backup-q4.s3.amazonaws.com /uploads/vault.7z   200          python-requests/2.31    4198305120        156
```

---

## Artefact 4: Zeek files.log (Monday, relevant entries)

```text
ts             uid           source  conn_uids      mime_type                    filename       md5                               sha256                                                            file_size   extracted
1705372245.00  FA1B2C3D4E5  HTTP    CgA1B2C3D4E5  application/octet-stream     implant.bin    e3b0c44298fc1c149afbf4c8996fb924  a665a45920422f9d417e4867efdc4fb8a304f3e7abe77f9a1a76e5594d72c72b  2408960     false
1705372250.00  FB2C3D4E5F6  HTTP    CgB2C3D4E5F6  application/x-powershell     stage3.ps1     d8e8fca2dc0f896fd7cb4cb0031ba249  a6b0396e0e134e8e7e38f1a5d3d478d2e9e3e0e5aada7aa45a453de1b99e87c  14336       false
1705372920.00  FC3D4E5F6G7  HTTP    ChA1B2C3D4E5  application/x-7z-compressed  vault.7z       -                                 -                                                                 4198305120  false
```

---

## Artefact 5: Firewall Allow/Block Log (abbreviated)

```text
2024-01-15 09:00:00 ALLOW  IN=eth0 OUT=eth1 SRC=185.220.101.35 DST=10.0.1.10 PROTO=TCP DPT=443
2024-01-15 09:45:30 ALLOW  IN=eth1 OUT=eth0 SRC=10.0.1.10 DST=185.220.101.35 PROTO=TCP DPT=4444
2024-01-15 10:00:50 ALLOW  IN=eth1 OUT=eth1 SRC=10.0.1.10 DST=10.10.1.5 PROTO=TCP DPT=445
[... internal traffic ...]
2024-01-15 13:34:00 ALLOW  IN=eth1 OUT=eth0 SRC=10.10.5.100 DST=52.1.2.100 PROTO=TCP DPT=443
2024-01-15 13:34:10 ALLOW  IN=eth1 OUT=eth0 SRC=10.10.5.100 DST=185.220.101.35 PROTO=TCP DPT=443
```

---

## Investigation Questions

### Part A: Timeline Reconstruction (30 points)

**Question A1 (10 pts):** Reconstruct the complete attack timeline with timestamps.
For each stage, identify:

* The timestamp (convert UNIX timestamps to human-readable)
* What happened
* Which Zeek log or artefact provides evidence

**Question A2 (10 pts):** Identify the initial access vector.
What was the attacker doing in the 45-minute period of connections to port 443 on `10.0.1.10`?
What does the connection pattern suggest about the attack type?

**Question A3 (10 pts):** What is the significance of the 90-minute gap in connections from `185.220.101.35`?
What happened during this time, and what happened immediately after?

### Part B: Scope Assessment (30 points)

**Question B1 (10 pts):** How many internal hosts were directly accessed or affected by the attacker?
List each host with evidence.

**Question B2 (10 pts):** Was data exfiltrated?
If so:

* How much data was taken?
* What type of file was it?
* Where did it go?
* Which host was used for exfiltration?

**Question B3 (10 pts):** The attacker sent DNS queries for `whoami.internal.volta-finance.com`, `dc01.internal.volta-finance.com`, etc. to `8.8.8.8`.
What was the purpose of this activity?
Why is querying external DNS for internal hostnames a security risk, even when the domain doesn't exist (NXDOMAIN)?

### Part C: Deeper Analysis (30 points)

**Question C1 (10 pts):** Analyse the DNS TXT query to `bRt7kXpY9mNq2wVs4uLe6iOa1dFh8jCg.relay.stealdata.pw`.
What is this?
Decode the response: `"STAGE2:download:http://185.220.101.35/implant.bin"`.
What does this tell you about the attack infrastructure?

**Question C2 (10 pts):** Two files were downloaded: `implant.bin` (2.3 MB) and `stage3.ps1` (14 KB).
The SHA256 of `implant.bin` is `a665a45920422f9d417e4867efdc4fb8a304f3e7abe77f9a1a76e5594d72c72b`.
What would you do with these hashes as an incident responder?
What do the file types suggest about the attack?

**Question C3 (10 pts):** The connection from `10.0.1.10` to `185.220.101.35:4444` lasted **1843 seconds** and transferred **24.8 MB outbound and 512 bytes inbound**.
Port 4444 is the default Metasploit listener port.
What does this connection represent?
Why is 24.8 MB outbound to a C2 server concerning?

### Part D: Reporting (20 points)

**Question D1 (20 pts):** Write a concise incident report (500–700 words) covering:

* Executive summary (non-technical, 100 words)
* Technical summary of the attack chain
* Affected systems and data
* Immediate containment actions taken/recommended
* Evidence preserved
* GDPR notification requirements (if applicable)

---

## Scoring

| Part | Points |
|------|--------|
| A: Timeline | 30 |
| B: Scope | 30 |
| C: Deeper analysis | 30 |
| D: Report | 20 |
| **Total** | **110** |

Passing: 77/110 (70%)
