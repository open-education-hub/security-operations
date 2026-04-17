# Project 02: Full Incident Analysis Workflow

**Covers:** Sessions 06–08

**Estimated time:** 6–8 hours

**Level:** Intermediate

---

## Overview

This project simulates a realistic incident from initial alert through to full post-incident report.
You will receive a pre-packaged Docker environment containing logs, forensic artefacts, and a mock ticketing system.
Your job is to work the incident as a Tier-2 analyst: investigate, classify, contain, and document.

Sessions 06–08 covered network forensics, host forensics, and malware analysis fundamentals.
This project integrates all three disciplines into a single incident investigation.

---

## Learning Outcomes

Upon completing this project, you will be able to:

* Work a real-world incident from alert triage through to closure
* Extract forensic evidence from network captures and host logs
* Apply structured analysis methodology (diamond model, kill chain)
* Produce a professional Incident Report suitable for management and legal review

---

## Scenario

**Incident Reference:** INC-2024-1147

**Organisation:** Caldera Pharmaceuticals Ltd

**Severity:** P1 — Critical

**Status:** Active

At 07:43 UTC, the automated SIEM raised a critical alert: multiple internal endpoints attempted to connect to a known Cobalt Strike C2 domain.
The on-call analyst escalated immediately.

You are being handed the investigation at the triage stage.
All relevant artefacts have been collected and are available in the Docker environment.
The incident is still active — the threat actor may still have access.

**Key facts from the initial alert:**

* Affected hosts: `WS-CALDERA-014`, `WS-CALDERA-022`
* Suspicious domain: `analytics-cdn.caldera-updates.net` (not affiliated with Caldera Pharmaceuticals)
* Source of initial detection: DNS monitoring alert (domain in threat intelligence feed)
* Time of first DNS query: `2024-11-13T06:12:04Z`

---

## Environment Setup

```console
git clone <course-repo>/projects/sec-ops-proj-02-incident-analysis
cd sec-ops-proj-02-incident-analysis
docker compose up -d
docker compose exec analyst bash
```

Available artefacts inside the container:

| File | Type | Description |
|------|------|-------------|
| `/artefacts/network/caldera_pcap.pcapng` | Network capture | 4 hours of traffic from the affected subnet |
| `/artefacts/network/dns_queries.json` | DNS logs | Full DNS resolution log for both affected hosts |
| `/artefacts/host/ws-014/windows_events.evtx.json` | Windows Event Log | Security, System, and Application event logs |
| `/artefacts/host/ws-014/prefetch_files.json` | Prefetch data | Recently executed programs (last 30 days) |
| `/artefacts/host/ws-014/network_connections.json` | Netstat snapshot | Active network connections at time of collection |
| `/artefacts/host/ws-022/windows_events.evtx.json` | Windows Event Log | Same for second host |
| `/artefacts/malware/suspicious_binary.exe` | Binary | Suspicious executable found in `C:\Users\jbrown\AppData\Local\Temp\` |
| `/artefacts/malware/memory_strings.txt` | Strings output | `strings` output from the suspicious binary |
| `/artefacts/tickets/INC-2024-1147.json` | Ticket | Initial incident ticket with timeline |

Tools pre-installed: `python3`, `wireshark` (tshark CLI), `yara`, `strings`, `jq`, `rich`

---

## Project Tasks

### Part 1 — Initial Triage (Estimated: 1 hour)

**1.1** Load and review the incident ticket (`/artefacts/tickets/INC-2024-1147.json`).
What is known so far?

**1.2** Review the DNS logs for both hosts:

* When did each host first query `analytics-cdn.caldera-updates.net`?
* What IP address did the domain resolve to?
* Did either host query any other suspicious domains? (Look for newly registered domains, typosquatted names, or domains with unusual TLDs)

**1.3** Check the Windows Event Logs for the time window around the first DNS query (±30 minutes):

* Was any user logged in to the affected hosts at that time?
* Was any new process started around that time (Event ID 4688)?
* Was there any failed authentication (Event ID 4625)?

**1.4** Produce an initial triage note (5–10 bullet points) summarising what you know after 30 minutes of investigation.
This is the kind of update you would give to the incident commander on a call.

**Deliverable:** `/tmp/triage_note.md`

---

### Part 2 — Network Forensics (Estimated: 1.5 hours)

**2.1** Using `tshark` or Python with `scapy`/`dpkt`, analyse the network capture:

```console
# Summary of all connections
tshark -r /artefacts/network/caldera_pcap.pcapng -q -z conv,tcp

# HTTP/HTTPS requests
tshark -r /artefacts/network/caldera_pcap.pcapng -Y "http" -T fields -e frame.time -e ip.src -e ip.dst -e http.request.uri
```

**2.2** Identify:

* All external IP addresses contacted by the affected hosts
* Any beaconing behaviour (regular, periodic connections to the same IP/port — classic C2 pattern)
* Any data exfiltration indicators (large outbound data transfers, unusual protocols)
* DNS tunnelling indicators (unusually long domain names, high query frequency to the same domain)

**2.3** Extract any cleartext credentials or sensitive data visible in the packet capture.

**2.4** Map the C2 communication: draw or describe the following:

* Initial connection: time, src IP, dst IP, dst port, bytes transferred
* Beaconing pattern: interval (in seconds), consistency
* Any apparent commands sent or output received (look for HTTP POST bodies or response content)

**Deliverable:** `/tmp/network_analysis.md`

---

### Part 3 — Host Forensics (Estimated: 1.5 hours)

**3.1** Analyse the prefetch data for `WS-CALDERA-014`:

* What programs were run in the 2 hours before the first C2 connection?
* Was any unusual program executed (something not in `C:\Windows\System32` or standard application paths)?
* The suspicious binary was found in `C:\Users\jbrown\AppData\Local\Temp\` — when was it first executed (if at all)?

**3.2** Analyse Windows Event Logs for persistence mechanisms:

* Was any scheduled task created? (Event ID 4698)
* Was any service installed? (Event ID 7045)
* Was any registry run key modified? (check Sysmon Event ID 13 if present)
* Was any new local user created? (Event ID 4720)

**3.3** Investigate lateral movement:

* Did either host authenticate to any other internal host using `net use` or similar? (Event ID 4624 with LogonType 3)
* Did `WS-CALDERA-022` show signs of being reached from `WS-CALDERA-014`?

**3.4** Determine the initial access vector:

* Check Event Log for any email attachment executed (look for `WINWORD.EXE` or `OUTLOOK.EXE` as parent of unusual processes)
* Check for download via browser (look for files in Downloads or Temp with .exe/.zip extensions in prefetch)

**Deliverable:** `/tmp/host_forensics.md`

---

### Part 4 — Malware Analysis (Estimated: 1 hour)

**4.1** Static analysis of the suspicious binary:

```console
# File type
file /artefacts/malware/suspicious_binary.exe

# Strings (already pre-extracted)
wc -l /artefacts/malware/memory_strings.txt
grep -i "http\|https\|cmd\|powershell\|registry\|sleep\|beacon" /artefacts/malware/memory_strings.txt | head -50
```

**4.2** From the strings output, identify:

* Any hardcoded IP addresses or domain names
* Any C2 protocol indicators (HTTP/HTTPS paths, User-Agent strings)
* Any persistence mechanism indicators (registry key paths, scheduled task names)
* Any anti-analysis techniques (sleep calls, debugger checks, VM detection strings)

**4.3** Search for YARA matches.
A set of Cobalt Strike YARA rules has been pre-loaded in `/artefacts/malware/rules/`:

```console
yara /artefacts/malware/rules/cobaltstrike.yar /artefacts/malware/suspicious_binary.exe
```

**4.4** Based on your analysis, classify the malware:

* Is it consistent with Cobalt Strike Beacon? What indicators support this?
* What capabilities does it appear to have (based on strings)?
* What ATT&CK techniques does it implement?

**Deliverable:** `/tmp/malware_analysis.md`

---

### Part 5 — Kill Chain and Diamond Model Analysis (Estimated: 45 minutes)

**5.1** Map the attack to the Cyber Kill Chain (all 7 stages).
For each stage:

* What evidence supports this stage occurred?
* What artefact or log entry is the key evidence?

**5.2** Complete a Diamond Model analysis:

* **Adversary:** What can you infer? (Sophistication, likely motivation, possibly a known group based on TTPs)
* **Capability:** What tools/techniques were used? Map to ATT&CK
* **Infrastructure:** C2 domain/IP, how was it hosted? (Consider: is this likely dedicated or shared infrastructure?)
* **Victim:** Who was targeted? Why Caldera Pharmaceuticals? (Consider their business: pharmaceutical R&D — IP theft is a likely motive)

**Deliverable:** `/tmp/kill_chain_diamond.md`

---

### Part 6 — Incident Report (Estimated: 1 hour)

Write a professional incident report at `/tmp/incident_report_INC-2024-1147.md`.

Required sections:

1. **Incident Summary** — 1 paragraph executive overview
1. **Timeline of Events** — Chronological table from first indicator to present
1. **Technical Findings** — Summarise network, host, and malware analysis findings
1. **Attack Narrative** — Tell the story of the attack in plain language (2–3 paragraphs)
1. **Indicators of Compromise** — Table of all identified IOCs (IPs, domains, hashes, file paths)
1. **Affected Systems and Data** — What hosts, what data may have been accessed
1. **Containment Actions Taken** — What has been done (even if hypothetical for this exercise)
1. **Recommended Remediation** — At least 6 specific, actionable items
1. **Lessons Learned** — What detection/prevention controls would have stopped this earlier?

**Deliverable:** `/tmp/incident_report_INC-2024-1147.md`

---

## Deliverables Summary

| # | Deliverable | Required Sections |
|---|------------|-------------------|
| 1 | `/tmp/triage_note.md` | 5–10 bullet triage update |
| 2 | `/tmp/network_analysis.md` | C2 mapping, beaconing, exfil indicators |
| 3 | `/tmp/host_forensics.md` | Persistence, lateral movement, initial access |
| 4 | `/tmp/malware_analysis.md` | Static analysis, YARA results, capability classification |
| 5 | `/tmp/kill_chain_diamond.md` | Full kill chain + diamond model |
| 6 | `/tmp/incident_report_INC-2024-1147.md` | All 9 report sections |

---

## Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| Triage note correctly identifies key facts within 30 min of data | 10 |
| Network analysis identifies C2 beaconing and exfiltration | 20 |
| Host forensics identifies persistence mechanism and initial access vector | 20 |
| Malware analysis reaches correct classification with supporting evidence | 15 |
| Kill chain and diamond model are complete and evidence-backed | 15 |
| Incident report is professional, complete, and actionable | 20 |

**Total: 100 points**

---

## Hints

* **Beaconing detection:** Sort connections by time and look for regular intervals between connections to the same IP. A Cobalt Strike default beacon interval is ~60 seconds with ±30% jitter. Look for connections every 42–78 seconds.
* **Initial access:** Check for `WINWORD.EXE` → `cmd.exe` → `PowerShell.exe` process chains in the Windows Event Logs. This is the most common initial access path for targeted attacks.
* **YARA analysis:** Even if you cannot identify the malware family from strings alone, YARA rules will confirm if it matches known Cobalt Strike shellcode patterns.
* **Lateral movement:** Event ID 4624 with LogonType=3 (network logon) from `WS-CALDERA-014` to other hosts is your primary lateral movement indicator.
* **Incident report tone:** Write for two audiences simultaneously — technical (Section 3) and executive (Sections 1, 8, 9). The executive narrative should be readable by someone who does not know what YARA is.
