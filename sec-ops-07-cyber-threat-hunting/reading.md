# Session 07: Cyber Threat Hunting and Intelligence Gathering

**Estimated reading time: ~2 hours**

---

## Table of Contents

1. [Introduction: The Hunt Mindset](#1-introduction-the-hunt-mindset)
1. [Threat Hunting vs. Reactive Detection](#2-threat-hunting-vs-reactive-detection)
1. [Threat Hunting Maturity Model](#3-threat-hunting-maturity-model)
1. [Hypothesis-Driven Hunting](#4-hypothesis-driven-hunting)
1. [Data-Driven Hunting: Statistics and Anomalies](#5-data-driven-hunting-statistics-and-anomalies)
1. [TTP-Driven Hunting with MITRE ATT&CK](#6-ttp-driven-hunting-with-mitre-attck)
1. [Threat Intelligence Lifecycle](#7-threat-intelligence-lifecycle)
1. [Intelligence Sources](#8-intelligence-sources)
1. [Intelligence Types: Tactical, Operational, Strategic](#9-intelligence-types-tactical-operational-strategic)
1. [TLP: Traffic Light Protocol](#10-tlp-traffic-light-protocol)
1. [MISP: Malware Information Sharing Platform](#11-misp-malware-information-sharing-platform)
1. [Threat Actor Profiling](#12-threat-actor-profiling)
1. [Sigma Rules: Writing and Converting Hunting Rules](#13-sigma-rules-writing-and-converting-hunting-rules)
1. [Hunting Tools](#14-hunting-tools)
1. [Analytical Frameworks](#15-analytical-frameworks)
1. [References](#16-references)

---

## 1. Introduction: The Hunt Mindset

Traditional security operations are largely reactive: alerts fire when signatures match, and analysts respond.
This model assumes that defenders know what to look for.
But advanced adversaries—nation-state groups, sophisticated criminal organizations—operate below the threshold of known signatures.
They use legitimate tools, live off the land, and dwell in networks for months before discovery.

Threat hunting is the **proactive, human-driven search for adversaries** that have evaded automated defenses.
It starts from the assumption: *"The adversary is already in my environment.
Where are they hiding?"*

This mindset shift is profound.
Rather than waiting for alerts, hunters:

* Form hypotheses about attacker behavior
* Actively query logs, endpoints, and network traffic
* Look for subtle indicators of compromise that automated systems miss
* Feed findings back into detection engineering to close gaps

### The Cost of Dwell Time

IBM's Cost of a Data Breach Report consistently shows that organizations take an average of **200+ days** to detect a breach.
Every day an adversary dwells in your network, they:

* Expand their foothold (lateral movement)
* Exfiltrate data incrementally
* Establish persistence mechanisms
* Learn your environment better than you do

Threat hunting directly attacks dwell time.
Organizations with mature hunting programs reduce mean time to detect (MTTD) from months to days or even hours.

---

## 2. Threat Hunting vs. Reactive Detection

Understanding the distinction between hunting and detection is fundamental to building an effective security operations program.

### Reactive Detection Model

```text
Threat Actor → Action → Alert Fires → Analyst Responds
```

Reactive detection depends on:

* **Known signatures**: File hashes, IP addresses, domain names
* **Known patterns**: Behavioral rules written against past attacks
* **Automation**: SIEM rules, EDR detections, IDS signatures

**Limitations:**

* Zero-day attacks have no signature
* Living-off-the-land (LotL) attacks use legitimate tools
* Signature evasion is trivial (polymorphic malware, obfuscation)
* Alert fatigue drowns out true positives

### Proactive Hunting Model

```text
Threat Intel → Hypothesis → Data Collection → Analysis → Finding → Detection/Response
         ↑_______________________________________________|
                        (Feedback Loop)
```

Proactive hunting depends on:

* **Human intuition and expertise**: Analysts who understand attacker tradecraft
* **Hypothesis formation**: Structured thinking about attacker behavior
* **Broad telemetry**: Rich data sources beyond just alerts
* **Iterative analysis**: Repeatedly refining queries and pivoting

### Key Differences

| Aspect | Reactive Detection | Proactive Hunting |
|--------|-------------------|-------------------|
| Trigger | Alert or event | Hypothesis or intel |
| Approach | Wait and respond | Seek and find |
| Coverage | Known threats | Known + unknown |
| Output | Incident tickets | New detections + findings |
| Speed | Seconds to minutes | Hours to days |
| Skill required | Tier 1-2 analyst | Senior hunter/researcher |
| Tools | SIEM, EDR alerts | Full telemetry + analysis tools |

### IOC vs. IOA

A critical distinction in hunting philosophy:

**Indicators of Compromise (IOCs)** are artifacts of a past attack:

* File hashes
* IP addresses
* Domain names
* Registry keys

IOCs are **backward-looking**.
By the time a hash is in a threat feed, it's been burned.
Attackers simply generate new infrastructure.

**Indicators of Attack (IOAs)** describe attacker behavior and intent:

* Process spawning patterns (e.g., Word spawning PowerShell)
* Unusual privilege escalation sequences
* Lateral movement via legitimate protocols
* Persistence mechanisms being installed

IOAs are **forward-looking**.
They remain valid even as infrastructure changes because TTPs (Tactics, Techniques, Procedures) persist across campaigns.

---

## 3. Threat Hunting Maturity Model

The SANS Institute and others have developed maturity models for threat hunting programs.
Understanding your current maturity level helps plan improvements.

### Level 0: Initial (Reactive)

**Characteristics:**

* Relies entirely on automated alerting
* No proactive investigation
* Hunting is ad hoc when a major incident occurs
* No dedicated hunting team or process

**Typical organization:** Most small and medium enterprises

**Data sources used:** Firewall logs, AV alerts, maybe a basic SIEM

### Level 1: Minimal (IOC-Based Hunting)

**Characteristics:**

* Searches for known IOCs from threat feeds
* Uses signature-based hunting (hash lookups, IP blocklist checks)
* Reactive to published threat intelligence
* Some documentation of findings

**Typical organization:** Organizations with a basic SIEM and threat feed subscriptions

**Activities:** "We received a report that IP 1.2.3.4 is malicious—let me search our logs for connections to it."

**Limitation:** Only finds known-bad.
Sophisticated attackers are never in IOC feeds until after they've moved on.

### Level 2: Procedural (TTP-Based Hunting)

**Characteristics:**

* Hunts based on documented procedures from threat reports
* Uses MITRE ATT&CK techniques as hunting targets
* Follows established playbooks
* Produces reusable queries and detection content

**Typical organization:** Organizations with mature SOCs and dedicated analysts

**Activities:** "ATT&CK T1059 describes PowerShell execution.
Let me hunt for unusual PowerShell with encoded commands."

### Level 3: Innovative (Data-Driven Hunting)

**Characteristics:**

* Develops novel hunting techniques not previously documented
* Uses statistical analysis to identify anomalies
* Builds custom data models and baselines
* Contributes findings to the broader community

**Typical organization:** Large enterprises, financial sector, healthcare with significant security investment

**Activities:** Creating machine learning models to identify command-and-control beaconing patterns.

### Level 4: Leading (Automated & Continuous)

**Characteristics:**

* Hunting is integrated into SIEM/SOAR as automated detection
* Continuous hunting pipelines run 24/7
* ML/AI assists hypothesis generation
* Contributes to threat intelligence sharing communities
* Measures program effectiveness with metrics

**Typical organization:** Top-tier financial institutions, defense contractors, cloud providers

**The goal of any hunting program:** Findings become detections, detections become automated, which frees hunters to find the next unknown threat.

---

## 4. Hypothesis-Driven Hunting

A hypothesis is the starting point for any structured hunt.
A good hypothesis:

1. Is **testable**: You can query data to prove or disprove it
1. Is **threat-informed**: Based on known attacker behavior or TTPs
1. Is **specific enough** to guide data collection
1. Is **broad enough** to find actual attacker behavior

### The Hypothesis Development Process

**Step 1: Identify the hunting trigger**

Hunting triggers come from several sources:

* New threat intelligence (a new APT report)
* A MITRE ATT&CK technique relevant to your sector
* An anomaly noticed in routine operations
* A new vulnerability disclosure
* Business context (merger, acquisition, high-value project)

**Step 2: Frame the hypothesis**

Use the format: *"If adversary X uses technique Y in environment Z, I would expect to see evidence W in data source D."*

Example:
> "If a threat actor is using PowerShell for lateral movement (T1059.001), I would expect to see PowerShell processes spawned by unusual parent processes (e.g., WMI, scheduled tasks) connecting to internal hosts, which would appear in Windows Event Logs (Event ID 4688) and network logs."

**Step 3: Define data sources and queries**

Map the hypothesis to specific data sources:

* Which log sources contain relevant data?
* What fields are important?
* What baseline is "normal"?

**Step 4: Execute the hunt**

Run queries, visualize data, look for outliers.
This is iterative—initial queries often need refinement.

**Step 5: Document findings**

Whether the hunt finds evidence of compromise or not, document:

* The hypothesis tested
* Data sources used
* Queries run
* Results (positive or negative)
* Recommended detections or monitoring improvements

### Hypothesis Templates

**Template 1: Actor-Based**
> "Based on [threat actor] targeting [my sector], using [technique T1XXX], I hypothesize that [specific observable behavior] exists in my environment."

**Template 2: Environment-Based**
> "Given [recent change in environment], an adversary exploiting [weakness] would likely [action], which would appear as [observable] in [data source]."

**Template 3: Data-Driven**
> "Statistical analysis of [data source] shows an anomaly in [metric] during [time period], which may indicate [malicious behavior]."

### Hunt Documentation: The Hunt Log

Maintain a structured hunt log with:

```markdown
# Hunt ID: HUNT-2024-042
## Hypothesis
PowerShell-based lateral movement via PsExec alternative (T1021.002)

## Trigger
New threat intelligence report on FIN7 activity in retail sector

## Scope
All Windows workstations and servers, last 30 days

## Data Sources
- Windows Security Event Logs (Event ID 4624, 4648, 4688)
- PowerShell Operational Logs (Event ID 4103, 4104)
- Sysmon (Event ID 1, 3, 7)

## Queries
[Attach query files]

## Results
- 3 suspicious PowerShell instances found on finance workstations
- All attributed to legitimate IT admin task (confirmed)
- Identified gap: no alerting on PowerShell with -encodedcommand flag

## Outcome
- Negative hunt (no compromise found)
- New detection rule created: [DETECTION-2024-105]
- Monitoring improved: PowerShell command logging enabled on 200 additional hosts

## Hunter
Jane Smith

## Date
2024-03-15
```

---

## 5. Data-Driven Hunting: Statistics and Anomalies

While hypothesis-driven hunting starts from a specific theory, data-driven hunting starts from the data itself.
Analysts look for statistical anomalies that deviate from baseline behavior.

### Establishing Baselines

Before you can find anomalies, you need to know what "normal" looks like:

**Process baselines:**

* Which processes run on workstations vs. servers?
* What parent-child process relationships are normal?
* What is the typical process execution frequency?

**Network baselines:**

* Which hosts communicate with which external destinations?
* What are typical data transfer volumes?
* When do users typically generate network traffic?

**Authentication baselines:**

* What is the typical login time for each user?
* From which locations do users authenticate?
* What is the normal frequency of authentication failures?

### Statistical Techniques for Hunting

**Frequency Analysis**

Count occurrences of events and look for outliers.
A process that runs once on a single host when it normally runs on 500 hosts is suspicious.

```sql
-- Find rare processes across the enterprise
SELECT process_name, COUNT(DISTINCT hostname) as host_count
FROM process_logs
WHERE timestamp > NOW() - INTERVAL 7 DAY
GROUP BY process_name
HAVING host_count < 3
ORDER BY host_count ASC;
```

**Long Tail Analysis**

In any large dataset, most values cluster in a "head" with a few values forming a long tail.
Malicious activity often appears in the long tail because attackers try to blend in but don't achieve perfect normality.

**Time-Based Anomalies**

Look for activity outside normal business hours:

* Authentication at 3 AM for an account that always logs in 9-5
* Large data transfers on weekends
* Scheduled tasks created outside normal IT change windows

**Beaconing Detection**

C2 (Command and Control) malware typically communicates with its server at regular intervals.
This regularity is detectable:

```python
# Simplified beaconing detection concept
from statistics import stdev

def detect_beaconing(connection_times, threshold_stdev=30):
    """
    connection_times: list of timestamps (in seconds)
    Returns True if regular beacon pattern detected
    """
    if len(connection_times) < 10:
        return False

    intervals = [connection_times[i+1] - connection_times[i]
                 for i in range(len(connection_times)-1)]

    # Low standard deviation = regular intervals = potential beacon
    return stdev(intervals) < threshold_stdev
```

**DNS Anomaly Detection**

Malware often uses DNS for C2.
Look for:

* Unusually high query rates for a single domain
* Long subdomains (potential DNS tunneling: `data.encoded.attacker.com`)
* Queries to newly registered domains (< 30 days old)
* High entropy domain names (DGA - Domain Generation Algorithms)

### Stack Counting

Stack counting is a technique where you count everything, sort by frequency, and investigate the rare items.
The principle: legitimate software is used by many users/systems, malicious software is often unique or rare.

Steps:

1. Select a data type (running processes, parent-child relationships, user agents, etc.)
1. Count all instances
1. Sort ascending (lowest count at top)
1. Investigate the smallest stacks (least common)

Example: Stack counting process-network connections

```text
cmd.exe → 192.0.2.50:443  (count: 1)   ← SUSPICIOUS
iexplore.exe → 198.51.100.5:443  (count: 1)   ← SUSPICIOUS
chrome.exe → 172.217.x.x:443  (count: 8,432)  ← Normal
```

---

## 6. TTP-Driven Hunting with MITRE ATT&CK

The MITRE ATT&CK framework is the most comprehensive publicly available knowledge base of adversary tactics, techniques, and procedures.
It is the primary reference for TTP-driven hunting.

### ATT&CK Structure

**Tactics** represent the adversary's goal (the "why"):

* TA0001: Initial Access
* TA0002: Execution
* TA0003: Persistence
* TA0004: Privilege Escalation
* TA0005: Defense Evasion
* TA0006: Credential Access
* TA0007: Discovery
* TA0008: Lateral Movement
* TA0009: Collection
* TA0010: Exfiltration
* TA0011: Command and Control
* TA0040: Impact

**Techniques** represent how adversaries achieve their goal (the "how"):

* T1059: Command and Scripting Interpreter
  * T1059.001: PowerShell
  * T1059.003: Windows Command Shell
  * T1059.004: Unix Shell

**Sub-techniques** provide additional specificity.

**Procedures** are specific implementations of techniques observed in the wild.

### Using ATT&CK Navigator for Hunting

ATT&CK Navigator is a web-based tool for visualizing and planning hunts against the ATT&CK matrix.

Hunting use cases:

1. **Coverage mapping**: Color-code techniques you currently detect (green) vs. those with no coverage (red)
1. **Priority scoring**: Weight techniques by frequency of use by threat actors targeting your sector
1. **Hunt planning**: Select techniques to hunt for in the next sprint
1. **Gap analysis**: Identify blind spots in your detection coverage

### Example: Hunting for T1055 (Process Injection)

Process injection is used by almost every advanced threat actor.
Sub-techniques include:

* T1055.001: Dynamic-link Library Injection
* T1055.002: Portable Executable Injection
* T1055.003: Thread Execution Hijacking
* T1055.012: Process Hollowing

**What to look for:**

```text
Data Sources:
- Sysmon Event ID 8 (CreateRemoteThread)
- Sysmon Event ID 10 (ProcessAccess with suspicious rights)
- Windows API calls: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread

Hunting Queries (Pseudo-SPL):
index=sysmon EventID=8
| stats count by SourceImage, TargetImage
| where count < 5
| sort count

index=sysmon EventID=10
| where GrantedAccess IN ("0x1fffff", "0x1410", "0x143a")
| stats count by SourceImage, TargetImage
```

### ATT&CK Groups as Hunting Targets

Each ATT&CK Group page documents which techniques a threat actor uses.
If you determine that APT29 (Cozy Bear) is likely targeting your sector:

1. Navigate to ATT&CK Groups → APT29
1. Export the technique list
1. For each technique, assess: Do I have coverage? Can I hunt for it?
1. Prioritize high-frequency, low-coverage techniques

### Operationalizing ATT&CK

The ATT&CK framework is a starting point, not a complete solution.
To operationalize it:

1. **Select relevant groups**: Which threat actors target your sector/geography?
1. **Map to your environment**: Which ATT&CK techniques apply to your stack?
1. **Assess coverage**: Do your current detections cover these techniques?
1. **Prioritize hunts**: Use frequency and impact to prioritize
1. **Create detections**: Every positive hunt becomes a new rule

---

## 7. Threat Intelligence Lifecycle

Threat intelligence is more than collecting IOCs from feeds.
It is a structured process of converting raw data into actionable knowledge.

### Phase 1: Planning and Direction

Before collecting intelligence, define requirements:

* **Who needs this intelligence?** Executive leadership needs strategic intel; SOC analysts need tactical.
* **What decisions will it inform?** Patch prioritization? Network segmentation? IR planning?
* **What are the priority intelligence requirements (PIRs)?**

Example PIRs for a financial institution:

1. "What threat actors are currently targeting our sector?"
1. "What techniques are they using that we don't currently detect?"
1. "Are any of our third-party vendors compromised?"

### Phase 2: Collection

Gathering raw data from intelligence sources (covered in Section 8).

Collection considerations:

* **Breadth vs. depth**: Many sources provide breadth; deep investigation provides depth
* **Signal vs. noise**: More sources = more noise; requires good filtering
* **Legal/ethical**: Ensure collection methods are legal in your jurisdiction

### Phase 3: Processing

Converting raw data into a usable format:

* Normalizing data formats (e.g., converting various IOC formats to STIX)
* Removing duplicates
* Enriching indicators (adding context: WHOIS, VirusTotal scores, geolocation)
* Assessing reliability and confidence

**Confidence scoring:**

| Level | Description |
|-------|-------------|
| Confirmed | Verified by multiple independent sources |
| Probable | Likely true based on available evidence |
| Possible | Some evidence supports this |
| Unlikely | Evidence is weak or contradictory |
| Doubtful | Strong contrary evidence exists |

### Phase 4: Analysis

Transforming processed data into intelligence:

* **Pattern recognition**: Identifying connections between indicators
* **Attribution**: Linking activity to known actors
* **Trend analysis**: Identifying changes in adversary behavior
* **Gap analysis**: What do we still not know?

Key analytic techniques:

* **ACH (Analysis of Competing Hypotheses)**: Systematically evaluating multiple hypotheses
* **Kill chain mapping**: Placing observations in the attack lifecycle
* **Diamond model analysis**: Mapping adversary, infrastructure, capability, victim relationships

### Phase 5: Dissemination

Getting intelligence to the right people at the right time:

* **Format**: Match format to audience (STIX/TAXII for automated, narrative reports for executives)
* **Timeliness**: Flash reports for urgent IOCs; weekly reports for trends
* **Actionability**: Every piece of intelligence should enable a decision or action

### Phase 6: Feedback

Intelligence consumers provide feedback:

* Was the intelligence accurate?
* Was it timely?
* Was it actionable?
* What additional context would have helped?

This feedback improves future intelligence production.

---

## 8. Intelligence Sources

### Open Source Intelligence (OSINT)

OSINT encompasses all publicly available information:

**Threat intelligence feeds (free):**

* **AlienVault OTX (Open Threat Exchange)**: Community-driven IOC sharing platform
* **MISP default feeds**: Curated feeds from CIRCL and other organizations
* **Abuse.ch**: Malware, botnet C2 tracking (URLhaus, MalwareBazaar, FeodoTracker)
* **Shodan**: Internet-connected device intelligence (also commercial)
* **Censys**: Similar to Shodan, strong on certificates

**Security research:**

* Threat actor reports from CrowdStrike, Mandiant, Secureworks, Recorded Future
* Academic papers and conference presentations (DEF CON, Black Hat, USENIX)
* Government advisories (CISA, NCSC, BSI)
* CVE/NVD databases

**Social media and forums:**

* Twitter/X: Security researchers share IOCs in real-time
* GitHub: Malware samples, IOC repositories, detection rules
* Reddit (r/netsec, r/cybersecurity)

**Passive DNS and certificate transparency:**

* **RiskIQ/Microsoft Defender Threat Intelligence**: Passive DNS
* **Censys Certificate Search**: Find attacker infrastructure via TLS certificates

### Information Sharing and Analysis Centers (ISACs)

ISACs are sector-specific organizations for sharing threat intelligence among peers:

| ISAC | Sector |
|------|--------|
| FS-ISAC | Financial Services |
| H-ISAC | Healthcare |
| E-ISAC | Energy |
| Aviation ISAC | Aviation |
| RH-ISAC | Retail and Hospitality |
| MS-ISAC | State/Local Government |

ISACs provide:

* Sector-specific threat intelligence
* Trusted sharing under TLP guidelines
* Incident coordination
* Working groups and exercises

### Commercial Threat Intelligence Feeds

Commercial feeds provide higher-quality, curated intelligence:

| Vendor | Specialization |
|--------|----------------|
| Recorded Future | Predictive intelligence, dark web monitoring |
| CrowdStrike Intelligence | Adversary tracking, nation-state activity |
| Mandiant/Google | Incident response intel, APT tracking |
| Intel 471 | Underground forums, criminal actors |
| Flashpoint | Deep/dark web, fraud |
| Team Cymru | BGP routing, network intelligence |

### Dark Web Monitoring

The dark web (Tor network) and deep web contain:

* Ransomware leak sites
* Criminal marketplaces selling access and data
* Hacking forums with TTPs and tools
* Initial access brokers advertising corporate access

**Monitoring approaches:**

* Commercial services (Flashpoint, Intel 471, Digital Shadows)
* Manual monitoring (requires operational security)
* Honeypots and sinkhole monitoring

**What to monitor for:**

* Mentions of your organization or domain
* Credentials for your employees
* Access listings to your industry
* New malware/exploit discussions

### Human Intelligence (HUMINT)

In the threat intelligence context, HUMINT refers to:

* Relationships with law enforcement (FBI, CISA partnerships)
* Industry peer relationships
* Vendor partnerships with intelligence-sharing agreements
* Infiltration of threat actor forums (specialized capability)

---

## 9. Intelligence Types: Tactical, Operational, Strategic

Not all intelligence serves the same purpose.
Different audiences need different intelligence types.

### Tactical Intelligence

**What it is:** Low-level, highly specific, short-lived indicators of compromise.

**Examples:**

* IP addresses associated with C2 servers
* File hashes of malware samples
* Domain names used in phishing campaigns
* Email addresses of phishing senders
* Registry keys created by malware
* Mutex names

**Consumer:** SOC analysts, incident responders, SIEM/firewall engineers

**Lifespan:** Hours to days (attackers rotate infrastructure constantly)

**Action:** Block IP in firewall, add hash to EDR blocklist, create SIEM alert

**Format:** STIX indicators, flat IOC lists, MISP events

### Operational Intelligence

**What it is:** Information about specific campaigns and threat actor activity.
More context than tactical.

**Examples:**

* "FIN7 is currently targeting restaurant chains in the US using spear-phishing with fake job applications"
* "Cobalt Strike Team Server configurations attributed to APT28 cluster"
* Campaign TTPs and tools

**Consumer:** Threat hunters, SOC managers, incident responders

**Lifespan:** Weeks to months

**Action:** Prioritize hunts against FIN7 TTPs, review phishing defenses, hunt for Cobalt Strike beacons

**Format:** Intelligence reports, analyst notes, MISP events with context

### Strategic Intelligence

**What it is:** High-level intelligence about the threat landscape, trends, and risk.

**Examples:**

* "Nation-state groups are increasingly targeting energy sector OT environments in advance of geopolitical events"
* "Ransomware-as-a-Service ecosystem has matured; average ransom demands have increased 80% YoY"
* "Supply chain attacks via software build pipelines are an emerging trend"

**Consumer:** CISO, board of directors, risk management

**Lifespan:** Months to years

**Action:** Investment decisions, policy changes, strategic security programs

**Format:** Executive briefings, risk reports, trend analyses

### The Intelligence Pyramid

```text
        Strategic
      (Why / So What?)
       /____________\
      /  Operational  \
     / (Who / When?)   \
    /___________________\
   /      Tactical        \
  /  (What / IoCs / TTPs)  \
 /___________________________\
            Raw Data
```

---

## 10. TLP: Traffic Light Protocol

The Traffic Light Protocol (TLP) was created by FIRST (Forum of Incident Response and Security Teams) to enable appropriate sharing of sensitive information.

### TLP Colors

**TLP:RED** - Not for disclosure, restricted to participants only

* Information shared at TLP:RED must not be shared with any party not in attendance
* Use when: Information is highly sensitive and sharing could harm the source or ongoing operations
* Example: Information about an active ongoing compromise that the victim is still investigating

**TLP:AMBER** - Limited disclosure to organization and clients

* Recipients may share with members of their own organization and clients who need to know
* Use when: Information carries some risk to privacy or reputation
* Example: A vulnerability that has a workaround but no patch yet

**TLP:AMBER+STRICT** - Disclosure limited to the recipient's organization only

* Unlike AMBER, cannot be shared with clients; organization-internal only
* Use when: Recipients need to be aware but sharing beyond the org would cause harm

**TLP:GREEN** - Disclosure to community

* Information may be shared with peers and partner organizations within the community
* Not for public disclosure
* Example: IOC feeds shared within an ISAC community

**TLP:WHITE / TLP:CLEAR** - Unlimited disclosure

* Information may be shared freely
* No risk of misuse
* Example: Public threat reports, CVE descriptions

### TLP in Practice

When receiving intelligence:

1. Check the TLP marking
1. Ensure you only share within the permitted boundaries
1. When forwarding, maintain or restrict (never expand) the TLP designation
1. Document your intelligence handling practices

When creating intelligence:

1. Apply the most restrictive TLP that still enables appropriate sharing
1. Consider the potential harm of wider disclosure
1. Communicate with recipients when TLP changes

---

## 11. MISP: Malware Information Sharing Platform

MISP is an open-source threat intelligence platform designed for sharing, storing, and correlating IOCs and threat intelligence.

### Core Concepts

**Events**

An Event is the primary container in MISP.
Each event represents a piece of intelligence:

* A malware campaign
* A phishing wave
* An APT intrusion set
* A vulnerability exploitation

Events have:

* A date (when the intelligence was first observed)
* A threat level (informational, low, medium, high)
* An analysis status (initial, ongoing, complete)
* A distribution setting (your organization, community, all)
* Tags (MITRE ATT&CK, TLP, kill chain phases)

**Attributes**

Attributes are the individual data points within an event:

* `ip-dst`: Destination IP address
* `domain`: Domain name
* `md5`, `sha1`, `sha256`: File hashes
* `url`: Malicious URL
* `email-src`: Phishing sender
* `filename`: Malware filename
* `yara`: YARA detection rule
* `snort`: Snort/Suricata rule

**Objects**

Objects group related attributes that represent a single entity:

* File object: filename + multiple hashes + file size + mime type
* Network connection: src IP + dst IP + port + protocol
* Email: from + to + subject + attachment

**Tags and Taxonomies**

MISP supports standardized taxonomies:

* **MITRE ATT&CK**: Tag events with specific techniques
* **Kill chain**: Tag with attack phase (reconnaissance, weaponization, delivery, etc.)
* **TLP**: Apply traffic light protocol markings
* **ENISA threat taxonomy**: Categorize threat types

**Galaxies**

Galaxies are knowledge bases expressed in MISP format:

* **Threat Actors Galaxy**: ATT&CK Groups, Threat Actors with known TTPs
* **Malware Galaxy**: Known malware families and their characteristics
* **ATT&CK Galaxy**: Full MITRE ATT&CK techniques

**Feeds**

MISP can consume external feeds:

* CIRCL OSINT feed
* Abuse.ch feeds
* MISP default feeds

### MISP Architecture

```text
External Feeds → MISP Instance → Sharing Groups → Partner Organizations
                     ↕
               Local Analysts
                     ↕
               SOC Tools (SIEM, EDR via API)
```

### MISP API Usage

MISP has a comprehensive REST API for integration:

```python
from pymisp import PyMISP

misp = PyMISP('https://your-misp-instance.org', 'your-api-key')

# Search for events related to APT28
events = misp.search(value='APT28', type_attribute='threat-actor')

# Get all IOCs from last 7 days
iocs = misp.search(
    publish_timestamp='7d',
    type_attribute=['ip-dst', 'domain', 'url'],
    to_ids=True  # Only return indicators flagged for detection
)

# Add a new indicator
event = misp.new_event(
    distribution=1,  # Organization only
    threat_level_id=2,  # Medium
    analysis=0,  # Initial
    info='Phishing campaign targeting finance sector'
)

misp.add_attribute(event['Event']['id'], {
    'type': 'ip-dst',
    'value': '192.0.2.50',
    'comment': 'C2 server',
    'to_ids': True
})
```

### MISP Sharing Communities

MISP enables trusted communities where organizations share intelligence:

**Public communities:**

* CIRCL (Computer Incident Response Center Luxembourg) MISP instance
* MISP Project public feeds

**Sector communities:**

* ISAC-operated MISP instances (FS-ISAC, H-ISAC)

**National communities:**

* Many national CERTs operate MISP instances for their constituents

**Private communities:**

* Organizations can create their own sharing groups with trusted partners

---

## 12. Threat Actor Profiling

Threat actor profiling is the process of building a comprehensive picture of an adversary to enable better defense and attribution.

### Components of a Threat Actor Profile

**1.
Identity and Attribution**

* Names and aliases (APT28, Fancy Bear, Sofacy, Strontium)
* Attribution confidence level
* Suspected sponsorship (nation-state, criminal organization, hacktivist)
* Geographic origin

**2.
Motivation and Objectives**

* Espionage (IP theft, government secrets)
* Financial (ransomware, BEC, banking fraud)
* Disruption (destructive attacks, DDoS)
* Hacktivism (ideological)

**3.
Target Sectors and Geography**

* Which industries are targeted?
* Which geographic regions?
* Why? (Strategic value, financial value, vulnerability)

**4.
Tactics, Techniques, and Procedures (TTPs)**

* ATT&CK techniques used
* Preferred initial access vectors
* Tools and malware families
* Operational security practices

**5.
Infrastructure**

* IP ranges used historically
* Domain registration patterns
* Hosting providers preferred
* Certificate patterns

**6.
Tools and Malware**

* Custom malware (indicates high sophistication)
* Modified commodity malware
* Open-source/offensive tools (Metasploit, Cobalt Strike)
* Living-off-the-land binaries (LOLBins)

### The Diamond Model of Intrusion Analysis

The Diamond Model provides a structured framework for analyzing intrusions:

```text
          Adversary
         /         \
        /           \
  Infrastructure ——— Capability
         \           /
          \         /
            Victim
```

**Four core features:**

* **Adversary**: The actor behind the intrusion
* **Infrastructure**: The technical systems used (IPs, domains, servers)
* **Capability**: Tools, TTPs, and methods used
* **Victim**: The target of the intrusion

**Meta-features:**

* Timestamp
* Phase (kill chain phase)
* Result (success/failure)
* Direction (adversary-to-victim vs. victim-to-adversary)
* Methodology
* Resources

**Pivoting with the Diamond Model:**

Once you identify one element, you can pivot to discover others:

* Known adversary → What infrastructure do they typically use?
* Known infrastructure (C2 IP) → What other victims connected to this IP?
* Known malware → What other actors use this malware?
* Known victim industry → What other organizations in this sector were targeted?

### The Pyramid of Pain

The Pyramid of Pain (David Bianco, 2013) illustrates the relative difficulty of using different types of indicators:

```text
          /\
         /  \
        / TTP\  ← Extremely Hard to Change
       /______\
      / Tools  \ ← Difficult
     /__________\
    /  Network   \
   /  Artifacts   \ ← Annoying
  /________________\
 /  Host Artifacts  \← Annoying
/____________________\
      Domain Names    ← Simple
________________________
      IP Addresses     ← Easy
________________________
   Hash Values (MD5)   ← Trivial
```

**Implications for hunting:**

* Hunting for file hashes (bottom) is low impact—attackers change these trivially
* Hunting for TTPs (top) is high impact—changing fundamental tradecraft requires significant effort
* Mature hunters focus on TTPs and tools, not just IOCs

### Attribution Challenges

Attribution is difficult and frequently overstated:

**Technical limitations:**

* False flags (attackers deliberately use another group's tools)
* Shared infrastructure (multiple actors use the same bulletproof hosting)
* Tool sharing (nation-state groups sell/share tools with criminals)
* VPNs and proxies obscure true origin

**Organizational limitations:**

* Most organizations don't have enough data for attribution
* Attribution requires correlating across many incidents
* Commercial pressure to attribute creates confirmation bias

**Best practice:** Attribute with explicit confidence levels.
Never say "this is definitely APT28" without substantial evidence.
Instead: "This activity shares TTPs with APT28 with moderate confidence (3 of 4 TTPs matched, infrastructure overlaps found in 2 separate incidents)."

---

## 13. Sigma Rules: Writing and Converting Hunting Rules

Sigma is an open, vendor-neutral signature format for SIEM systems.
Think of it as YARA for logs.

### Sigma Rule Structure

```yaml
title: Suspicious PowerShell Encoded Command
id: 4b0f1a8e-91c4-4c23-8d7a-3b5e2e4f9d1a
status: experimental
description: Detects PowerShell execution with encoded command parameter,
             often used to obfuscate malicious scripts
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: Your Name
date: 2024/01/15
modified: 2024/03/20
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
            - '-ec '
    condition: selection
falsepositives:
    - Legitimate administrative scripts using encoded commands
    - Software deployment tools
level: medium
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
```

### Sigma Rule Components

**logsource:**
Defines the data source:

```yaml
logsource:
    category: process_creation   # Generic category
    product: windows             # Specific product
    # OR:
    service: sysmon             # Specific service
    # OR:
    product: apache              # Web server logs
    category: webserver
```

**detection:**
Contains the matching logic:

```yaml
detection:
    # Selection: what to look for
    selection_main:
        EventID: 4624
        LogonType: 3

    # Additional filter to narrow down
    filter_legitimate:
        SubjectUserName|endswith: '$'   # Machine accounts

    # Keywords: search in full log line
    keywords:
        - 'mimikatz'
        - 'sekurlsa'

    # Condition: boolean logic combining selections
    condition: selection_main and not filter_legitimate
```

**Condition operators:**

* `and`: Both conditions must match
* `or`: Either condition must match
* `not`: Negate a condition
* `1 of selection_*`: Match 1 or more selections with prefix
* `all of selection_*`: Match all selections with prefix
* `x of them`: x conditions from all selections must match

### Advanced Sigma Modifiers

```yaml
detection:
    selection:
        CommandLine|contains: 'payload'       # Contains string
        CommandLine|contains|all:             # Contains ALL strings
            - 'payload'
            - 'execute'
        CommandLine|startswith: 'C:\Temp'     # Starts with
        CommandLine|endswith: '.ps1'          # Ends with
        CommandLine|re: '.*-[Ee][Nn][Cc].*'  # Regex match
        CommandLine|base64offset|contains:   # B64 decoded contains
            - 'whoami'
        EventID|in:                          # Value in list
            - 4624
            - 4625
            - 4634
        SourceAddress|cidr: '192.168.0.0/16' # CIDR range
        field|expand: '%AdminAccounts%'       # Reference to list
```

### Converting Sigma Rules

Sigma rules are backend-independent.
The `sigma` CLI tool converts them to SIEM query languages:

```bash
# Install sigmac (legacy) or sigma-cli (new)
pip install sigma-cli

# Convert to Splunk
sigma convert -t splunk rule.yml

# Convert to Elastic EQL
sigma convert -t elasticsearch-eql rule.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t azure-monitor rule.yml

# Convert to Chronicle YARA-L
sigma convert -t chronicle rule.yml

# Convert with pipeline (field mappings)
sigma convert -t splunk -p sysmon rule.yml

# Convert multiple rules
sigma convert -t splunk rules/
```

**Converting Sigma to Splunk SPL:**

```text
# Output example for the PowerShell rule:
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
(CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *" OR CommandLine="*-ec *")
```

**Converting to Elastic Query DSL:**

```json
{
  "query": {
    "bool": {
      "must": [
        {"wildcard": {"process.executable": "*\\powershell.exe"}},
        {"bool": {
          "should": [
            {"wildcard": {"process.command_line": "*-EncodedCommand*"}},
            {"wildcard": {"process.command_line": "*-enc *"}}
          ]
        }}
      ]
    }
  }
}
```

### Writing Effective Sigma Rules

**Focus on high-fidelity indicators:**

Bad (too broad):

```yaml
detection:
    selection:
        CommandLine|contains: 'powershell'
```

Better (more specific):

```yaml
detection:
    selection_base:
        CommandLine|contains|all:
            - 'powershell'
            - '-nop'
            - '-w hidden'
            - 'IEX'
    condition: selection_base
```

**Use meaningful false positive documentation:**
Document known legitimate uses.
This helps tuning and reduces alert fatigue.

**Test your rules:**
Use the `sigma-test` tool or run against known-good and known-bad datasets.

### Sigma Rule Repositories

* **SigmaHQ**: Official rule repository with 2000+ rules
* **Elastic Detection Rules**: Elastic-maintained rules
* **SOC Prime Threat Detection Marketplace**: Commercial rule marketplace
* **MITRE Cyber Analytics Repository (CAR)**: MITRE-maintained analytics

---

## 14. Hunting Tools

### Osquery

Osquery exposes the operating system as a relational database, allowing SQL-like queries across system state.

```sql
-- Find all listening processes and their connection counts
SELECT p.name, p.pid, l.address, l.port, l.protocol
FROM processes p
JOIN listening_ports l ON p.pid = l.pid
WHERE l.address != '127.0.0.1';

-- Find recently modified executables
SELECT path, mtime, sha256
FROM file
WHERE path LIKE '/usr/bin/%'
AND mtime > (SELECT strftime('%s', 'now') - 86400);

-- Find suspicious scheduled tasks (Windows)
SELECT name, action, path, enabled
FROM scheduled_tasks
WHERE action LIKE '%powershell%'
OR action LIKE '%cmd.exe%'
OR action LIKE '%wscript%';

-- Detect LOLBins with network connections
SELECT p.name, p.path, proc.local_address, proc.remote_address
FROM processes p
JOIN process_open_sockets proc ON p.pid = proc.pid
WHERE p.name IN ('certutil.exe', 'bitsadmin.exe', 'mshta.exe', 'regsvr32.exe');
```

Osquery can be deployed as a fleet management tool (Fleet, Kolide, osquery Manager) to query thousands of endpoints simultaneously.

### Velociraptor

Velociraptor is a powerful digital forensics and incident response (DFIR) platform ideal for threat hunting at scale.

**Key features:**

* VQL (Velociraptor Query Language) for flexible artifact collection
* Pre-built artifacts for common hunts
* Real-time collection from endpoints
* Timeline analysis
* Memory forensics

**Example VQL hunt for suspicious parent-child relationships:**

```sql
SELECT Name, Pid, Ppid, CommandLine,
       Exe, Username, CreateTime
FROM pslist()
WHERE Ppid IN (
    SELECT Pid FROM pslist()
    WHERE Name = 'winword.exe'
    OR Name = 'excel.exe'
    OR Name = 'powerpnt.exe'
)
```

**Running a hunt:**

```console
# Deploy a hunt for all endpoints
velociraptor artifacts collect Windows.System.Pslist --args
# Export results to CSV/JSON for analysis
```

### MITRE ATT&CK Navigator

A web-based tool for visualizing the ATT&CK matrix:

**Use cases for hunters:**

* **Heat map**: Color-code techniques by frequency in threat reports targeting your sector
* **Coverage map**: Mark techniques you currently detect (green) vs. hunting targets (yellow) vs. gaps (red)
* **Multi-layer comparison**: Compare your detection coverage against an adversary's known TTPs

**Creating a coverage map:**

1. Open ATT&CK Navigator
1. Create a new layer
1. Select "Techniques"
1. Color code:
   * Red: No coverage, high priority
   * Yellow: Partial coverage or only hunting
   * Green: Automated detection
1. Export to JSON/SVG for reporting

### ELK Stack (Elasticsearch, Logstash, Kibana)

The ELK stack is commonly used for log aggregation and analysis:

**Hunt queries in Kibana:**

```text
# Find processes with network connections using EQL
process where process.name == "powershell.exe" and
network.direction == "outgoing"

# Find lateral movement indicators
sequence by host.name with maxspan=5m
  [process where process.name == "net.exe" and process.args : "user"]
  [process where process.name == "net.exe" and process.args : "localgroup"]
```

### TheHive and Cortex

**TheHive**: Case management platform for coordinating hunt and incident response activities.

* Track hunt findings as cases
* Assign tasks to team members
* Document evidence and timeline

**Cortex**: Observable analysis engine that integrates with TheHive:

* Automated enrichment of IOCs
* Integration with VirusTotal, Shodan, PassiveDNS
* Returns structured analysis results

### OpenCTI

OpenCTI (Open Cyber Threat Intelligence) is a platform for storing, organizing, and sharing cyber threat intelligence:

* STIX 2.1 native data model
* Integrates with MITRE ATT&CK
* Connects to MISP, TheHive
* Supports complex relationship mapping between entities
* Role-based access control for intelligence compartmentalization

---

## 15. Analytical Frameworks

### The Lockheed Martin Cyber Kill Chain

The Kill Chain models a cyberattack as a sequence of stages:

```text
1. Reconnaissance    → Researching the target

2. Weaponization     → Creating the attack payload
3. Delivery          → Sending the payload to the victim
4. Exploitation      → Triggering the vulnerability
5. Installation      → Installing malware/backdoor
6. C2 (Command & Control) → Establishing communication
7. Actions on Objectives  → Exfiltration, disruption, etc.
```

**Kill chain in hunting:**

* If you detect delivery but not installation, what happened next?
* Which phase is your detection coverage strongest/weakest?
* At which phase do you want to detect and respond?

**Limitation:** Linear model doesn't capture all modern attacks (e.g., insider threats, supply chain attacks, living-off-the-land).

### The Diamond Model

(Covered in Section 12, Threat Actor Profiling)

The Diamond Model complements the Kill Chain by focusing on the relationships between adversary elements rather than the sequence of attack.

**Diamond Model for hunting:**

* Pivot from known C2 infrastructure to find other victims (infrastructure → victim)
* Pivot from known malware to find other campaigns (capability → adversary)
* Pivot from victim to find related victims (victim → adversary → victim)

### MITRE ATT&CK

(Covered in depth in Section 6)

### The Pyramid of Pain

(Covered in Section 12, Threat Actor Profiling)

### F3EAD Intelligence Cycle

A military intelligence model adapted for threat intelligence:

* **Find**: Identify potential threats
* **Fix**: Determine their location and status
* **Finish**: Take action (remediate, block)
* **Exploit**: Extract intelligence from the action
* **Analyze**: Understand what the intelligence means
* **Disseminate**: Share intelligence to inform future cycles

### The Intelligence Confidence Ladder

Structured analytic technique for communicating confidence:

| Qualifier | Confidence |
|-----------|------------|
| We assess with high confidence | 85-95% |
| We assess | 55-85% |
| We assess with moderate confidence | 55-75% |
| We assess with low confidence | 30-55% |
| We cannot assess | < 30% |

Always pair assessments with the evidence and reasoning that supports them.

---

## 16. References

### Frameworks and Standards

* MITRE ATT&CK Framework: https://attack.mitre.org
* MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
* FIRST TLP Standard: https://www.first.org/tlp/
* STIX/TAXII Standard: https://oasis-open.github.io/cti-documentation/
* Sigma Rules Project: https://github.com/SigmaHQ/sigma
* MITRE CAR (Cyber Analytics Repository): https://car.mitre.org

### Books

* *The Practice of Network Security Monitoring* - Richard Bejtlich
* *Intelligence-Driven Incident Response* - Scott Roberts, Rebekah Brown
* *The Threat Intelligence Handbook* - CrowdStrike
* *Applied Network Security Monitoring* - Chris Sanders, Jason Smith
* *Practical Threat Intelligence and Data-Driven Threat Hunting* - Valentina Costa-Gazcón

### Research Papers and Reports

* "Tracking Threat Actors Through Changes in Their Infrastructure" - Palo Alto Unit 42
* "APT1: Exposing One of China's Cyber Espionage Units" - Mandiant (2013)
* "The Diamond Model of Intrusion Analysis" - Caltagirone, Pendergast, Betz (2013)
* "Pyramid of Pain" - David Bianco (2013)
* SANS Threat Hunting Survey (Annual)

### Tools Documentation

* MISP Project: https://www.misp-project.org/documentation/
* Osquery Documentation: https://osquery.readthedocs.io
* Velociraptor Documentation: https://docs.velociraptor.app
* Sigma Documentation: https://sigmahq.io
* OpenCTI Documentation: https://docs.opencti.io

### Threat Intelligence Communities

* OTX AlienVault: https://otx.alienvault.com
* Abuse.ch: https://abuse.ch
* MISP CIRCL Feeds: https://www.circl.lu/services/misp-information-sharing/
* Threat Intelligence Platform Comparison: https://www.g2.com/categories/threat-intelligence

### Training Resources

* SANS FOR578: Cyber Threat Intelligence
* SANS FOR608: Enterprise-Class Incident Response and Threat Hunting
* MITRE ATT&CK Defender Training: https://mad.mitre-engenuity.org
* Cyberdefenders: https://cyberdefenders.org
* Blue Team Labs Online: https://blueteamlabs.online

---

*End of Session 07 Reading Material*

*Next Session: Session 08 - Security Automation and SOAR*
