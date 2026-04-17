# Demo 03: Network Topology Analysis — Identifying Monitoring Gaps

**Level:** Beginner–Intermediate

**Duration:** 45–60 minutes

**Format:** Analysis exercise (no code required)
**Learning objectives:**

* Analyse a provided network topology description to identify monitoring capabilities and blind spots
* Apply knowledge of TAPs, SPAN ports, firewall logs, and flow records to assess coverage
* Identify high-risk assets that lack visibility
* Produce a structured monitoring gap analysis report

---

## Background

Before deploying any monitoring tool, a security team must understand what is — and is not — visible in the current network architecture.
This process is called a **visibility assessment** or **monitoring gap analysis**.

Even organisations with mature security teams often have significant blind spots:

* Internal (east-west) traffic between hosts on the same VLAN is invisible to perimeter monitoring
* VPN concentrators that don't generate logs leave remote access unmonitored
* Legacy systems that don't support NetFlow or syslog create islands of invisibility
* Encrypted traffic (HTTPS) without inspection leaves payload content opaque

In this demo, you will analyse a realistic (but fictional) company network and systematically identify where monitoring exists and where it is absent.

---

## Scenario: Meridian Financial Services

**Company profile:**
Meridian Financial Services is a mid-sized investment firm with 250 employees.
Their IT environment consists of a corporate headquarters and one remote branch office.

### Current Network Architecture

```text
╔══════════════════════════════════════════════════════════════════════════╗
║  INTERNET                                                                ║
╚════════════════════════════╦═════════════════════════════════════════════╝
                             │  1 Gbps ISP uplink
                             │
                    ┌────────┴────────┐
                    │   Edge Router   │  (Cisco ASR 1001)
                    │  BGP to ISP     │  → No NetFlow configured
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    │  Outer Firewall │  (Palo Alto PA-3250)
                    │  Logs: yes      │  → Syslog to SIEM
                    └──┬──────────┬───┘
                       │          │
              ┌────────┴──┐    ┌──┴─────────────────────────┐
              │  DMZ Zone │    │       Internal LAN          │
              │ 10.0.1./24│    │                             │
              └─────┬─────┘    └─────────────────────────────┘
                    │                          │
        ┌───────────┴──────────┐      ┌────────┴────────┐
        │  DMZ Switch (L2)     │      │  Core Switch    │
        │  No SPAN configured  │      │  (Cisco C9300)  │
        └──┬────────────┬──────┘      │  SPAN on 2/4    │
           │            │             │  uplink ports   │
   ┌───────┴──┐  ┌──────┴──────┐     └───┬───┬───┬─────┘
   │Web Server│  │Email Gateway│         │   │   │
   │10.0.1.10 │  │ 10.0.1.11  │    ┌────┘   │   └────────────┐
   │Logs: none│  │Logs: SMTP   │    │        │                │
   └──────────┘  └─────────────┘    │        │                │
                                ┌───┴──┐  ┌──┴───┐  ┌────────┴──────┐
                                │VLAN10│  │VLAN20│  │VLAN30 Finance │
                                │Users │  │Serv  │  │(PCI-DSS scope)│
                                │/24   │  │/24   │  │ 10.10.30./24  │
                                │No    │  │AD,DB │  │ No dedicated  │
                                │monitor│ │logs  │  │ monitoring    │
                                └──────┘  └──────┘  └───────────────┘
                                              │
                                        ┌─────┴──────┐
                                        │  Database  │
                                        │ SQL Server │
                                        │No net logs │
                                        └────────────┘

    ┌──────────────────────────────────────────────────────┐
    │  BRANCH OFFICE (connected via IPsec VPN)             │
    │  30 users, flat network 10.50.0.0/24                 │
    │  Single consumer router — no logs, no monitoring     │
    └──────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────┐
    │  REMOTE ACCESS (Split-tunnel VPN)                    │
    │  VPN Concentrator: FortiGate 100F                    │
    │  Logs: connection start/stop to SIEM                 │
    │  Split tunnel: only 10.0.0.0/8 through VPN          │
    │  Employee internet traffic bypasses VPN entirely     │
    └──────────────────────────────────────────────────────┘

    Current monitoring tools:
    - SIEM: Splunk (receives: PA firewall logs, VPN logs, email gateway)
    - No IDS/IPS deployed
    - No network flow collection
    - No Zeek or packet capture capability
    - SPAN port configured on Core Switch (only covers inter-VLAN traffic)
    - SPAN port currently connected to nothing
```

---

## Part 1: Mapping Existing Visibility

Complete the following visibility matrix by identifying what data is currently available for each network zone/component:

| Component | Data Available | Tool/Source | Gaps |
|-----------|---------------|-------------|------|
| Internet ↔ Edge Router | ? | ? | ? |
| Edge Router ↔ Outer Firewall | ? | ? | ? |
| Outer Firewall | ? | ? | ? |
| DMZ (all traffic) | ? | ? | ? |
| Web Server (10.0.1.10) | ? | ? | ? |
| Email Gateway (10.0.1.11) | ? | ? | ? |
| Core LAN Switch | ? | ? | ? |
| VLAN 10 (Users) | ? | ? | ? |
| VLAN 20 (Servers/AD/DB) | ? | ? | ? |
| VLAN 30 (Finance/PCI) | ? | ? | ? |
| SQL Database | ? | ? | ? |
| Branch Office | ? | ? | ? |
| Remote Access VPN | ? | ? | ? |
| Employee internet (split tunnel) | ? | ? | ? |

**Instructions:** For each row, determine:

* What monitoring data exists today?
* From which tool or log source?
* What important visibility is missing?

---

## Part 2: Risk Assessment of Monitoring Gaps

For each monitoring gap identified in Part 1, assess its risk level:

**Risk scoring criteria:**

* **Criticality of asset:** Does this zone contain sensitive data (PCI-DSS scope, PII, credentials)?
* **Likelihood of attack:** Is this zone exposed to external threats or lateral movement paths?
* **Detection impact:** If an attacker is in this zone undetected, how long before you would know?

Complete this risk table:

| Gap | Asset Criticality | Likelihood | Detection Impact | Risk Level |
|-----|------------------|------------|-----------------|------------|
| No visibility into DMZ traffic | ? | ? | ? | ? |
| No monitoring of Finance VLAN | ? | ? | ? | ? |
| No SQL Server network logs | ? | ? | ? | ? |
| No flow data from edge router | ? | ? | ? | ? |
| Branch office: zero visibility | ? | ? | ? | ? |
| Split-tunnel VPN blind spot | ? | ? | ? | ? |
| SPAN port connected to nothing | ? | ? | ? | ? |

---

## Part 3: Prioritised Recommendations

Based on your gap analysis, write a prioritised list of monitoring improvements.
For each recommendation, specify:

1. **What to deploy:** Tool or configuration change
1. **Where to deploy it:** Specific network location
1. **What it provides:** Type of visibility gained
1. **Implementation effort:** Low / Medium / High
1. **Priority:** Critical / High / Medium / Low

Use the template below:

```text
RECOMMENDATION #1
-----------------
What:      [e.g., Deploy Zeek sensor]
Where:     [e.g., Connected to SPAN port on Core Switch]
Provides:  [e.g., HTTP, DNS, conn logs for all inter-VLAN traffic]
Effort:    [Low / Medium / High]
Priority:  [Critical / High / Medium / Low]
Rationale: [Why is this the top priority?]

RECOMMENDATION #2
...
```

---

## Part 4: Compliance Considerations

Meridian is subject to **PCI-DSS** (Payment Card Industry Data Security Standard) because it processes financial transactions.
PCI-DSS has specific monitoring requirements:

**PCI-DSS Requirement 10:** Log and monitor all access to system components.

**PCI-DSS Requirement 11.4:** Detect and alert on/about intrusions.

Identify which of the current monitoring gaps would constitute **PCI-DSS non-compliance**, and explain how each recommendation in Part 3 addresses a specific compliance requirement.

---

## Part 5: Monitoring Architecture Diagram

Sketch (or describe in text) an improved monitoring architecture for Meridian that addresses the critical gaps.
Your design should include:

* Where to place TAPs vs. SPAN ports (and why)
* Which tool to deploy at each sensor point (Zeek, Suricata, NetFlow)
* How data flows to the SIEM
* What additional log sources to enable
* How to handle the branch office and remote access blind spots

---

## Discussion Questions

1. The SPAN port on the Core Switch is connected to nothing. Is this a configuration mistake or a deliberate choice? What would you tell management about the cost of not connecting it?

1. The split-tunnel VPN means employees browsing the internet from home completely bypass corporate monitoring. What are the security risks of this design? How could you address them without eliminating split tunnelling?

1. The web server generates no logs. In the event of a web application attack (e.g., SQL injection), where would you look for evidence? What is the minimum logging you would recommend adding?

1. A security consultant argues that monitoring the Finance VLAN would violate employees' privacy rights under GDPR. Do you agree? What GDPR principles apply, and how would you balance security monitoring with privacy?

1. If you could only choose ONE improvement to implement this week, given budget and time constraints, which would it be? Justify your choice.

---

## Expected Outcomes

After completing this demo, you should be able to:

* Read and interpret a network topology diagram
* Systematically identify monitoring blind spots
* Assess risk levels of different monitoring gaps
* Produce a structured, prioritised gap analysis
* Understand the link between network monitoring and compliance requirements

---

## Solution Notes

See the instructor notes file for a model completed visibility matrix and risk assessment.
Key findings that students should identify:

1. **Critical gap:** Finance VLAN (PCI-DSS scope) has zero monitoring — attacker could exfiltrate card data undetected
1. **Critical gap:** DMZ switch has no SPAN — web server attacks cannot be detected in real time
1. **High gap:** SQL Server generates no network logs — data exfiltration via SQL dump would be invisible
1. **High gap:** Branch office is completely dark — compromise there could be used as pivot
1. **Quick win:** SPAN port on Core Switch is already configured — just connect a sensor to it
1. **Compliance gap:** PCI-DSS 11.4 requires IDS — none is deployed
