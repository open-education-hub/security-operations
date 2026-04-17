# Threat Actor Profile: FIN-STORM

**Classification:** TLP:AMBER
**Confidence:** Medium
**Date Created:** 2024-03-15
**Last Updated:** 2024-03-15
**Profile Author:** SecureBank Threat Intelligence Team

---

## 1. Identity and Attribution

| Field | Value |
|-------|-------|
| Actor Name | FIN-STORM |
| Aliases | STORM-0231 (Microsoft naming), GOLD-TEMPEST (Secureworks naming) |
| Attribution Confidence | Medium |
| Suspected Sponsorship | Financially Motivated Criminal Organization |
| Geographic Origin | Eastern Europe (suspected; low confidence) |

**Attribution Basis:**

- TTPs overlap significantly with FIN7/Carbanak (Carbanak group tools observed in samples)
- Infrastructure patterns consistent with Eastern European cybercriminal groups
- Operational timing suggests UTC+2 to UTC+3 timezone
- Use of modified Cobalt Strike and custom PowerShell loaders

**Caveats:**

- Attribution to a specific nation or group cannot be confirmed
- Possible false-flag operations cannot be ruled out
- Tool sharing between criminal groups is common and may explain TTP overlap

---

## 2. Motivation and Objectives

**Primary Motivation:** Financial gain

**Objectives:**

- Business Email Compromise (BEC) targeting financial workflows
- Financial fraud via access to banking platforms and SWIFT infrastructure
- Ransomware deployment as a secondary fallback objective
- Data theft for sale on underground markets

---

## 3. Targeting

**Sectors:**

- Financial Services (primary — banks, investment firms, payment processors)
- Retail and Hospitality (secondary — POS system targeting)
- Healthcare (occasional — high-value data)

**Geography:**

- Western Europe (United Kingdom, Germany, France, Netherlands) — primary
- North America — secondary

**Organisation Size:** Mid to large enterprises (>500 employees preferred)

**Victim Selection Criteria:**

- Organisations with significant financial assets or transaction volumes
- Companies with known cybersecurity weaknesses or legacy infrastructure
- Organisations undergoing mergers and acquisitions (temporary complexity)

---

## 4. Tactics, Techniques, and Procedures (TTPs)

### Kill Chain Mapping

| Phase | Technique | ATT&CK ID | Confidence |
|-------|-----------|-----------|------------|
| Initial Access | Spear-phishing with macro-enabled Office documents | T1566.001 | High |
| Execution | PowerShell with base64-encoded commands | T1059.001 | High |
| Defense Evasion | AMSI bypass via PowerShell | T1562.001 | Medium |
| Defense Evasion | Execution policy bypass | T1059.001 | High |
| Credential Access | LSASS memory dumping (Mimikatz variants) | T1003.001 | High |
| Lateral Movement | WMI remote execution | T1047 | High |
| Lateral Movement | PsExec alternative (Impacket smbexec) | T1021.002 | Medium |
| Collection | Data staging in system directories | T1074.001 | Medium |
| Exfiltration | HTTPS exfiltration over C2 channel | T1048.002 | High |
| C2 | HTTPS-based C2 (Cobalt Strike modified profile) | T1071.001 | High |

### Preferred Tools

| Tool | Type | Purpose |
|------|------|---------|
| Cobalt Strike (modified profile) | Commercial RAT | C2, post-exploitation |
| Mimikatz variants | Credential dumper | Credential harvesting from LSASS |
| Impacket suite | Open-source offensive framework | SMB lateral movement, PtH |
| Custom PowerShell loaders | Custom malware | Staging, AMSI bypass, persistence |
| Macro-enabled Office documents | Delivery vehicle | Initial access via phishing |

---

## 5. Infrastructure

### Observed Patterns

**Domain Registration:**

- Registrars commonly used: NameCheap, GoDaddy (privacy protection almost always enabled)
- Domain age at time of use: usually less than 30 days
- Naming conventions: impersonates CDN providers, authentication services, security updates
- Common keywords in domains: `update`, `secure`, `cdn`, `auth`, `verify`, `portal`, `login`

**Hosting:**

- Primarily dedicated servers via bulletproof hosting providers
- Geographic location of infrastructure: Netherlands and Romania (most common)
- Occasional use of major cloud providers (AWS, Azure) for some C2 to blend with legitimate traffic

**Certificate Patterns:**

- Let's Encrypt certificates are the norm (fast, automated, anonymous)
- Certificates typically issued within 24 hours of domain registration
- Expiry dates shorter than typical legitimate services (30-90 days)

### Current IOCs

> **Note:** IOCs age quickly. Always consume indicators from live threat feeds rather
> than static documents. Current IOCs for this actor are maintained in MISP Event ID:
> [link to MISP event].

---

## 6. Countermeasures

### Detection

**High-fidelity detections (low false-positive rate):**

- Office applications spawning PowerShell or cmd.exe
  → Sigma rule: `office_spawns_powershell.yml`
- LSASS memory access by non-security processes
  → Sigma rule: `lsass_memory_access.yml`
- WMI spawning command shells or PowerShell
  → Sigma rule: `wmi_remote_execution.yml`
- Encoded PowerShell from unusual parent processes
  → Sigma rule: `ps_encoded_command.yml`
- Archive files created in ProgramData or Windows\Temp
  → Sigma rule: `data_staging.yml`

**Network detections:**

- Newly registered domains (< 30 days old) appearing in web proxy logs
- C2 beaconing patterns: regular HTTPS intervals to residential or cheap hosting
- Large HTTPS transfers to non-business destinations during off-hours

### Prevention

**Priority 1 — Immediate:**

- Disable macro execution in Office via Group Policy (Attack Surface Reduction rules)
- Enable Protected View for files from the internet
- Deploy application allowlisting on all privileged and sensitive systems

**Priority 2 — Short-term:**

- Disable WMI remote execution where not operationally required
- Enable LSASS protection (RunAsPPL registry key + Credential Guard on Windows 10/11)
- Enforce multi-factor authentication on all VPN and remote access

**Priority 3 — Medium-term:**

- Deploy sandbox detonation for all email attachments
- Implement network traffic inspection with SSL/TLS visibility where legally permitted
- Run user security awareness training focused on spear-phishing and macro-enabled documents

---

## 7. Intelligence Sources

| Source | Reliability | Notes |
|--------|-------------|-------|
| Internal IR findings | High | Confirmed direct observation |
| FS-ISAC Community Reports | High | Peer-validated financial sector intel |
| Vendor reports (Mandiant, CrowdStrike) | Medium-High | Well-researched, may lag by weeks |
| Open-source threat feeds | Medium | Variable quality; validate before use |
| Social media / researcher posts | Low-Medium | Good for timeliness; low confidence |

---

## 8. Profile Confidence Assessment

| Area | Confidence | Basis |
|------|------------|-------|
| Motivation | High | Consistent financial fraud pattern across incidents |
| Target sectors | High | Multiple confirmed victims in financial services |
| TTPs | High | Multiple incident observations over 6+ months |
| Tools | Medium | Limited malware sample availability for deep analysis |
| Attribution | Low-Medium | No definitive technical evidence linking to named group |
| Infrastructure patterns | Medium | Pattern analysis across limited dataset |

---

## 9. Related Actors

- **FIN7 / Carbanak:** Significant TTP overlap; may be same group, a spinoff, or shared tooling
- **Lazarus Group:** Occasional tool overlap but distinct operational pattern and motivations
- **Unnamed criminal collective:** Observed purchasing FIN-STORM tooling on underground markets

---

*Profile maintained by: SecureBank Threat Intelligence Team*
*Review cycle: Monthly, or immediately upon receipt of new significant intelligence*
*Distribution: TLP:AMBER — internal use and named partner organisations only*
