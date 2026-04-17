# Drill 01 (Basic): Generating Hunting Hypotheses from TTPs

**Level:** Basic

**Estimated Time:** 30-45 minutes

**Submission Format:** Written document (PDF or Markdown)

---

## Learning Objectives

By completing this drill, you will be able to:

* Extract TTPs from a threat intelligence report
* Map TTPs to MITRE ATT&CK techniques
* Write structured, testable hunting hypotheses
* Identify appropriate data sources for each hypothesis

---

## Scenario

You are a threat hunter at a healthcare organization.
Your threat intelligence team has received the following advisory from H-ISAC (Health Information Sharing and Analysis Center):

---

> **H-ISAC ADVISORY TLP:GREEN**
>
> **Threat: VIPER-HEALTH – Healthcare-Targeted Ransomware Group**
>
> VIPER-HEALTH is a ransomware-as-a-service (RaaS) group that specifically targets healthcare providers. Over the past 6 months, they have successfully encrypted systems at 12 hospitals across Europe and North America.
>
> **Observed Attack Pattern:**
>
> 1. **Initial Access:** Exploitation of internet-facing VPN appliances (Fortinet, Pulse Secure). Followed by valid account usage.
>
> 2. **Persistence:** Creation of new local administrator accounts with names resembling service accounts (e.g., `svc-healthmon`, `svc-monitor01`).
>
> 3. **Discovery:** Internal reconnaissance using native Windows tools: `net.exe`, `nltest.exe`, `whoami.exe`, `ipconfig.exe`, and `arp.exe`.
>
> 4. **Lateral Movement:** RDP connections using the newly created accounts; also observed using WinRM for remote management.
>
> 5. **Data Collection:** Staging sensitive files (patient records, financial data) in `C:\Windows\SysWOW64\Tasks\` using modified names.
>
> 6. **Exfiltration:** Data exfiltration via Rclone to cloud storage providers (Google Drive, Mega.nz) before ransomware deployment.
>
> 7. **Impact:** Deployment of LOCKBIT 3.0 variant with custom encryption parameters.
>
> **Observed IOCs (at time of report):**
> - Rclone binary renamed to `svchostmon.exe` and `systeminform.exe`
> - Rclone config files in: `C:\Users\<user>\AppData\Roaming\Microsoft\`
> - New local admin accounts created within 24h of initial compromise
> - `nltest.exe` used for domain trust enumeration

---

## Tasks

### Task 1: TTP Extraction and ATT&CK Mapping (20 points)

Create a table with the following columns for **each of the 7 attack phases** described in the advisory:

| Phase | Observed Behavior | ATT&CK Technique ID | ATT&CK Technique Name | Tactic |
|-------|------------------|--------------------|-----------------------|--------|

> **Hint:** Search https://attack.mitre.org for each behavior. Some phases may map to multiple techniques.

---

### Task 2: Hypothesis Development (40 points)

Select **4 of the 7 TTPs** from your mapping above and write a complete hunting hypothesis for each.

Each hypothesis must include:

**Template:**

```text
Hypothesis #[N]: [Descriptive Title]

Threat Actor / Technique:
[Actor name and ATT&CK technique(s)]

Hypothesis Statement:
"If [actor/technique] is active in [scope], I would expect to observe
[specific evidence] in [data source] during [time window]."

Specific Indicators to Hunt For:
- [Specific observable 1]
- [Specific observable 2]
- [Specific observable 3]

Baseline (What is Normal):
[Describe what legitimate activity looks like for comparison]

Data Sources Required:
- [Data source 1]: [Why it's needed]
- [Data source 2]: [Why it's needed]

Prioritization Justification:
[Why did you select this hypothesis? Impact if found? Huntability?]
```

---

### Task 3: Hunt Prioritization (20 points)

Create a prioritization matrix for all 7 TTPs.

Score each TTP on two dimensions (1=Low, 3=High):

| TTP | Huntability Score (1-3) | Impact Score (1-3) | Total Score | Priority Rank |
|-----|------------------------|--------------------|-------------|---------------|

**Huntability** considerations:

* Is data likely available? (Windows events, SIEM coverage)
* How specific are the indicators?
* How many false positives would you expect?

**Impact** considerations:

* How severe is this TTP if the attacker is doing it?
* How far along the kill chain does this place the attacker?
* What damage could occur?

Explain your scoring with 1-2 sentences per TTP.

---

### Task 4: Data Source Assessment (20 points)

For your top 2 highest-priority hypotheses, create a data source readiness assessment:

```text
Hypothesis: [Title]

Required Data Source: [Name]
- Availability: [How would you check if this data is available?]
- Coverage: [What % of endpoints likely have this data?]
- Retention: [How long is this data typically retained?]
- Quality Issues: [What could make this data incomplete or unreliable?]
- Gap Impact: [If this data is missing, how does it affect your hunt?]
```

---

## Submission Checklist

Before submitting, verify:

* [ ] All 7 TTPs from the advisory are mapped to ATT&CK
* [ ] 4 complete hypotheses written (all template fields completed)
* [ ] Prioritization matrix completed with explanations
* [ ] Data source assessment for top 2 hypotheses
* [ ] Writing is clear and specific (avoid vague language like "unusual activity")

---

## Evaluation Criteria

| Criteria | Points |
|----------|--------|
| Accuracy of ATT&CK mapping | 20 |
| Hypothesis quality (specific, testable, complete) | 40 |
| Prioritization logic and justification | 20 |
| Data source assessment depth | 20 |
| **Total** | **100** |

---

## Reference Resources

* MITRE ATT&CK Enterprise: https://attack.mitre.org
* Reading material: Session 07, sections 4 and 6
* Guide 01: Threat Hunting Methodology
