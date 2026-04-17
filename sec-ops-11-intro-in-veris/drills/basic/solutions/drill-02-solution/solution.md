# Solution: Drill 02 (Basic) — Actor and Action Mapping

**Level:** Basic

**Directory:** `drills/basic/solutions/drill-02-solution/`

---

## Part 1: Actor Identification — Solutions

### Scenario A: Terminated Employee with Residual Access

* **Actor type**: Internal
* **Actor variety**: End-user (or System administrator if they had elevated access)
* **Actor motive**: Financial (downloading client contracts for competitive use) or Grudge

**Key point**: Even though access wasn't revoked, this employee is still "Internal" in VERIS — they had legitimate credentials.
The failure to revoke access is an operational security gap, not a technical attack.

---

### Scenario B: Nation-State LinkedIn Spear-Phishing

* **Actor type**: External
* **Actor variety**: Nation-state (or State-affiliated)
* **Actor motive**: Espionage

**Key point**: Fake LinkedIn recruiter targeting defense engineers = classic nation-state social engineering TTP.
The LinkedIn account is the "vector" for the social engineering action.

---

### Scenario C: MSP RMM Hijacking

* **Actor type**: External + Partner
* **Actor variety**: External: Unknown (or Organized crime); Partner: MSP
* **Actor motive**: Unknown (or Financial if ransomware follows)

**Key point**: Two actor types.
The external attacker compromised the MSP (Partner).
The Partner's platform was then used as a vector against clients.
Supply chain attacks require both actors to be recorded.

---

### Scenario D: Competitor Industrial Espionage via Bribed Insider

* **Actor type**: External (competitor) AND Internal (the bribed engineer)
* **Actor variety**: External: Competitor; Internal: Developer (or End-user)
* **Actor motive**: External: Financial (competitive advantage); Internal: Financial (bribe)

**Key point**: Two actors.
The competitor is the External > Competitor actor.
The bribed engineer is Internal > Developer with Financial motive.
Both should be recorded.

---

### Scenario E: Hacktivist Website Defacement

* **Actor type**: External
* **Actor variety**: Hacktivist
* **Actor motive**: Ideology

**Key point**: Hacktivists are ideologically motivated.
Website defacement to make a political statement is a classic hacktivist TTP.

---

### Scenario F: Software Bug Causing Misdirected Emails

* **Actor type**: Internal
* **Actor variety**: System administrator (or Developer — whoever deployed the software)
* **Actor motive**: Negligence

**Key point**: This is an Error incident — the "actor" is the organization's own IT/dev team that deployed buggy software.
No malicious external actor.
Motive: Negligence (unintentional).

---

### Scenario G: Phishing Kit-as-a-Service

* **Actor type**: External
* **Actor variety**: Unknown (the renter of the phishing kit) — possibly Organized crime
* **Actor motive**: Unknown (likely Financial — credential harvesting for sale)

**Key point**: The phishing-kit-as-a-service model means even unsophisticated actors can run credential harvesting campaigns.
Attribution is often "Unknown" in these cases.

---

### Scenario H: Security Researchers on Connected Medical Device

* **Actor type**: External
* **Actor variety**: Unaffiliated (security researchers — not organized crime, not hacktivist)
* **Actor motive**: Fun (research/curiosity) — though their intent could be considered disclosure

**Key point**: Even well-meaning security researchers who access data without authorization create incidents.
The actor variety is "Unaffiliated" and motive could be "Fun" or "Ideology" (responsible disclosure advocacy).
This is still a VERIS incident even though no harm was intended.

---

## Part 2: Action Chain Mapping — Solutions

### Attack 1: Credential Theft to Data Exfiltration

```text
Step 1: Social (Phishing) > Spear phishing > Email
        [Fake O365 login page harvests credentials from 3 employees]

Step 2: Hacking > Use of stolen credentials > VPN
        [Stolen credentials used to authenticate to VPN]

Step 3: Hacking > Use of stolen credentials > Internal network
        [Lateral movement to file server; data downloaded]
```

**Note**: Steps 2 and 3 both use stolen credentials but the vector changes (VPN → Internal network).
In VERIS, you can record both as the same action variety with different vectors, or as separate action entries.

---

### Attack 2: Full Ransomware Deployment Chain

```text
Step 1: Social (Phishing) > Phishing > Email
        [Malicious Word doc sent to accounts payable clerk]

Step 2: Malware > Downloader > Email attachment
        [Macro downloads second-stage payload from C2]

Step 3: Malware > Backdoor / RAT > C2 (Cobalt Strike)
        [Beacon establishes persistent C2 channel]

Step 4: Hacking > Password dumping (Kerberoasting) > Command shell
        [Privilege escalation via Kerberoasting]

Step 5: Malware > Ransomware > Direct install
        [ALPHV deployed across domain]
```

**Key teaching point**: A complete ransomware attack chain typically has 4–5 steps.
Recording all of them provides much richer data than just "Ransomware."

---

### Attack 3: Physical POS Skimmer

```text
Step 1: Physical > Tampering > Victim facility
        [Criminal installs skimming overlays at 12 retail locations]

Step 2: Physical > Skimming > Victim facility
        [Skimmers collect card data; transmitted via Bluetooth]
```

**Note**: Both actions are Physical category.
Tampering (physical modification of the POS terminals) precedes Skimming (the data capture mechanism).

---

### Attack 4: Cloud Misconfiguration

```text
Step 1: Error > Misconfiguration > Cloud infrastructure
        [Elasticsearch cluster created without authentication]
```

**Is there a second action?** The search engine indexing and researcher finding the data are external events, not actions.
The single Error > Misconfiguration is the incident.
The "discovery" is recorded in the discovery_method field.

This is a **one-step incident** with no attacker — just an accidental misconfiguration.

---

### Attack 5: Software Supply Chain Backdoor

**From the engineer's perspective (encoding for the vendor's incident):**

```text
Step 1: Misuse > Privilege abuse > Internal development environment
        [Engineer abuses legitimate code access to introduce backdoor]
```

**From the victim organizations' perspective:**

```text
Step 1: Malware > Backdoor > Software update (Third-party software)
        [Backdoor delivered via legitimate software update mechanism]
```

**Key teaching point**: The same incident looks different depending on whose VERIS record you are encoding.
The vendor records a Misuse incident.
The customer organizations record a Malware > Backdoor incident delivered via Software update.
This is why supply chain attacks are complex to categorize — they are fundamentally two separate incidents linked by causality.

---

## Part 3: Quick-Fire Solutions

| # | Scenario | Action Category | Reasoning |
|---|---------|----------------|-----------|
| 1 | Wrong-recipient email | **error** | Error > Misdelivery — unintentional |
| 2 | Citrix VPN zero-day | **hacking** | Hacking > Exploit vulnerability |
| 3 | Vishing for password | **social** | Social Engineering > Vishing |
| 4 | Hurricane destroys DC | **environmental** | Environmental > Natural disaster |
| 5 | Employee copies files to USB | **misuse** | Misuse > Data mishandling |
| 6 | Keylogger via browser exploit | **malware** | Malware > Keylogger (installed via Hacking > Exploit vuln) |
| 7 | `rm -rf` in production | **error** | Error > Omission (or Programming error) |
| 8 | Gas pump skimmer | **physical** | Physical > Skimming |
| 9 | Files to personal Gmail | **misuse** | Misuse > Unapproved workaround / Data mishandling |
| 10 | DDoS on DNS server | **hacking** | Hacking > DoS (or Denial of Service variety) |

**Note on question 6**: The keylogger itself is Malware, but it was *installed* through a Hacking action (exploit vuln).
In a full VERIS record, both Hacking (initial access) and Malware (installed payload) would be recorded.

---

## Score Guide

**Part 1 (Actor ID)**: 3 points each × 8 = 24 points max

**Part 2 (Action chains)**: Award 2 points per step correctly identified, max 16 points

**Part 3 (Quick-fire)**: 1 point each × 10 = 10 points max

**Total: 50 points**

* 45–50: Ready for intermediate drills
* 35–44: Review Guide 02 sections on Actor and Action
* Below 35: Revisit reading.md Sections 4 and 5

---

*Solution — Drill 02 | Session 11 | Security Operations Master Class | Digital4Security*
