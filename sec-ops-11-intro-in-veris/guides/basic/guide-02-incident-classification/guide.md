# Guide 02: Classifying Incidents Using VERIS Taxonomy

**Level:** Basic

**Estimated time:** 45 minutes

**Directory:** `guides/basic/guide-02-incident-classification/`

**Prerequisites:** Guide 01: Understanding the VERIS Framework

---

## Purpose

This guide teaches you the practical skill of classifying security incidents using the VERIS 4A taxonomy.
You will learn a step-by-step classification workflow and work through eight worked examples covering a range of real-world incident types.

---

## 1. The Classification Workflow

When classifying an incident using VERIS, follow this systematic process:

```text
Step 1: Read the narrative completely
         ↓
Step 2: Identify the ACTOR(s)
         ↓
Step 3: Identify the ACTION(s) — in order of attack chain
         ↓
Step 4: Identify the ASSET(s) — primary and secondary
         ↓
Step 5: Identify the ATTRIBUTE(s) — was CIA affected?
         ↓
Step 6: Determine: Security Incident or Data Breach?
         ↓
Step 7: Assess completeness — what information is missing?
```

### The Five Key Questions

Ask these questions about every incident:

1. **Who did it?** → Actor type, variety, motive
1. **What did they do?** → Action categories, varieties, vectors (in order)
1. **What was affected?** → Asset categories and specific varieties
1. **How was it affected?** → Which of C, I, A were compromised?
1. **Was data actually disclosed?** → Determines incident vs. breach

---

## 2. Classification Decision Trees

### Choosing the Actor Type

```text
Was the person involved authorized to access the system?
├── NO  → External actor (or Partner if vendor with some access)
│         └── What type of external actor?
│               ├── Criminal group → Organized crime
│               ├── Government-backed → Nation-state
│               ├── Ideological motivation → Hacktivist
│               ├── Business rival → Competitor
│               └── Unknown/individual → Unknown/Unaffiliated
└── YES → Internal actor (or Partner if contractor/vendor)
          └── Was it intentional?
                ├── YES → Motive: Financial/Grudge/Ideology → Malicious
                └── NO  → Motive: Convenience/Negligence → Error/Misuse
```

### Choosing the Primary Action

```text
What was the initial access method?
├── Someone was tricked (email, phone, social) → Social Engineering
├── Technical exploit, credential use, malware download → Hacking or Malware
│     └── Was software deployed? → Malware
│         Was no software deployed? → Hacking
├── A device/media was stolen or lost → Physical
├── Someone with access did something wrong → Misuse (if intentional) or Error (if accidental)
└── Natural event (storm, power) → Environmental
```

### Choosing the Attribute

```text
Was data accessed or exfiltrated by unauthorized party?
├── YES → Confidentiality
│         └── What data types? → Personal, PHI, Payment, Credentials, etc.
└── NO  → Not Confidentiality

Was data or software modified without authorization?
├── YES → Integrity
└── NO  → Not Integrity

Was access to systems or data disrupted?
├── YES → Availability
└── NO  → Not Availability

Note: Multiple attributes are possible and common.
```

---

## 3. Worked Examples

### Example 1: The Phishing Executive

> "A CFO received an email that appeared to come from the CEO, requesting an urgent wire transfer of $285,000 to a new vendor. The CFO processed the transfer. The email was not from the CEO — it was a Business Email Compromise attack. Discovery was made 3 days later when the actual CEO was informed."

**Actor**: External — Organized crime — Financial motive

**Action**: Social Engineering — Pretexting (impersonating the CEO)
*Note: BEC is classified as Social Engineering > Pretexting (or Phishing depending on the method).
The CFO was manipulated, not hacked.*

**Asset**: Person — Finance user (P - Finance)
*The targeted "asset" is the CFO who was manipulated.*

**Attribute**:

* Not Confidentiality (no data was disclosed)
* Not Integrity (no systems modified)
* Not Availability (no systems disrupted)
* Record: **Financial loss** — no CIA attribute applies

*Wait — this seems odd.
How do we record a BEC with no CIA impact?*

In VERIS, BEC attacks that result in financial loss without a CIA compromise are sometimes challenging to classify.
You can record an **Impact** (financial loss) even when no CIA attribute is directly affected.
The social engineering action itself is still recorded.
Some practitioners also record Integrity (the wire transfer was an unauthorized financial transaction).

**Is this a breach?** No — no data was disclosed.
This is a security incident resulting in financial loss.

---

### Example 2: The Mistaken Email

> "An HR specialist sent a spreadsheet containing salary information for 2,400 employees to the company mailing list instead of to the HR leadership team. It was discovered immediately when employees began responding. The email was recalled within 30 minutes."

**Actor**: Internal — End-user — Motive: Negligence (no malicious intent)

**Action**: Error — Misdelivery
*Sent to wrong recipients.
No malicious actor.
No technical attack.*

**Asset**: S - Mail (email system was the medium)
*Or you could argue U - Desktop as the user's workstation.
Both are defensible.*

**Attribute**: Confidentiality

* `data_disclosure: "Yes"` — salary data was disclosed to unauthorized parties
* Data type: Internal organizational (salary information is internal data)
* Data total: 2,400 records

**Is this a breach?** Yes — confirmed data disclosure.
Even though it was an accident and contained immediately, the data was disclosed.

**Key learning**: This is a breach with NO malicious actor.
Error incidents frequently result in breaches.

---

### Example 3: The Encrypted Backup Tapes

> "A healthcare provider used a courier service to transport backup tapes containing patient records. One box was lost in transit. The tapes were encrypted. The loss was discovered during inventory check two weeks later. The tapes were never recovered."

**Actor**: External — Unknown (the courier/someone who found the tapes)

*Wait — is this External or Environmental?* The tapes were lost, not necessarily stolen.
If they were stolen by someone, it's External Physical > Theft.
If they simply fell off a truck, it could be Error > Loss by the internal team.
The narrative says "lost in transit" which suggests Error.

**Best classification**:

**Actor**: Internal — End-user (or System admin for whoever managed the backup process)

**Action**: Error — Loss
*The organization's own processes failed to maintain control of the media.*

**Asset**: M - Tape (Media > Tape)

**Attribute**: Confidentiality

* `data_disclosure: "Potentially"` — tapes were encrypted, so actual disclosure is uncertain
* Data type: Medical (PHI)

**Note on data_disclosure "Potentially"**: When data was on a device that was lost or stolen but encryption was in place, VERIS records "Potentially" to reflect the uncertainty.
Many healthcare breach notification rules have a "safe harbor" for encrypted data, so this distinction matters legally.

**Is this a breach?** Potentially — depends on whether encryption was adequate and key was separately secured.

---

### Example 4: The DDoS Attack

> "A gaming company's servers were hit by a volumetric DDoS attack from a botnet. The attack peaked at 450 Gbps and took the game servers offline for 6 hours. The attack was attributed to a hacktivist group protesting the company's business practices. No data was accessed."

**Actor**: External — Hacktivist — Ideology motive

**Action**: Hacking — DoS (Denial of Service attacks are classified under Hacking in VERIS)

**Asset**: N - Server (the game servers; could also argue S - Web application)

**Attribute**: Availability

* Variety: Interruption (temporary unavailability)
* Duration: 6 hours

**Is this a breach?** No — no data was accessed.
This is an Availability-only incident.

**Key learning**: DDoS attacks affect only Availability.
They are significant incidents but not data breaches.

---

### Example 5: The Disgruntled Developer

> "A software developer who had been laid off retained access to the company's source code repository for 30 days post-termination due to an access review oversight. Before access was revoked, she deleted 3 years of version history from the main product repository. The deletion was detected during a sprint review meeting when engineers couldn't access historical commits."

**Actor**: Internal — Developer — Motive: Grudge (revenge for being laid off)
*She was a former employee but still had active credentials — still classified as Internal in VERIS.*

**Action**: Misuse — Privilege abuse (using residual access to cause harm)

*Could also argue: Hacking — Use of stolen credentials?
No — the credentials were legitimately hers; they were just not revoked.
This is Misuse.*

**Asset**: S - File (or S - Source code server)

**Attribute**: Integrity

* Variety: Data modification/deletion

Also potentially: Availability (code history was inaccessible after deletion)

**Is this a breach?** No — no data was disclosed to an unauthorized party.
This is an Integrity (and possibly Availability) incident.

**Key learning**: Insider threat incidents are often Integrity attacks (sabotage) rather than Confidentiality attacks (theft).

---

### Example 6: The Ransomware Hospital (Double Extortion)

> "A hospital was hit by ransomware. The attacker first exfiltrated 15,000 patient records, then encrypted the hospital's systems. The group threatened to publish the records unless a ransom was paid. Discovery was immediate (ransomware note displayed). Investigation confirmed exfiltration via forensic log analysis."

**Actor**: External — Organized crime — Financial motive (extortion + ransom)

**Action**:

1. Social Engineering — Phishing (assumed initial access, typical for ransomware)
1. Hacking — Use of stolen credentials (lateral movement)
1. Malware — Ransomware (encryption payload)

**Asset**:

* U - Desktop (workstations encrypted)
* S - Database (patient records exfiltrated)
* S - File (file servers encrypted)

**Attribute**:

* **Confidentiality** — data_disclosure: "Yes" — PHI exfiltrated (confirmed by forensics)
* **Integrity** — Software installation, Alter behavior
* **Availability** — Encryption, Duration: X days

*This is the "double extortion" pattern — all three CIA attributes are affected.*

**Is this a breach?** Yes — confirmed PHI exfiltration.
HIPAA breach notification required.

**Key learning**: Double-extortion ransomware affects all three CIA dimensions.
Always ask: was data confirmed exfiltrated, not just encrypted?

---

### Example 7: The Compromised Firewall

> "A nation-state actor exploited a zero-day vulnerability in the organization's border firewall firmware. This gave them persistent access to all network traffic for 4 months. The compromise was discovered by the organization's threat hunting team through anomalous beacon patterns."

**Actor**: External — Nation-state — Espionage motive

**Action**: Hacking — Exploit vulnerability (zero-day)
*Vector: Network (the firewall is a network device)*

**Asset**: N - Firewall (Network > Firewall)

**Attribute**: Confidentiality

* The attacker could see all network traffic for 4 months
* Data types: Internal (network traffic potentially containing sensitive communications)
* Disclosure status: "Potentially" (traffic was accessible but specific data viewed may be unknown)

Also possibly: Integrity (if the attacker modified firewall rules to redirect traffic)

**Is this a breach?** Potentially — depends on whether the network traffic captured contained sensitive data.

**Key learning**: Network infrastructure compromise can result in mass data exposure even without accessing any application directly.

---

### Example 8: The USB Drive in the Parking Lot

> "Security researchers discovered that an employee at an energy company inserted a USB drive found in the company parking lot into their workstation. The USB contained malware that established persistence and began beaconing to a command and control server. The C2 server was later attributed to a nation-state APT group. No data exfiltration was confirmed."

**Actor**: External — Nation-state — Espionage motive

**Action**:

1. Social Engineering — Baiting (leaving the USB drive)
1. Malware — Backdoor, RAT (what was installed)

**Asset**: U - Desktop (the workstation where USB was inserted)

**Attribute**: Integrity — Software installation (malware was installed)
*No confirmed Confidentiality because no exfiltration confirmed.*
*Availability was not affected.*

**Is this a breach?** No — no confirmed data exfiltration.
This is an integrity/malware incident.

**Key learning**: The baiting technique (leaving malicious USB) is Social Engineering > Baiting, not Physical action.
The physical medium is incidental; the manipulation of the human is the primary attack.

---

## 4. Common Classification Pitfalls

| Pitfall | Correct Approach |
|---------|-----------------|
| Calling everything "Hacking" | Use Misuse for authorized users abusing access; Physical for skimming |
| Calling all ransomware a "breach" | Only add Confidentiality if exfiltration is confirmed or suspected |
| Forgetting Error incidents | Misconfiguration, misdelivery, loss are real incidents |
| Over-attributing actors | If attribution is uncertain, use "Unknown" |
| Recording only the final action | Record the full attack chain (phishing → credential use → DB access) |
| Missing the Partner actor | Supply chain attacks often have a Partner component |

---

## 5. Classification Practice Matrix

Use this matrix as a quick reference when classifying:

| Incident Type | Actor | Primary Action | Asset | Attribute |
|---------------|-------|---------------|-------|-----------|
| Phishing → credential theft → DB access | External | Social + Hacking | S-DB | Confidentiality |
| Ransomware (no exfil confirmed) | External | Social + Malware | U-Desktop, S-File | Integrity + Availability |
| S3 bucket misconfiguration | Internal | Error > Misconfiguration | S-Database (cloud) | Confidentiality |
| Employee data theft | Internal | Misuse | S-Database | Confidentiality |
| ATM skimmer | External | Physical > Skimming | T-ATM | Confidentiality |
| DDoS attack | External | Hacking > DoS | S-Web app | Availability |
| Lost laptop (encrypted) | Internal | Error > Loss | U-Laptop | Confidentiality (Potentially) |
| Physical server theft | External | Physical > Theft | S-Server | Confidentiality + Availability |
| BEC wire transfer fraud | External | Social > Pretexting | P-Finance | Impact (financial) |
| Zero-day on VPN | External | Hacking > Exploit vuln | N-VPN | Confidentiality / Integrity |

---

## 6. Self-Assessment Questions

Test your classification skills by answering these before checking the answer:

1. An intern accidentally deletes a production database table during training. What action category? What attribute?

1. A competitor pays a current employee to copy and send them your product roadmap. What actor types might you record?

1. A customer's laptop containing encrypted company data is stolen from their car. What actor? What asset? What attribute?

1. A web scraper indexes your customer-facing portal and accidentally accesses a debug page containing internal IP addresses. No authentication was bypassed. What action? Is this a breach?

---

## Key Takeaways from This Guide

1. **Follow the workflow**: Read completely, then classify Actor → Action → Asset → Attribute in order.
1. **Record the full attack chain**: Multi-step attacks need all actions recorded.
1. **Error incidents are real incidents**: Accidental breaches count.
1. **Confirm before recording Confidentiality**: "Yes" means confirmed; use "Potentially" when uncertain.
1. **When in doubt, use Unknown**: It is better to have an incomplete record than a wrong one.

---

*Guide 02 | Session 11 | Security Operations Master Class | Digital4Security*
