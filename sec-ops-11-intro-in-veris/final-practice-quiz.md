# Final Practice Quiz — Session 11: Introduction to VERIS

---

## Part 1: Short Answer Questions

**Question 1:** What is the purpose of the VERIS `confidence` field, and what are its possible values?

> **Model Answer:** The `confidence` field indicates how certain the analyst is about the accuracy of the VERIS record as a whole. Possible values are: None, Low, Medium, High. A "High" confidence means the analyst has direct evidence supporting all major claims in the record. "None" would be used when almost all details are unknown or unverified. The field helps consumers of the data know how much weight to give each record.

---

**Question 2:** Explain the difference between the VERIS `actor` types "Internal" and "Partner." Give one example of each.

> **Model Answer:** An **Internal** actor is someone who belongs to the victim organization and has authorized access — such as an employee, contractor working on-site, or system administrator. Their access is granted as part of their role. A **Partner** actor is from a third-party organization that has a business relationship with the victim — such as a cloud service provider, IT vendor, or outsourced service provider. Example of Internal: an employee who downloads customer data to sell to a competitor. Example of Partner: an IT service provider who accidentally exposes client data due to misconfiguration during a migration project.

---

**Question 3:** A ransomware attack encrypts all files on a company's servers.
No data exfiltration was confirmed.
Which VERIS CIA attributes apply and why?

> **Model Answer:** The primary attribute is **Availability** — specifically the `variety = ["Extortion", "Interruption"]` since files are encrypted (held hostage) and the organization cannot access them. This maps to both extortion (ransomware demands payment) and interruption (operations are disrupted). **Integrity** also applies — `variety = ["Install code"]` since the ransomware itself was installed on the systems. **Confidentiality should NOT be added** if no data exfiltration was confirmed — adding it would misrepresent the incident. Only record confirmed impacts.

---

**Question 4:** What is the DBIR, and what is meant by the term "n =" in the context of DBIR findings?

> **Model Answer:** The **DBIR (Data Breach Investigations Report)** is Verizon's annual statistical analysis of security incidents and data breaches, published since 2008. It uses VERIS-coded data from Verizon's own investigations and partner contributions to identify trends and patterns in the threat landscape. The notation **n =** in a DBIR chart indicates the number of incidents in the sample used to calculate that specific finding. For example, `n = 1,500` means the statistic was derived from 1,500 analyzed incidents. The n value is critical context: a finding from n = 50 is far less reliable than one from n = 5,000. Wider confidence intervals also appear when n is small.

---

**Question 5:** Name four VERIS asset type prefixes and give one example of a specific variety for each.

> **Model Answer:**
> - **S** (Server): Example: `S - Database` (a database server)
> - **U** (User Device): Example: `U - Laptop` (an employee's laptop)
> - **N** (Network): Example: `N - Firewall` (a network firewall)
> - **M** (Media): Example: `M - Flash drive` (a USB storage device)
> - (Acceptable alternatives: P = Person, e.g., `P - Finance`; T = Terminal, e.g., `T - ATM`)

---

**Question 6:** What is the difference between VERIS `action.hacking` and `action.malware`?
Give a scenario where both would apply to the same incident.

> **Model Answer:** **Hacking** refers to the use of technical techniques to gain unauthorized access to systems or bypass security controls. This includes exploiting vulnerabilities, using stolen credentials, brute-force attacks, and SQL injection. **Malware** refers to malicious software installed or running on systems, such as viruses, ransomware, keyloggers, backdoors, and spyware.
>
> In practice, both often appear in the same incident. **Example scenario:** An attacker exploits an unpatched web application vulnerability (Hacking — `variety: "Exploit vulnerability"`) to gain initial access to a server. Once inside, they install a Remote Access Trojan (RAT) to maintain persistence (Malware — `variety: "Backdoor"`). Both action types should be recorded because they describe distinct phases of the attack: the initial intrusion (Hacking) and the malicious software component (Malware).

---

**Question 7:** Describe the full VERIS coding process for the following incident scenario.
Provide the Actor, Action, Asset, and Attribute sections as JSON, and explain your classification decisions.

**Scenario:** A healthcare company's IT manager used their administrative credentials to access a terminated employee's email account and read private communications.
The access was not authorized by HR or legal.
The IT manager exported 120 emails before the activity was discovered by an audit two months later.
No emails were shared externally.

> **Model Answer:**
>
> **Actor:** Internal — The IT manager is an employee with legitimate administrative access. The access was deliberate and unauthorized in purpose (no business justification). Motive is ambiguous — could be curiosity, grudge, or investigation. Use "Unknown" motive or "Grudge" if there's context.
>
> ```json
> "actor": {
>   "internal": {
>     "variety": ["System admin"],
>     "motive": ["Unknown"]
>   }
> }
> ```
>
> **Action:** Misuse — The actor used legitimate credentials to access systems they were technically authorized to access (admin rights) but did so without business authorization. This is not "hacking" because no system was exploited; it is misuse of legitimate access. The action variety is "Privilege abuse."
>
> ```json
> "action": {
>   "misuse": {
>     "variety": ["Privilege abuse"],
>     "vector": ["LAN access"]
>   }
> }
> ```
>
> **Asset:** Mail server (the emails were on a mail server) and the person whose email was accessed.
>
> ```json
> "asset": {
>   "assets": [
>     {"variety": "S - Mail"},
>     {"variety": "P - End-user"}
>   ]
> }
> ```
>
> **Attribute:** Confidentiality — emails were read and exported (disclosed to an unauthorized purpose). `data_disclosure: "Yes"` is appropriate since the actor definitively accessed the private communications. The emails were not shared externally, but the unauthorized access itself constitutes a confidentiality breach.
>
> ```json
> "attribute": {
>   "confidentiality": {
>     "data_disclosure": "Yes",
>     "data": [
>       {"variety": "Internal", "amount": 120}
>     ]
>   }
> }
> ```
>
> **Timeline:** `discovery.unit = "Months"`, `discovery.value = 2`. The incident itself (access) occurred before the audit. We don't know exactly when the access started, but the discovery was 2 months later.
>
> **Confidence:** High — the audit confirmed the access, the actor, and the records accessed.

---

**Question 8:** A financial institution's third-party payroll provider suffers a breach.
Attackers compromise the provider's systems and steal employee PII (names, social security numbers, salaries) for 3,000 employees.
From the financial institution's perspective as the victim, how would the VERIS actor and action be coded, and why?

> **Model Answer:**
>
> From the victim financial institution's perspective:
>
> **Actor:** External — The attackers are outside the victim organization. However, the incident was enabled by a Partner (the payroll provider). The actor variety depends on whether we know who attacked the provider. If unknown, use `actor.external.variety = ["Unknown"]`. If organized crime is confirmed, use `["Organized crime"]`. Some analysts would also note a secondary actor as the Partner (the payroll provider whose controls failed), though the primary malicious actor is External.
>
> **Action:** This is nuanced because the victim organization did not observe the attack directly — they experienced the downstream consequence. The attack on the provider likely involved Hacking. From the victim's view, the most accurate action is whatever the provider was subjected to. If unknown, `action.unknown` may be appropriate, or document based on information shared by the provider.
>
> **Key insight:** VERIS should represent the incident **as experienced by the victim organization**. The financial institution's assets (employee PII held by the provider) were compromised. The actor is external (the attackers), and the chain includes a Partner who failed to protect the data. The `victim.secondary.victim_id` field can capture the provider as a secondary victim or contributing party.
>
> **Attribute:** Confidentiality — `data_disclosure = "Yes"`, `data.variety = ["Personal"]`, `data.amount = 3000`. PII (names, SSNs, salaries) constitutes personal data.

---

**Question 9:** Compare and contrast VERIS with MITRE ATT&CK.
In what situations would you use each framework, and how can they be used together in a SOC environment?

> **Model Answer:**
>
> **VERIS** is designed for incident data recording and sharing. It captures what happened at a high level — who (actor), what they did (action), what was affected (asset), and how the CIA properties were impacted (attribute). VERIS is retrospective: you use it after an incident to document it in a structured, comparable way. VERIS enables statistical analysis across many incidents, benchmarking, and trend reporting. It is the language of the DBIR and VCDB.
>
> **MITRE ATT&CK** is an adversary behavior framework describing specific tactics, techniques, and sub-techniques used by real threat groups. It is highly granular (hundreds of techniques), focused on the attacker's perspective, and designed to support detection engineering. You use ATT&CK when designing detection rules, mapping red team exercises, or hunting for specific threat actor behaviors.
>
> **Key differences:**
> - VERIS: high-level categories (7 action types) vs. ATT&CK: granular techniques (hundreds)
> - VERIS: incident record (retrospective) vs. ATT&CK: behavior model (prospective and retrospective)
> - VERIS: full incident lifecycle vs. ATT&CK: primarily attacker TTPs
> - VERIS: open dataset (VCDB) vs. ATT&CK: no comparable public incident dataset
>
> **Using them together in a SOC:**
> When an incident is closed, you code it in VERIS for trend tracking and reporting. The VERIS action varieties map approximately to ATT&CK tactics. For example, VERIS `social/Phishing` maps to ATT&CK Initial Access (T1566). This mapping allows VERIS incident data to inform ATT&CK-based detection rule priorities — if VERIS data shows phishing is in 36% of your incidents, you should ensure you have high-quality ATT&CK T1566 detections in your SIEM. ATT&CK provides the "how to detect" detail; VERIS provides the "what matters most" context from real incident data.

---

**Question 10:** Your SOC has been asked to contribute historical incident data to the VCDB.
What are three key considerations you must address before submitting, and how does VERIS support each?

> **Model Answer:**
>
> **1. Data anonymization / victim de-identification:**
> Before contributing to the VCDB, you must remove or obscure any information that could identify the victim organization, affected individuals, or specific systems. VERIS supports this through the `victim.victim_id` field (which can be replaced with a UUID or omitted) and by using general industry/size fields (`victim.industry`, `victim.employee_count`) rather than specific company names. The VCDB contributor guidelines also specify what fields must be redacted.
>
> **2. Completeness and confidence:**
> Submitted records should accurately represent what is known and unknown. VERIS provides the `confidence` field (None/Low/Medium/High) and uses `"Unknown"` as a valid value throughout the schema to indicate fields where information is not available. Partial records are acceptable — you should not fabricate values for unknown fields.
>
> **3. Consent and legal review:**
> The incident data may contain information subject to legal privilege, NDA, or regulatory restrictions. Before contributing, legal counsel should review whether the organization is permitted to share incident details externally. VERIS itself does not enforce legal controls, but the framework's design (minimal PII in the schema, focus on technical details) makes it easier to share without exposing sensitive organizational or personal data.
