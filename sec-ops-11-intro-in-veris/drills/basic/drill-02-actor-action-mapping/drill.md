# Drill 02 (Basic): Actor and Action Mapping

**Level:** Basic

**Estimated time:** 25–35 minutes

**Directory:** `drills/basic/drill-02-actor-action-mapping/`

**Prerequisites:** Reading.md, Guides 01–02

---

## Overview

This drill focuses specifically on the Actor and Action dimensions of VERIS.
You will practice identifying actors and mapping the complete action chain for 8 attack scenarios.
The skill of correctly identifying multi-step attack chains is critical for both VERIS encoding and incident analysis.

---

## Part 1: Actor Identification (8 scenarios)

For each scenario, identify:

* Actor **type** (external / internal / partner)
* Actor **variety** (the specific type within the category)
* Actor **motive**

---

**Scenario A:** *A terminated employee, still having remote access for 5 days post-termination, logs in and downloads all client contracts to a personal Dropbox account.*

Actor type: ___________
Actor variety: ___________
Actor motive: ___________

---

**Scenario B:** *A foreign intelligence service compromises a defense contractor through a LinkedIn recruiter account that sends a malicious PDF "job offer" to engineers.*

Actor type: ___________
Actor variety: ___________
Actor motive: ___________

---

**Scenario C:** *An MSP's remote monitoring agent (legitimately installed) is hijacked by attackers who exploited a zero-day in the MSP's management platform to run commands on all client systems.*

Actor type(s): ___________
Actor variety: ___________
Actor motive: ___________

---

**Scenario D:** *Employees of a competitor company bribe a recently laid-off engineer to provide them with your company's product source code and customer list.*

Actor type(s): ___________  *(Hint: Two actors may be involved)*
Actor variety: ___________
Actor motive: ___________

---

**Scenario E:** *A hacktivist group discovers an unpatched web application vulnerability and defaces your company's website to protest your environmental practices.*

Actor type: ___________
Actor variety: ___________
Actor motive: ___________

---

**Scenario F:** *An HR system generated incorrect spreadsheets during a software upgrade, automatically emailing salary data to the wrong department.*

Actor type: ___________
Actor variety: ___________
Actor motive: ___________

---

**Scenario G:** *A phishing kit-as-a-service was rented by an unknown actor who targeted your organization with a fake Microsoft 365 login page.*

Actor type: ___________
Actor variety: ___________
Actor motive: ___________

---

**Scenario H:** *A hospital's biomedical engineering team notices that an internet-connected infusion pump is transmitting patient data to an unknown IP address.
Investigation traces the IP to a cybersecurity research team that discovered the vulnerability and is collecting proof-of-concept data.*

Actor type: ___________
Actor variety: ___________
Actor motive: ___________

---

## Part 2: Action Chain Mapping (5 scenarios)

For each attack scenario, identify all actions in the correct **sequence** using the VERIS action categories.
Use the format:

```text
Step 1: [Action Category] > [Variety] via [Vector]
Step 2: [Action Category] > [Variety] via [Vector]
...
```

---

**Attack 1: Credential Theft to Data Exfiltration**

> *Attackers sent spear-phishing emails to 15 finance employees with a link to a fake O365 login page. 3 employees entered credentials. The attackers used the stolen credentials to log in to the company's VPN, from which they moved laterally to a file server and downloaded 8GB of financial documents over 4 days.*

Action chain:

Step 1: _________________________________
Step 2: _________________________________
Step 3: _________________________________

---

**Attack 2: Ransomware Deployment**

> *A malicious macro-enabled Word document was attached to a phishing email sent to an accounts payable clerk. The clerk opened and enabled macros. The macro downloaded a second-stage payload (Cobalt Strike beacon) from a C2 server. The attacker used the beacon to enumerate the network, escalate privileges via a Kerberoasting attack, and then deployed ALPHV ransomware across the domain.*

Action chain:

Step 1: _________________________________
Step 2: _________________________________
Step 3: _________________________________
Step 4: _________________________________
Step 5: _________________________________

---

**Attack 3: Physical POS Compromise**

> *A criminal traveled to 12 retail locations and physically installed skimming overlays on payment terminals at each checkout counter. The skimmers collected card data and transmitted it via Bluetooth to a device in the criminal's car in the parking lot.*

Action chain:

Step 1: _________________________________
Step 2: _________________________________

---

**Attack 4: Cloud Misconfiguration to Data Exposure**

> *A developer ran a script that created a new Elasticsearch cluster for log analysis. The default configuration left the cluster without authentication. A search engine specifically designed to find exposed cloud services indexed the data within 48 hours. A security researcher found the indexed data and notified the company.*

Action chain:

Step 1: _________________________________
(Consider: Is there a second action, or is this a single-step incident?)

---

**Attack 5: Insider to Supply Chain**

> *A software engineer at a vendor company was recruited by a foreign intelligence service and paid to introduce a backdoor into a security software product. The backdoor was compiled into a legitimate update package and distributed to over 10,000 customer organizations.*

Action chain (from the engineer's perspective):

Step 1: _________________________________
Step 2: _________________________________
(Now answer: If you were encoding this for the VICTIM organizations, what would the action chain look like?)

---

## Part 3: Quick-Fire Classification (10 questions)

For each question, provide the single-word VERIS action category.

1. An employee emails a customer's account information to the wrong customer. → ___________
1. A nation-state group exploits a Citrix VPN zero-day to gain initial access. → ___________
1. A ransomware gang calls an employee pretending to be IT support and obtains their password. → ___________
1. A hurricane destroys a data center. → ___________
1. An employee copies sensitive files to a USB drive before resigning. → ___________
1. Attackers install a keylogger by exploiting a browser vulnerability on a user's computer. → ___________
1. An admin accidentally runs `rm -rf /data` in production. → ___________
1. A criminal gang attaches a skimming device to a gas station pump. → ___________
1. An employee emails their work files to a personal Gmail account "for convenience." → ___________
1. A botnet sends millions of packets to your DNS server causing it to go offline. → ___________

---

## Answers

Compare your answers to:
`drills/basic/solutions/drill-02-solution/solution.md`

---

*Drill 02 | Session 11 | Security Operations Master Class | Digital4Security*
