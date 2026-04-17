# Guide 02: Applying the 4-A Classification Framework

**Level:** Basic

**Estimated time:** 35 minutes

**Prerequisites:** Guide 01 (VERIS Schema)

---

## Objective

By the end of this guide, you will be able to:

* Apply the Actor, Action, Asset, and Attribute categories to incident descriptions
* Distinguish between similar-sounding categories (e.g., Hacking vs. Malware vs. Misuse)
* Handle uncertainty using VERIS "Unknown" values correctly
* Code a complete incident scenario using the 4-A framework

---

## Background

The 4-A framework is the heart of VERIS.
Every incident can be described by answering four questions:

1. **Actor**: Who caused this? (External, Internal, Partner)
1. **Action**: What did they do? (Hacking, Malware, Social, Misuse, Physical, Error, Environmental)
1. **Asset**: What was targeted? (Server, User Device, Network, Media, Person)
1. **Attribute**: What property was compromised? (Confidentiality, Integrity, Availability)

---

## Actor Categories Deep Dive

### External vs. Internal: Key Distinction

The most important distinction in VERIS actor classification:

| Clue in the scenario | Actor type |
|----------------------|-----------|
| "An attacker from outside" | External |
| "A hacker" | External |
| "An employee" | Internal |
| "A contractor" | Internal (if they have organizational access) |
| "A vendor" | Partner |
| "Our IT service provider" | Partner |

**Internal actors are NOT necessarily malicious.** Internal includes:

* Deliberate malicious insiders
* Negligent employees who accidentally cause incidents
* Administrative errors by authorized users

```json
// Malicious insider
"actor": {
  "internal": {
    "variety": ["System admin"],
    "motive": ["Grudge"]
  }
}

// Negligent employee (accidental)
"actor": {
  "internal": {
    "variety": ["End-user"],
    "motive": ["NA"]
  }
}
```

### Exercise: Classify the Actor

For each scenario, identify the actor type:

1. "A disgruntled database administrator deleted production records before quitting."

   > **Answer:** Internal (System admin, Grudge)

1. "An organized crime group conducted a spear phishing campaign targeting European banks."

   > **Answer:** External (Organized crime, Financial)

1. "A cloud hosting provider's shared infrastructure was compromised, affecting multiple clients."

   > **Answer:** Partner (IT outsourcing provider)

1. "A developer accidentally pushed API keys to a public GitHub repository."

   > **Answer:** Internal (Developer, negligent — motive: NA)

---

## Action Categories Deep Dive

### The Seven Actions and When to Use Each

**Hacking** — Technical exploitation of systems:

```text
Clues: "exploited vulnerability", "SQL injection", "brute force",
       "used stolen credentials", "unauthorized access to system"
```

**Malware** — Malicious software:

```text
Clues: "ransomware", "virus", "trojan", "keylogger", "spyware",
       "malware installed", "infected", "backdoor"
```

**Social Engineering** — Human manipulation:

```text
Clues: "phishing email", "fake login page", "impersonated IT",
       "pretexted", "business email compromise", "vishing call"
```

**Misuse** — Legitimate access used improperly:

```text
Clues: "used their authorized access to", "downloaded data they
       weren't supposed to", "accessed records outside their role"
       NOTE: Must have legitimate access — this is NOT hacking
```

**Physical** — Physical access to systems:

```text
Clues: "laptop stolen", "USB drive found", "device tampered",
       "ATM skimmer", "shoulder surfing", "break-in"
```

**Error** — Accidental/unintentional:

```text
Clues: "misconfigured", "accidentally sent to wrong recipient",
       "publicly exposed by mistake", "programming error",
       "left default credentials"
```

**Environmental** — Natural/physical environment:

```text
Clues: "power outage", "flood", "fire", "earthquake", "lightning"
```

### Exercise: Classify the Action

1. "The attacker sent a fake invoice email to the finance team."

   > **Answer:** Social / Phishing

1. "Ransomware encrypted all files on the company's servers."

   > **Answer:** Malware / Ransomware

1. "An employee emailed a spreadsheet of customer data to their personal email by mistake."

   > **Answer:** Error / Misdelivery (Internal actor, accidental)

1. "The threat actor exploited a vulnerability in the VPN appliance to gain initial access."

   > **Answer:** Hacking / Exploit public-facing application

1. "A salesperson downloaded the full customer database before leaving to work for a competitor."

   > **Answer:** Misuse / Privilege abuse (Internal actor)

---

## Asset Categories Deep Dive

### Asset Type Prefixes

| Code | Type | Common varieties |
|------|------|-----------------|
| `S` | Server | Database, Web, Mail, File, Directory, DNS, Log |
| `U` | User Device | Desktop, Laptop, Mobile, Tablet |
| `N` | Network | Router, Switch, Firewall, WAP, PBX |
| `M` | Media | Flash drive, Backup tape, Paper, Disk |
| `P` | Person | End-user, Finance, Executive, Developer, DBA |
| `T` | Kiosk/Terminal | ATM, POS, Kiosk |

### Tips for Asset Classification

* **Multiple assets are common**: A breach often involves Person (phished user) → Mail server (credentials used) → Database (data exfiltrated)
* **Include the person as an asset** when phishing or social engineering is involved: `P - End-user`
* **Database is the ultimate target** in most data breaches: `S - Database`
* **Paper records count**: Physical theft of printed documents = `M - Paper`

### Exercise: Classify the Assets

For the scenario: "An attacker phished an employee, stole their VPN credentials, connected remotely, and copied data from the HR database."

> **Answer:**
> - `P - End-user` (the phished employee)
> - `U - Desktop` or `N - VPN` (remote access point)
> - `S - Database` (HR data source)

---

## Attribute Categories Deep Dive

### Confidentiality

Use this when data was accessed, viewed, or copied without authorization:

```json
"attribute": {
  "confidentiality": {
    "data_disclosure": "Yes",
    "data": [
      {"variety": "Personal", "amount": 10000},
      {"variety": "Medical", "amount": 5000}
    ],
    "state": ["Stored unencrypted"]
  }
}
```

`data_disclosure`:

* "Yes" — confirmed that data was accessed/stolen
* "No" — no evidence data was accessed (e.g., attacker was stopped before reaching data)
* "Unknown" — unclear whether data was accessed

### Integrity

Use this when data or systems were modified:

```json
"attribute": {
  "integrity": {
    "variety": ["Install code", "Modify data"]
  }
}
```

Common integrity varieties:

* `Install code` — malware was installed
* `Modify data` — records were altered
* `Create account` — unauthorized account created
* `Alter behavior` — system configuration changed
* `Repudiation` — logs were deleted/tampered

### Availability

Use this when systems or data were made unavailable:

```json
"attribute": {
  "availability": {
    "variety": ["Extortion"],
    "duration": {"unit": "Days", "value": 3}
  }
}
```

Common availability varieties:

* `Interruption` — complete outage
* `Degradation` — performance impacted
* `Extortion` — ransomware / data held hostage
* `Loss` — permanent data or system loss
* `Obscuration` — service degraded by flooding

---

## Complete Coding Exercise

**Scenario:**
> A manufacturing company received an invoice email that appeared to come from their CEO. A finance employee approved a $75,000 wire transfer to a fraudulent bank account. Two weeks later, the company also discovered that a contractor had installed a keylogger on a shared workstation three months prior, and had been capturing employee credentials. Some of those credentials were used to access the company's ERP system and download supplier contracts.

**Step 1: Identify actors**

1. External actor (organized crime / BEC gang) — financial motive
1. Partner (contractor) — financial motive

**Step 2: Identify actions**

1. Social / Pretexting (fake CEO email — Business Email Compromise)
1. Physical or Malware — keylogger installation by contractor
1. Hacking / Use of stolen credentials — ERP access

**Step 3: Identify assets**

1. Person (Finance employee — BEC victim)
1. S-Other (banking/wire transfer system)
1. U-Desktop (workstation with keylogger)
1. S-ERP or S-Database (ERP with supplier contracts)

**Step 4: Identify attributes**

1. Financial impact from wire transfer (not a traditional CIA attribute, but VERIS captures this in `impact`)
1. Confidentiality — supplier contracts disclosed
1. Integrity — keylogger installed (Install code)

**Full VERIS JSON:**

```json
{
  "actor": {
    "external": {
      "variety": ["Organized crime"],
      "motive": ["Financial"]
    },
    "partner": {
      "variety": ["Other"],
      "motive": ["Financial"]
    }
  },
  "action": {
    "social": {
      "variety": ["Pretexting", "BEC"],
      "vector": ["Email"],
      "target": ["Finance"]
    },
    "malware": {
      "variety": ["Spyware"],
      "vector": ["Direct install"]
    },
    "hacking": {
      "variety": ["Use of stolen creds"],
      "vector": ["Web application"]
    }
  },
  "asset": {
    "assets": [
      {"variety": "P - Finance"},
      {"variety": "U - Desktop"},
      {"variety": "S - Database"}
    ]
  },
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Yes",
      "data": [{"variety": "Internal", "amount": 0}]
    },
    "integrity": {
      "variety": ["Install code", "Repudiation"]
    }
  }
}
```

---

## Summary

You have practiced:

* Classifying actors as External, Internal, or Partner based on scenario clues
* Distinguishing all seven action types and their key indicators
* Mapping affected systems to VERIS asset varieties
* Applying CIA attributes and their VERIS sub-fields

**Next:** Guide 03 — Interpreting DBIR findings
