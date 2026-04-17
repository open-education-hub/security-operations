# Solution: Drill 02 — 4-A Classification from Incident Reports

---

## Incident A: The Public Database

### Classification

**Actor:** Internal — a developer or operations person at the company misconfigured the database.
There is no external actor involved in *causing* the incident (the researcher who found it is not an actor in the security incident sense — they reported it responsibly).

```json
"actor": {
  "internal": {
    "variety": ["System admin"],
    "motive": ["NA"]
  }
}
```

**Action:** Error — specifically a misconfiguration of database access controls.

```json
"action": {
  "error": {
    "variety": ["Misconfiguration"],
    "vector": ["Unknown"]
  }
}
```

**Asset:** Database server (cloud-hosted, publicly accessible).

```json
"asset": {
  "assets": [{"variety": "S - Database"}],
  "cloud": ["External Cloud Asset(s)"],
  "hosting": ["External Cloud Asset(s)"]
}
```

**Attribute:** Confidentiality — 1.2M customer records were potentially exposed.

```json
"attribute": {
  "confidentiality": {
    "data_disclosure": "Unknown",
    "data": [
      {"variety": "Personal", "amount": 1200000}
    ],
    "state": ["Stored unencrypted"]
  }
}
```

**`security_incident`: "Confirmed"** — the misconfiguration is confirmed and the data was confirmed to be exposed.
The question is whether it was actually *accessed* by unauthorized parties — that is "Unknown" in `data_disclosure`.
The incident itself is confirmed.

**Key judgment:** `data_disclosure: "Unknown"` is the honest answer.
The researcher accessed it (confirming exposure), but there's no evidence of malicious prior access.
Using "Unknown" is correct.

---

## Incident B: The Laptop Theft

### Classification

**Actor:** External — the laptop thief.
While the employee violated policy, the theft is caused by an external actor.

Note: There is also an **internal** element (policy violation, lack of encryption), but the primary cause of the breach is the physical theft.
The internal element would be captured as a contributing factor, or coded as a second `action.error` if you choose to be thorough.

```json
"actor": {
  "external": {
    "variety": ["Unknown"],
    "motive": ["Unknown"]
  }
}
```

**Action:** Physical theft.
The lack of encryption is an Error (misconfiguration/policy violation) — some coders would add this as a second action.

```json
"action": {
  "physical": {
    "variety": ["Theft"],
    "vector": ["Uncontrolled location"]
  },
  "error": {
    "variety": ["Misconfiguration"],
    "vector": ["Unknown"]
  }
}
```

**Asset:** User device (laptop) and potentially media (unencrypted files).

```json
"asset": {
  "assets": [
    {"variety": "U - Laptop"},
    {"variety": "M - Disk"}
  ]
}
```

**Attribute:** Confidentiality — 450 employee records (salary, HR data).

```json
"attribute": {
  "confidentiality": {
    "data_disclosure": "Yes",
    "data": [
      {"variety": "Personal", "amount": 450},
      {"variety": "Internal", "amount": 450}
    ],
    "state": ["Stored unencrypted"]
  }
}
```

**Classification challenge:** Is this Physical/External (theft) or Error/Internal (policy violation)?
In VERIS, both can be recorded.
The **primary** cause is the theft; the error is a contributing factor.
Many VERIS coders would include both action types.

---

## Incident C: The DoS Attack

### Classification

**Actor:** External — unknown attacker(s).

```json
"actor": {
  "external": {
    "variety": ["Unknown"],
    "motive": ["Unknown"],
    "country": ["Unknown"]
  }
}
```

**Action:** Hacking — DDoS is classified under hacking in VERIS.

```json
"action": {
  "hacking": {
    "variety": ["DoS"],
    "vector": ["Unknown"]
  }
}
```

**Asset:** Network or web server (the website was the target).

```json
"asset": {
  "assets": [
    {"variety": "S - Web"},
    {"variety": "N - Unknown"}
  ]
}
```

**Attribute:** Availability only — no data was accessed.

```json
"attribute": {
  "availability": {
    "variety": ["Interruption"],
    "duration": {"unit": "Hours", "value": 4}
  }
}
```

**Key point:** When no data was accessed, there is **no confidentiality impact**.
Do NOT add `confidentiality` section "just in case." VERIS should only record what is known or confirmed.

**"Unknown" fields:** Actor variety, motive, country — all Unknown.
This is appropriate and honest.

---

## Complete Records

### Record A

```json
{
  "schema_version": "1.3.7",
  "incident_id": "incident-a",
  "security_incident": "Confirmed",
  "confidence": "High",
  "actor": {
    "internal": {"variety": ["System admin"], "motive": ["NA"]}
  },
  "action": {
    "error": {"variety": ["Misconfiguration"], "vector": ["Unknown"]}
  },
  "asset": {
    "assets": [{"variety": "S - Database"}],
    "cloud": ["External Cloud Asset(s)"]
  },
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Unknown",
      "data": [{"variety": "Personal", "amount": 1200000}],
      "state": ["Stored unencrypted"]
    }
  }
}
```

### Record B

```json
{
  "schema_version": "1.3.7",
  "incident_id": "incident-b",
  "security_incident": "Confirmed",
  "confidence": "High",
  "actor": {
    "external": {"variety": ["Unknown"], "motive": ["Unknown"]}
  },
  "action": {
    "physical": {"variety": ["Theft"], "vector": ["Uncontrolled location"]},
    "error": {"variety": ["Misconfiguration"], "vector": ["Unknown"]}
  },
  "asset": {
    "assets": [{"variety": "U - Laptop"}, {"variety": "M - Disk"}]
  },
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Yes",
      "data": [{"variety": "Personal", "amount": 450}],
      "state": ["Stored unencrypted"]
    }
  }
}
```

### Record C

```json
{
  "schema_version": "1.3.7",
  "incident_id": "incident-c",
  "security_incident": "Confirmed",
  "confidence": "High",
  "actor": {
    "external": {"variety": ["Unknown"], "motive": ["Unknown"]}
  },
  "action": {
    "hacking": {"variety": ["DoS"], "vector": ["Unknown"]}
  },
  "asset": {
    "assets": [{"variety": "S - Web"}]
  },
  "attribute": {
    "availability": {
      "variety": ["Interruption"],
      "duration": {"unit": "Hours", "value": 4}
    }
  }
}
```
