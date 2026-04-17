# Solution: Drill 02 (Intermediate) — VERIS Incident Report Creation

**Level:** Intermediate

**Directory:** `drills/intermediate/solutions/drill-02-solution/`

---

## Incident 1 Solution: Credential Stuffing Bank Attack

```json
{
  "schema_version": "1.3.7",
  "incident_id": "c7d8e9f0-a1b2-3456-cdef-012345678901",
  "source_id": "demo-solution",
  "summary": "Credential stuffing attack on online banking portal. 2,847 accounts accessed using credentials from external breaches; $340,000 stolen via ACH from 412 accounts. Detected by fraud monitoring system after 11 days.",
  "confidence": "High",
  "security_incident": "Confirmed",
  "timeline": {
    "incident": {
      "year": 2024,
      "month": 8,
      "day": 3
    },
    "discovery": {
      "unit": "Days",
      "value": 11,
      "notes": "Fraud operations flagged unusual transaction patterns"
    },
    "containment": {
      "unit": "Hours",
      "value": 6,
      "notes": "MFA enforced across all accounts within 6 hours of discovery"
    },
    "exfiltration": {
      "unit": "Unknown",
      "value": -1
    }
  },
  "victim": {
    "victim_id": "Anonymized Regional Bank",
    "industry": "522110",
    "industry2": "Commercial Banking",
    "employee_count": "1001 to 10000",
    "country": ["US"],
    "region": ["NA"]
  },
  "actor": {
    "external": {
      "variety": ["Unknown"],
      "motive": ["Financial"],
      "country": ["Unknown"],
      "region": ["Unknown"],
      "notes": "Botnet with IPs across 47 countries; likely organized crime but not confirmed"
    }
  },
  "action": {
    "hacking": {
      "variety": ["Brute force", "Use of stolen credentials"],
      "vector": ["Web application"],
      "notes": "8.2M credential pairs tested; credential stuffing using external breach data"
    }
  },
  "asset": {
    "assets": [
      {
        "variety": "S - Authentication",
        "amount": 1,
        "notes": "Online banking portal authentication system"
      },
      {
        "variety": "S - Web application",
        "amount": 1,
        "notes": "Online banking application"
      }
    ],
    "cloud": ["Unknown"]
  },
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Yes",
      "data_total": 2847,
      "data_victim": ["Customer"],
      "data": [
        {
          "variety": "Bank",
          "amount": 2847,
          "notes": "Account details, balances, transaction history for 2,847 accounts"
        },
        {
          "variety": "Personal",
          "amount": 2847,
          "notes": "Customer PII associated with accessed accounts"
        }
      ],
      "state": "Stored"
    }
  },
  "discovery_method": {
    "internal": {
      "variety": ["Fraud detection"]
    }
  },
  "impact": {
    "loss": [
      {
        "variety": "Asset and fraud",
        "amount": 340000,
        "iso_currency_code": "USD",
        "notes": "$340,000 drained via ACH from 412 accounts"
      },
      {
        "variety": "Notification",
        "amount": -1,
        "iso_currency_code": "USD",
        "notes": "All 2,847 affected customers notified within 3 business days"
      },
      {
        "variety": "Response and remediation",
        "amount": -1,
        "iso_currency_code": "USD"
      }
    ],
    "overall_rating": "Major",
    "notes": "412 accounts drained of funds; 2,435 accounts accessed but not financially exploited"
  },
  "notes": "GLBA breach notification required. Federal banking regulator (FDIC/OCC) notification likely required. Attack used botnet to evade IP-based rate limiting. Note: actor variety recorded as 'Unknown' because while organized crime is likely, attribution is not confirmed."
}
```

### Key Encoding Decisions for Incident 1

1. **Actor variety: "Unknown" not "Organized crime"** — The narrative says the attack "originated from a botnet across 47 countries" but does not confirm organized crime attribution. Using Unknown is the more conservative and accurate choice.

1. **Hacking variety: both "Brute force" and "Use of stolen credentials"** — Credential stuffing is a form of brute force (automated testing) that uses stolen credentials. Both varieties are appropriate.

1. **Two assets recorded** — The authentication system and the web application are both affected. Both are important for analysis.

1. **data_total: 2,847 not 412** — The disclosure count should be ALL accounts accessed (2,847), not just those with financial theft (412). All 2,847 accounts had their data viewed.

1. **Impact includes both financial loss AND notification costs** — The $340,000 theft is "Asset and fraud"; the notification effort is a separate impact.

---

## Incident 2 Solution: Insider PHI Theft

```json
{
  "schema_version": "1.3.7",
  "incident_id": "d0e1f2a3-b4c5-6789-def0-123456789012",
  "source_id": "demo-solution",
  "summary": "Billing specialist with authorized EHR access systematically exfiltrated 8,400 patient records over 87 days, exporting to personal email. Suspected motive: sale to data broker. Discovered via internal access review audit.",
  "confidence": "High",
  "security_incident": "Confirmed",
  "timeline": {
    "incident": {
      "year": 2023,
      "month": 10,
      "day": 8
    },
    "compromise": {
      "unit": "Days",
      "value": 87,
      "notes": "October 8, 2023 to January 3, 2024 — 87 days of unauthorized access"
    },
    "discovery": {
      "unit": "Days",
      "value": 87,
      "notes": "Discovered on January 3, 2024 during access review audit"
    },
    "containment": {
      "unit": "Hours",
      "value": 2,
      "notes": "Account disabled within 2 hours of discovery"
    },
    "exfiltration": {
      "unit": "Days",
      "value": 87,
      "notes": "Ongoing exfiltration via personal email over entire 87-day period"
    }
  },
  "victim": {
    "victim_id": "Anonymized Hospital System",
    "industry": "622110",
    "industry2": "General Medical and Surgical Hospitals",
    "employee_count": "10001 to 25000",
    "country": ["US"],
    "region": ["NA"],
    "locations_affected": 1,
    "notes": "Atlanta, GA"
  },
  "actor": {
    "internal": {
      "variety": ["End-user"],
      "motive": ["Financial"],
      "notes": "Billing specialist with authorized EHR access. Evidence of contact with suspected data broker."
    }
  },
  "action": {
    "misuse": {
      "variety": ["Privilege abuse", "Data mishandling"],
      "vector": ["Internal network access"],
      "notes": "Accessed records outside assigned billing queue; exported via personal email"
    }
  },
  "asset": {
    "assets": [
      {
        "variety": "S - Database",
        "amount": 1,
        "notes": "Revenue cycle management / EHR system"
      }
    ],
    "cloud": ["Unknown"]
  },
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Yes",
      "data_total": 8400,
      "data_victim": ["Patient"],
      "data": [
        {
          "variety": "Medical (PHI)",
          "amount": 8400,
          "notes": "Diagnoses, treatment information"
        },
        {
          "variety": "Personal",
          "amount": 8400,
          "notes": "Patient names, SSNs, demographics"
        },
        {
          "variety": "Insurance",
          "amount": 8400,
          "notes": "Insurance details and policy information"
        }
      ],
      "state": "Stored"
    }
  },
  "discovery_method": {
    "internal": {
      "variety": ["Audit"]
    }
  },
  "impact": {
    "loss": [
      {
        "variety": "Response and remediation",
        "amount": 700000,
        "iso_currency_code": "USD",
        "notes": "Investigation, forensics, legal fees"
      },
      {
        "variety": "Notification",
        "amount": 500000,
        "iso_currency_code": "USD",
        "notes": "Patient notification and credit monitoring for 8,400 patients"
      }
    ],
    "overall_rating": "Major",
    "notes": "Total estimated response cost $1.2M"
  },
  "notes": "HIPAA breach notification: filed with HHS OCR within 60 days as required. Individual patient notifications sent. Law enforcement referred. SSNs involved may trigger state identity theft protections. Attorney General notifications in affected states may be required."
}
```

### Key Encoding Decisions for Incident 2

1. **Actor: Internal, not External** — The billing specialist was an employee with legitimate authorized access. Even though they exfiltrated data for financial gain, they are an Internal actor. Motive: Financial.

1. **Action: Misuse, not Hacking** — The actor used their own legitimate credentials to access the system. No technical exploitation occurred. This is Misuse > Privilege abuse (accessing data outside their authorized scope).

1. **Three data types under Confidentiality** — PHI (diagnoses), Personal (names, SSNs), and Insurance details are all distinct data types. Recording each separately allows regulatory mapping (PHI → HIPAA; SSNs → state breach laws).

1. **Timeline.compromise = 87 days** — The "compromise" duration is the full period of unauthorized access, not the day of discovery.

1. **discovery_method: internal, Audit** — The access review audit is an internal discovery method. This is a relatively good detection (internal audit finding it, though 87 days is still a long dwell time).

---

## Common Mistakes to Avoid

| Mistake | Correct Approach |
|---------|----------------|
| Recording the insider as "External" | Internal actors have authorized access, even if they misuse it |
| Using "Hacking" for the insider | They used legitimate credentials — this is Misuse |
| Missing Insurance data type in Incident 2 | Insurance details are a separate, distinct data type |
| Recording data_total as 412 for Incident 1 | All 2,847 accounts accessed = 2,847, not just the 412 with financial theft |
| Missing the 87-day dwell time | Record compromise duration accurately; it's a key analytical data point |

---

*Solution — Drill 02 (Intermediate) | Session 11 | Security Operations Master Class | Digital4Security*
