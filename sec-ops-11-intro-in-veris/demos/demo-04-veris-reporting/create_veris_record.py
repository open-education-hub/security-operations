#!/usr/bin/env python3
"""
VERIS Demo 04 - Creating and Validating a VERIS Record
Session 11 | Security Operations Master Class | Digital4Security

Run: python3 create_veris_record.py
"""
import json
import uuid

VERIS_RECORD = {
    "schema_version": "1.3.7",
    "incident_id": str(uuid.uuid4()),
    "source_id": "demo",
    "summary": (
        "MSP supply chain attack: compromised RMM software used to deploy "
        "credential-harvesting malware to 8 workstations. Stolen domain admin "
        "credentials used to access core banking application and exfiltrate 12,000 "
        "customer records (PII + bank account data)."
    ),
    "confidence": "High",
    "security_incident": "Confirmed",
    "timeline": {
        "incident": {"year": 2024, "month": 3},
        "compromise": {"unit": "Days", "value": 30, "notes": "MSP compromised 30 days before victim firm"},
        "discovery": {"unit": "Days", "value": 22},
        "containment": {"unit": "Unknown", "value": -1},
        "exfiltration": {"unit": "Unknown", "value": -1}
    },
    "victim": {
        "victim_id": "Anonymized Financial Services Firm",
        "industry": "522110",
        "industry2": "Commercial Banking",
        "employee_count": "101 to 1000",
        "country": ["US"],
        "region": ["NA"]
    },
    "actor": {
        "external": {
            "variety": ["Organized crime"],
            "motive": ["Financial"],
            "country": ["Unknown"],
            "notes": "Actor compromised MSP as stepping stone to victim firm"
        },
        "partner": {
            "motive": ["Unknown"],
            "industry": "541513",
            "notes": "MSP RMM software used as attack vector after MSP compromise"
        }
    },
    "action": {
        "hacking": {
            "variety": ["Use of stolen credentials", "Use of backdoor or C2"],
            "vector": ["Desktop sharing software", "Web application"],
            "notes": "RMM agent used as C2; stolen creds used for banking DB access"
        },
        "malware": {
            "variety": ["Keylogger", "Credential stealer"],
            "vector": ["Direct install"],
            "notes": "Deployed via compromised MSP RMM agent"
        }
    },
    "asset": {
        "assets": [
            {"variety": "U - Desktop", "amount": 8},
            {"variety": "S - Database", "amount": 1}
        ],
        "cloud": ["No"]
    },
    "attribute": {
        "confidentiality": {
            "data_disclosure": "Yes",
            "data_total": 12000,
            "data_victim": ["Customer"],
            "data": [
                {"variety": "Personal", "amount": 12000},
                {"variety": "Bank", "amount": 12000}
            ]
        }
    },
    "discovery_method": {
        "internal": {"variety": ["Reported by user"]}
    },
    "impact": {
        "loss": [
            {
                "variety": "Response and remediation",
                "amount": 1800000,
                "iso_currency_code": "USD"
            }
        ],
        "overall_rating": "Major"
    },
    "notes": "Supply chain attack. GLBA and state breach notification laws apply."
}

REQUIRED_FIELDS = ["incident_id", "source_id", "security_incident"]
REQUIRED_4A = ["actor", "action", "asset", "attribute"]


def validate(record):
    issues = []
    for f in REQUIRED_FIELDS:
        if f not in record: issues.append(f"MISSING: {f}")
    for d in REQUIRED_4A:
        if d not in record or not record[d]: issues.append(f"MISSING dimension: {d}")
    if "confidence" not in record: issues.append("ADVISORY: confidence not set")
    conf = record.get("attribute", {}).get("confidentiality", {})
    if conf.get("data_disclosure") in ["Yes", "Potentially"]:
        if not conf.get("data"): issues.append("ADVISORY: breach but no data types")
        if not conf.get("data_total"): issues.append("ADVISORY: breach but no record count")
    return issues


def print_summary(record):
    print(f"\n{'─' * 65}")
    print(f"  VERIS Record: {record['incident_id'][:8]}...")
    print(f"  Type: {record['security_incident']} | Confidence: {record['confidence']}")
    print(f"\n  Summary: {record['summary'][:80]}...")
    v = record.get("victim", {})
    t = record.get("timeline", {})
    print(f"\n  Victim: {v.get('industry2')} | {v.get('employee_count')} employees | {v.get('country')}")
    print(f"  Discovery: {t.get('discovery', {}).get('value')} {t.get('discovery', {}).get('unit')}")
    print(f"\n  Actor(s):")
    for at, d in record["actor"].items():
        print(f"    [{at}] {d.get('variety', [])} / {d.get('motive', [])}")
    print(f"\n  Action(s):")
    for at, d in record["action"].items():
        print(f"    [{at}] {d.get('variety', [])}")
    print(f"\n  Assets: {[a['variety'] + ' x' + str(a.get('amount')) for a in record['asset']['assets']]}")
    conf = record["attribute"].get("confidentiality", {})
    print(f"\n  Confidentiality: disclosure={conf.get('data_disclosure')}, total={conf.get('data_total')}")
    for d in conf.get("data", []):
        print(f"    {d['variety']}: {d.get('amount')} records")
    impact = record.get("impact", {})
    print(f"\n  Impact: {impact.get('overall_rating')}")
    for loss in impact.get("loss", []):
        print(f"    {loss['variety']}: ${loss['amount']:,} {loss.get('iso_currency_code', '')}")


if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  VERIS Demo 04: Creating a VERIS Record")
    print("  MSP Supply Chain Attack — Financial Services")
    print("=" * 65)
    issues = validate(VERIS_RECORD)
    print(f"\n  Validation: {'PASS' if not issues else 'ISSUES:'}")
    for i in issues: print(f"    ⚠ {i}")
    print_summary(VERIS_RECORD)
    outfile = "msp_supply_chain_veris.json"
    with open(outfile, "w") as f:
        json.dump(VERIS_RECORD, f, indent=2)
    print(f"\n  Exported: {outfile}\n")
