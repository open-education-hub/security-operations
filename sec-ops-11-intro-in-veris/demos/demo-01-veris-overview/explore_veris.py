#!/usr/bin/env python3
"""
VERIS Demo 01 - VERIS Framework Overview with Worked Examples
Session 11 | Security Operations Master Class | Digital4Security

Run: python3 explore_veris.py
"""

import json

INCIDENTS = [
    {
        "incident_id": "demo-001",
        "source_id": "demo",
        "summary": "Phishing email led to credential theft; attacker accessed customer database",
        "confidence": "High",
        "security_incident": "Confirmed",
        "timeline": {
            "incident": {"year": 2024, "month": 3},
            "discovery": {"unit": "Days", "value": 14},
            "containment": {"unit": "Hours", "value": 48}
        },
        "victim": {
            "industry": "522110",
            "industry2": "Commercial Banking",
            "employee_count": "1001 to 10000",
            "country": ["US"]
        },
        "actor": {
            "external": {
                "variety": ["Organized crime"],
                "motive": ["Financial"],
                "country": ["Unknown"]
            }
        },
        "action": {
            "social": {
                "variety": ["Phishing"],
                "vector": ["Email"],
                "target": ["End-user"]
            },
            "hacking": {
                "variety": ["Use of stolen credentials"],
                "vector": ["Web application"]
            }
        },
        "asset": {
            "assets": [
                {"variety": "S - Database", "amount": 1},
                {"variety": "U - Desktop", "amount": 12}
            ],
            "cloud": ["No"]
        },
        "attribute": {
            "confidentiality": {
                "data_disclosure": "Yes",
                "data_total": 25000,
                "data": [
                    {"variety": "Personal", "amount": 20000},
                    {"variety": "Credentials", "amount": 5000}
                ]
            }
        }
    },
    {
        "incident_id": "demo-002",
        "source_id": "demo",
        "summary": "IT admin accidentally exposed customer backup to public S3 bucket for 3 weeks",
        "confidence": "High",
        "security_incident": "Confirmed",
        "timeline": {
            "incident": {"year": 2024, "month": 5},
            "discovery": {"unit": "Days", "value": 21},
            "containment": {"unit": "Hours", "value": 2}
        },
        "victim": {
            "industry": "621111",
            "industry2": "Offices of Physicians",
            "employee_count": "11 to 100",
            "country": ["US"]
        },
        "actor": {
            "internal": {
                "variety": ["System administrator"],
                "motive": ["Convenience"]
            }
        },
        "action": {
            "error": {
                "variety": ["Misconfiguration"],
                "vector": ["Unknown"]
            }
        },
        "asset": {
            "assets": [
                {"variety": "S - Database", "amount": 1}
            ],
            "cloud": ["Yes"]
        },
        "attribute": {
            "confidentiality": {
                "data_disclosure": "Yes",
                "data_total": 8500,
                "data": [
                    {"variety": "Medical (PHI)", "amount": 8500}
                ]
            }
        }
    },
    {
        "incident_id": "demo-003",
        "source_id": "demo",
        "summary": "Ransomware deployed via phishing, encrypting 150 workstations and 4 file servers",
        "confidence": "High",
        "security_incident": "Confirmed",
        "timeline": {
            "incident": {"year": 2024, "month": 8},
            "discovery": {"unit": "Hours", "value": 3},
            "containment": {"unit": "Days", "value": 5}
        },
        "victim": {
            "industry": "336111",
            "industry2": "Automobile Manufacturing",
            "employee_count": "10001 to 25000",
            "country": ["DE"]
        },
        "actor": {
            "external": {
                "variety": ["Organized crime"],
                "motive": ["Financial"]
            }
        },
        "action": {
            "social": {
                "variety": ["Phishing"],
                "vector": ["Email"]
            },
            "malware": {
                "variety": ["Ransomware"],
                "vector": ["Email attachment"]
            }
        },
        "asset": {
            "assets": [
                {"variety": "U - Desktop", "amount": 150},
                {"variety": "S - File", "amount": 4}
            ],
            "cloud": ["No"]
        },
        "attribute": {
            "integrity": {"variety": ["Software installation", "Alter behavior"]},
            "availability": {
                "variety": ["Encryption"],
                "duration": {"unit": "Days", "value": 5}
            }
        }
    }
]


def display_4a_summary(incident: dict):
    print(f"\n{'=' * 65}")
    print(f"  INCIDENT: {incident['incident_id']}")
    print(f"  {incident['summary'][:70]}...")
    print(f"{'=' * 65}")

    actors = incident.get("actor", {})
    print("\n  [ACTOR]")
    for actor_type, actor_data in actors.items():
        print(f"    Type:    {actor_type.capitalize()}")
        print(f"    Variety: {', '.join(actor_data.get('variety', ['Unknown']))}")
        print(f"    Motive:  {', '.join(actor_data.get('motive', ['Unknown']))}")

    actions = incident.get("action", {})
    print("\n  [ACTION]")
    for action_type, action_data in actions.items():
        print(f"    Category: {action_type.capitalize()}")
        print(f"    Variety:  {', '.join(action_data.get('variety', ['Unknown']))}")
        print(f"    Vector:   {', '.join(action_data.get('vector', ['Unknown']))}")

    assets = incident.get("asset", {}).get("assets", [])
    print("\n  [ASSET]")
    for asset in assets:
        print(f"    {asset['variety']} (count: {asset.get('amount', 1)})")
    print(f"    Cloud: {', '.join(incident.get('asset', {}).get('cloud', ['Unknown']))}")

    attrs = incident.get("attribute", {})
    print("\n  [ATTRIBUTE]")
    for attr_type, attr_data in attrs.items():
        print(f"    {attr_type.capitalize()}:")
        if attr_type == "confidentiality":
            print(f"      Disclosure: {attr_data.get('data_disclosure', 'Unknown')}")
            print(f"      Records:    {attr_data.get('data_total', 'Unknown')}")
            print(f"      Data types: {', '.join(d['variety'] for d in attr_data.get('data', []))}")
        elif attr_type == "availability":
            dur = attr_data.get("duration", {})
            print(f"      Variety:  {', '.join(attr_data.get('variety', []))}")
            if dur:
                print(f"      Duration: {dur.get('value')} {dur.get('unit')}")
        elif attr_type == "integrity":
            print(f"      Variety:  {', '.join(attr_data.get('variety', []))}")

    breach = attr_data = incident.get("attribute", {}).get("confidentiality", {}).get("data_disclosure", "No")
    is_breach = breach in ["Yes", "Potentially"]
    icp = classify_icp(incident)
    disc = incident.get("timeline", {}).get("discovery", {})
    print(f"\n  [CLASSIFICATION]")
    print(f"    Incident pattern: {icp}")
    print(f"    Data breach:      {'YES' if is_breach else 'NO'}")
    print(f"    Discovery time:   {disc.get('value', '?')} {disc.get('unit', '')}")


def classify_icp(incident: dict) -> str:
    actions = set(incident.get("action", {}).keys())
    malware_varieties = incident.get("action", {}).get("malware", {}).get("variety", [])
    if "malware" in actions and "Ransomware" in malware_varieties:
        return "System Intrusion (Ransomware)"
    elif "error" in actions:
        return "Miscellaneous Errors"
    elif "social" in actions and "hacking" in actions:
        return "System Intrusion"
    elif "social" in actions:
        return "Social Engineering"
    elif "hacking" in actions:
        return "Basic Web Application Attack"
    elif "misuse" in actions:
        return "Privilege Misuse"
    elif "physical" in actions:
        return "Lost and Stolen Assets"
    return "Everything Else"


def summary_statistics(incidents: list):
    print(f"\n{'=' * 65}")
    print("  AGGREGATE SUMMARY (3 incidents)")
    print(f"{'=' * 65}")
    actor_counts, action_counts, attr_counts, breach_count = {}, {}, {}, 0
    for inc in incidents:
        for a in inc.get("actor", {}):
            actor_counts[a] = actor_counts.get(a, 0) + 1
        for a in inc.get("action", {}):
            action_counts[a] = action_counts.get(a, 0) + 1
        for a in inc.get("attribute", {}):
            attr_counts[a] = attr_counts.get(a, 0) + 1
        if inc.get("attribute", {}).get("confidentiality", {}).get("data_disclosure", "No") in ["Yes", "Potentially"]:
            breach_count += 1

    print(f"\n  Actor types:    {dict(sorted(actor_counts.items(), key=lambda x: -x[1]))}")
    print(f"  Action types:   {dict(sorted(action_counts.items(), key=lambda x: -x[1]))}")
    print(f"  Attributes:     {dict(sorted(attr_counts.items(), key=lambda x: -x[1]))}")
    print(f"  Data breaches:  {breach_count}/{len(incidents)}")
    print()


if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  VERIS Demo 01: Framework Overview with Worked Examples")
    print("  Session 11 | Security Operations Master Class")
    print("=" * 65)
    for incident in INCIDENTS:
        display_4a_summary(incident)
    summary_statistics(INCIDENTS)
