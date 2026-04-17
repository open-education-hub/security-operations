#!/usr/bin/env python3
"""
VERIS Demo 02 - Incident Classification Exercise - Answer Script
Session 11 | Security Operations Master Class | Digital4Security

Run: python3 classify_incidents.py
"""

CLASSIFIED_INCIDENTS = [
    {
        "incident_id": "demo-A",
        "label": "Hospital Insider",
        "narrative": "Nurse accessed celebrity patient records and shared with tabloid",
        "actor": {"internal": {"variety": ["End-user"], "motive": ["Financial", "Fun"]}},
        "action": {"misuse": {"variety": ["Privilege abuse"], "vector": ["Internal network access"]}},
        "asset": {"assets": [{"variety": "S - Database", "amount": 1}]},
        "attribute": {"confidentiality": {"data_disclosure": "Yes", "data": [{"variety": "Medical (PHI)", "amount": 1}]}},
        "teaching_notes": [
            "Internal actor — legitimate system access misused (not hacking)",
            "Misuse > Privilege abuse — accessing data outside authorized scope",
            "This IS a data breach: PHI confirmed disclosed to unauthorized third party",
            "HIPAA breach notification would be required",
            "Discovery method: internal audit (favorable — internal detection)"
        ]
    },
    {
        "incident_id": "demo-B",
        "label": "E-Commerce SQLi",
        "narrative": "SQLi on retail site extracted credentials; used for fraud",
        "actor": {"external": {"variety": ["Organized crime"], "motive": ["Financial"]}},
        "action": {"hacking": {"variety": ["SQLi", "Use of stolen credentials"], "vector": ["Web application"]}},
        "asset": {"assets": [{"variety": "S - Database", "amount": 1}, {"variety": "U - Desktop", "amount": 3200}]},
        "attribute": {"confidentiality": {"data_disclosure": "Yes", "data": [
            {"variety": "Credentials", "amount": 3200}, {"variety": "Payment", "amount": 3200}
        ]}},
        "teaching_notes": [
            "TWO hacking varieties in one action block: SQLi then Use of stolen creds",
            "Confidentiality only — no integrity or availability disruption",
            "Discovery: external (payment processor) = unfavorable, took 45 days",
            "PCI data disclosure triggers PCI DSS reporting obligations"
        ]
    },
    {
        "incident_id": "demo-C",
        "label": "School Ransomware",
        "narrative": "Phishing + ransomware at K-12 school district",
        "actor": {"external": {"variety": ["Organized crime"], "motive": ["Financial"]}},
        "action": {
            "social": {"variety": ["Phishing"], "vector": ["Email"]},
            "malware": {"variety": ["Ransomware"], "vector": ["Email attachment"]}
        },
        "asset": {"assets": [{"variety": "U - Desktop", "amount": 80}, {"variety": "S - File", "amount": 3}]},
        "attribute": {
            "integrity": {"variety": ["Software installation", "Alter behavior"]},
            "availability": {"variety": ["Encryption"], "duration": {"unit": "Hours", "value": 12}}
        },
        "teaching_notes": [
            "NO Confidentiality — no evidence of exfiltration; do NOT assume breach",
            "Ransomware = Integrity + Availability, not automatically Confidentiality",
            "Two actions: Social Engineering (delivery) then Malware (payload)",
            "Education sector (NAICS 611110)"
        ]
    },
    {
        "incident_id": "demo-D",
        "label": "Defense Contractor APT",
        "narrative": "Nation-state APT, 8-month dwell time, classified document theft",
        "actor": {"external": {"variety": ["Nation-state"], "motive": ["Espionage"]}},
        "action": {"hacking": {"variety": ["Exploit vulnerability"], "vector": ["VPN"]}},
        "asset": {"assets": [{"variety": "S - File", "amount": 1}, {"variety": "N - VPN concentrator", "amount": 1}]},
        "attribute": {"confidentiality": {"data_disclosure": "Yes", "data": [
            {"variety": "Classified", "amount": -1}, {"variety": "Internal", "amount": -1}
        ]}},
        "teaching_notes": [
            "Nation-state, not organized crime — motive is Espionage, not Financial",
            "Zero-day exploit = Hacking > Exploit vulnerability (zero-day variety)",
            "8-month dwell = extremely high dwell time (industry average is ~3 months)",
            "External discovery by government agency = detection gap",
            "-1 for amount indicates unknown quantity of records"
        ]
    },
    {
        "incident_id": "demo-E",
        "label": "ATM Skimmer Gang",
        "narrative": "Criminal gang installed skimmers on 12 ATMs, captured 340 cards",
        "actor": {"external": {"variety": ["Organized crime"], "motive": ["Financial"]}},
        "action": {"physical": {"variety": ["Tampering", "Skimming"], "vector": ["Victim facility"]}},
        "asset": {"assets": [{"variety": "T - ATM", "amount": 12}]},
        "attribute": {"confidentiality": {"data_disclosure": "Yes", "data": [{"variety": "Payment", "amount": 340}]}},
        "teaching_notes": [
            "PHYSICAL action — skimming is Physical category, NOT Hacking",
            "Asset: T (Kiosk/Terminal) > ATM",
            "PCI data (payment cards) triggers card brand and bank notification",
            "Discovery: internal (maintenance staff) — good internal detection"
        ]
    }
]


def display_classification(incident):
    print(f"\n{'=' * 65}")
    print(f"  {incident['incident_id']}: {incident['label']}")
    print(f"  Narrative: {incident['narrative']}")
    print(f"{'=' * 65}")
    for actor_type, d in incident.get("actor", {}).items():
        print(f"  ACTOR ({actor_type}): variety={d.get('variety')}, motive={d.get('motive')}")
    for action_type, d in incident.get("action", {}).items():
        print(f"  ACTION ({action_type}): variety={d.get('variety')}, vector={d.get('vector')}")
    for asset in incident.get("asset", {}).get("assets", []):
        print(f"  ASSET: {asset['variety']} x{asset.get('amount')}")
    for attr, d in incident.get("attribute", {}).items():
        if attr == "confidentiality":
            print(f"  ATTRIBUTE: Confidentiality — disclosure={d.get('data_disclosure')}")
            for rec in d.get("data", []):
                print(f"             data: {rec['variety']} ({rec.get('amount')} records)")
        elif attr == "availability":
            dur = d.get("duration", {})
            print(f"  ATTRIBUTE: Availability — {d.get('variety')} for {dur.get('value')} {dur.get('unit')}")
        elif attr == "integrity":
            print(f"  ATTRIBUTE: Integrity — {d.get('variety')}")
    is_breach = incident.get("attribute", {}).get("confidentiality", {}).get("data_disclosure", "No") in ["Yes", "Potentially"]
    print(f"  BREACH: {'YES' if is_breach else 'NO'}")
    print(f"\n  Teaching Notes:")
    for n in incident.get("teaching_notes", []):
        print(f"    • {n}")


if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  VERIS Demo 02: Classification Solutions")
    print("  Session 11 | Security Operations Master Class")
    print("=" * 65)
    for inc in CLASSIFIED_INCIDENTS:
        display_classification(inc)
    print(f"\n{'=' * 65}\n")
