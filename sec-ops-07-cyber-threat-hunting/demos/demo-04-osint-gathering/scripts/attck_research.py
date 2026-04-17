#!/usr/bin/env python3
"""
Query MITRE ATT&CK for group and technique information.

Uses the mitreattack-python library to research threat actor TTPs
and obtain detection guidance for specific techniques.

Usage:
    pip install mitreattack-python
    python3 scripts/attck_research.py

The script downloads the ATT&CK STIX bundle (~20 MB) on first run
and caches it as enterprise-attack.json in the current directory.
"""

import sys
import json
import urllib.request
from pathlib import Path

try:
    from mitreattack.stix20 import MitreAttackData
except ImportError:
    print("[!] Missing dependency. Install with:  pip install mitreattack-python")
    sys.exit(1)

# ---------------------------------------------------------------------------
# ATT&CK data loader
# ---------------------------------------------------------------------------

STIX_CACHE = Path("enterprise-attack.json")
STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def load_attck() -> MitreAttackData:
    """Load ATT&CK data, downloading and caching if necessary."""
    if not STIX_CACHE.exists():
        print(f"[*] Downloading ATT&CK STIX bundle (~20 MB) → {STIX_CACHE}")
        urllib.request.urlretrieve(STIX_URL, STIX_CACHE)
        print("[✓] Download complete.")
    else:
        print(f"[*] Using cached ATT&CK data: {STIX_CACHE}")
    return MitreAttackData(str(STIX_CACHE))


# ---------------------------------------------------------------------------
# Group research
# ---------------------------------------------------------------------------

def research_group(group_name: str, mitre: MitreAttackData) -> None:
    """Print a structured profile of an ATT&CK group."""

    groups = mitre.get_groups()
    target_group = None

    for group in groups:
        if not hasattr(group, "name"):
            continue
        if group_name.lower() in group.name.lower():
            target_group = group
            break
        # Check aliases
        for alias in getattr(group, "aliases", []):
            if group_name.lower() in alias.lower():
                target_group = group
                break
        if target_group:
            break

    if not target_group:
        print(f"[-] Group '{group_name}' not found in ATT&CK.")
        return

    print(f"\n{'=' * 60}")
    print(f"Group: {target_group.name}")
    print(f"{'=' * 60}")

    aliases = getattr(target_group, "aliases", [])
    if aliases:
        print(f"Aliases: {', '.join(aliases)}")

    desc = getattr(target_group, "description", "No description available.")
    print(f"\nDescription:\n{desc[:400]}...")

    # Techniques organised by tactic
    print(f"\n[*] Techniques used by {target_group.name}:")
    try:
        techniques = mitre.get_techniques_used_by_group(target_group.id)
    except Exception:
        techniques = []

    by_tactic: dict = {}
    for tech in techniques:
        for phase in getattr(tech, "kill_chain_phases", []):
            tactic = phase.phase_name
            by_tactic.setdefault(tactic, []).append(tech.name)

    for tactic, names in sorted(by_tactic.items()):
        print(f"\n  [{tactic.upper().replace('-', ' ')}]")
        for name in names[:6]:
            print(f"    - {name}")

    # Associated software
    print(f"\n[*] Software used by {target_group.name}:")
    try:
        software_list = mitre.get_software_used_by_group(target_group.id)
    except Exception:
        software_list = []

    for sw in software_list[:10]:
        sw_type = getattr(sw, "type", "tool")
        print(f"  - {sw.name} ({sw_type})")


# ---------------------------------------------------------------------------
# Technique hunting guidance
# ---------------------------------------------------------------------------

def get_technique_hunting_guidance(technique_id: str, mitre: MitreAttackData) -> None:
    """Print detection data sources and guidance for a specific technique."""

    techniques = mitre.get_techniques()

    for tech in techniques:
        for ref in getattr(tech, "external_references", []):
            if getattr(ref, "external_id", None) == technique_id:
                print(f"\n{'=' * 60}")
                print(f"Technique: {tech.name} ({technique_id})")
                print(f"{'=' * 60}")

                data_sources = getattr(tech, "x_mitre_data_sources", [])
                if data_sources:
                    print("\nData Sources (for hunting):")
                    for ds in data_sources:
                        print(f"  - {ds}")

                detection = getattr(tech, "x_mitre_detection", "")
                if detection:
                    print(f"\nDetection Guidance:\n{detection[:400]}...")
                return

    print(f"[-] Technique {technique_id} not found in ATT&CK data.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mitre = load_attck()

    # Research a reference financially-motivated group
    research_group("FIN7", mitre)

    # Print hunting guidance for the key FIN-STORM TTPs
    print("\n\n=== HUNTING GUIDANCE FOR FIN-STORM TTPs ===")
    for tid in ["T1059.001", "T1003.001", "T1047"]:
        get_technique_hunting_guidance(tid, mitre)
