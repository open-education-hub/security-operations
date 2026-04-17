#!/usr/bin/env python3
"""
Simple Sigma rule tester against sample log data.

Tests rule detection logic without requiring a full SIEM.
Supports the basic Sigma field modifiers: endswith, startswith, contains.

Usage:
    python3 tests/test_rules.py

Prerequisites:
    pip install pyyaml
"""

import json
import yaml
from pathlib import Path


# ---------------------------------------------------------------------------
# Log loading
# ---------------------------------------------------------------------------

def load_sample_logs(log_file: str) -> list:
    with open(log_file) as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Condition evaluation helpers
# ---------------------------------------------------------------------------

def _match_value(log_value: str, rule_value, modifiers: list) -> bool:
    """
    Return True if log_value satisfies rule_value given Sigma field modifiers.
    rule_value may be a scalar or a list (OR logic).
    """
    candidates = rule_value if isinstance(rule_value, list) else [rule_value]
    lv = log_value.lower()

    for candidate in candidates:
        cv = str(candidate).lower()
        if "endswith" in modifiers:
            if lv.endswith(cv):
                return True
        elif "startswith" in modifiers:
            if lv.startswith(cv):
                return True
        elif "contains" in modifiers:
            if cv in lv:
                return True
        else:
            if lv == cv:
                return True
    return False


def check_selection(log_entry: dict, selection: dict) -> bool:
    """
    Return True if ALL fields in a Sigma selection block match the log entry.
    Each field is an AND; values within a list field are OR.
    """
    for field_expr, rule_value in selection.items():
        parts = field_expr.split("|")
        field_name = parts[0]
        modifiers = parts[1:]

        log_value = log_entry.get(field_name, "")
        if log_value is None:
            return False

        if not _match_value(str(log_value), rule_value, modifiers):
            return False
    return True


# ---------------------------------------------------------------------------
# Rule testing
# ---------------------------------------------------------------------------

def test_rule_against_logs(rule_file: Path, logs: list) -> list:
    """
    Run a single Sigma rule against a list of log entries.
    Returns a list of matching log entries (alerts).
    """
    with open(rule_file) as fh:
        rule = yaml.safe_load(fh)

    title = rule.get("title", rule_file.name)
    level = rule.get("level", "unknown").upper()

    print(f"\n{'=' * 60}")
    print(f"Rule:  {title}")
    print(f"Level: {level}")
    print(f"{'=' * 60}")

    detection = rule.get("detection", {})

    # Separate named selections, filters, and the condition string
    selections = {
        k: v
        for k, v in detection.items()
        if k != "condition" and isinstance(v, dict) and not k.startswith("filter")
    }
    filters = {
        k: v
        for k, v in detection.items()
        if k.startswith("filter") and isinstance(v, dict)
    }

    hits = []
    for i, log in enumerate(logs):
        matched_selections = {
            name: check_selection(log, criteria)
            for name, criteria in selections.items()
        }
        matched_filters = {
            name: check_selection(log, criteria)
            for name, criteria in filters.items()
        }

        # Simplified condition: any selection hit AND no filter hit
        if any(matched_selections.values()) and not any(matched_filters.values()):
            hits.append(
                {
                    "log_index": i,
                    "log": log,
                    "matched_selections": [
                        k for k, v in matched_selections.items() if v
                    ],
                    "expected": log.get("expected_detection", "unknown"),
                }
            )

    if hits:
        print(f"[!] ALERTS: {len(hits)}")
        for hit in hits:
            log = hit["log"]
            print(
                f"\n    Log #{hit['log_index']}: "
                f"{log.get('ComputerName')} | {log.get('User')}"
            )
            print(f"    Time:     {log.get('timestamp')}")
            print(f"    Matched:  {', '.join(hit['matched_selections'])}")
            print(f"    Expected: {hit['expected']}")
            if "CommandLine" in log:
                print(f"    CmdLine:  {log['CommandLine'][:90]}...")
    else:
        print("[✓] No alerts triggered")

    return hits


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    log_path = Path(__file__).parent / "sample_logs.json"
    rules_dir = Path(__file__).parent.parent / "rules"

    if not log_path.exists():
        raise SystemExit(f"[!] Sample log file not found: {log_path}")

    if not rules_dir.exists():
        raise SystemExit(f"[!] Rules directory not found: {rules_dir}")

    logs = load_sample_logs(str(log_path))
    print(f"[*] Loaded {len(logs)} sample log events")
    print(f"[*] Testing rules in: {rules_dir}")

    all_hits: dict = {}
    for rule_file in sorted(rules_dir.glob("*.yml")):
        hits = test_rule_against_logs(rule_file, logs)
        all_hits[rule_file.name] = len(hits)

    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print(f"{'=' * 60}")
    for rule_name, count in all_hits.items():
        status = f"[!] {count} hit(s)" if count > 0 else "[✓] No hits"
        print(f"  {rule_name:<50} {status}")
