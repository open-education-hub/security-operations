#!/usr/bin/env python3
"""
Snort Rule Syntax Validator
============================
This script performs basic syntax validation on Snort 3 rules.
It checks for common mistakes made by students writing their first rules.

It does NOT replace running the rules through actual Snort — always test
your rules with: snort -c your-rules.rules --plugin-path /usr/lib/snort

Usage:
    python3 validate-snort-rules.py my-rules.rules
    python3 validate-snort-rules.py snort-rule-reference.rules
"""

import re
import sys


# ──────────────────────────────────────────────────────
# Rule parser and validator
# ──────────────────────────────────────────────────────

VALID_ACTIONS = {"alert", "drop", "pass", "reject", "rewrite", "log"}
VALID_PROTOS  = {"tcp", "udp", "icmp", "ip"}
VALID_DIRS    = {"->", "<>"}
VALID_CLASSTYPES = {
    "attempted-admin", "attempted-recon", "attempted-user",
    "denial-of-service", "misc-attack", "policy-violation",
    "shellcode-detect", "trojan-activity", "web-application-attack",
    "network-scan", "misc-activity", "bad-unknown",
}

# Regex to split a rule into header + options
RULE_RE = re.compile(
    r"^(alert|drop|pass|reject|rewrite|log)\s+"  # action
    r"(tcp|udp|icmp|ip)\s+"                       # proto
    r"(\S+)\s+"                                    # src_ip
    r"(\S+)\s+"                                    # src_port
    r"(->|<>)\s+"                                  # direction
    r"(\S+)\s+"                                    # dst_ip
    r"(\S+)\s+"                                    # dst_port
    r"\((.+)\)$",                                  # options
    re.IGNORECASE
)

def extract_option(options_str, key):
    """Extract the value of an option like msg:"value" or sid:12345."""
    # Match key:"quoted value" or key:unquoted_value
    pattern = re.compile(
        r"\b" + re.escape(key) + r':"([^"]*)"',  # quoted
        re.IGNORECASE
    )
    m = pattern.search(options_str)
    if m:
        return m.group(1)
    pattern2 = re.compile(r"\b" + re.escape(key) + r":(\S+?);", re.IGNORECASE)
    m2 = pattern2.search(options_str)
    if m2:
        return m2.group(1)
    return None


def validate_rule(rule_text, line_no):
    """Validate a single Snort rule. Returns list of (severity, message) tuples."""
    issues = []

    # Strip trailing comment
    rule = rule_text.split("#")[0].strip()
    if not rule:
        return issues

    # Join continuation lines (backslash)
    rule = rule.replace("\\\n", " ").replace("\\", " ")

    m = RULE_RE.match(rule)
    if not m:
        issues.append(("ERROR", f"Line {line_no}: Cannot parse rule header. "
                                 "Check action/proto/src/dir/dst/options format."))
        return issues

    action, proto, src_ip, src_port, direction, dst_ip, dst_port, options = m.groups()

    # Check for ??? placeholders (incomplete student rule)
    if "???" in rule:
        issues.append(("WARNING", f"Line {line_no}: Rule contains '???' placeholders — incomplete rule."))

    # Check msg field
    msg = extract_option(options, "msg")
    if not msg:
        issues.append(("ERROR", f"Line {line_no}: Missing 'msg:' option."))
    elif msg.startswith("???") or msg == "":
        issues.append(("WARNING", f"Line {line_no}: msg field is empty or placeholder."))

    # Check sid
    sid = extract_option(options, "sid")
    if not sid:
        issues.append(("ERROR", f"Line {line_no}: Missing 'sid:' option."))
    else:
        try:
            sid_val = int(sid.rstrip(";"))
            if sid_val < 1:
                issues.append(("ERROR", f"Line {line_no}: sid must be positive integer, got {sid_val}."))
            elif 1 <= sid_val <= 999999:
                issues.append(("WARNING", f"Line {line_no}: sid {sid_val} is in reserved range (1-999999). "
                                           "Use 1000000+ for custom rules."))
        except ValueError:
            issues.append(("ERROR", f"Line {line_no}: sid '{sid}' is not a valid integer."))

    # Check rev
    rev = extract_option(options, "rev")
    if not rev:
        issues.append(("WARNING", f"Line {line_no}: Missing 'rev:' option — recommended."))

    # Check classtype
    classtype = extract_option(options, "classtype")
    if not classtype:
        issues.append(("WARNING", f"Line {line_no}: Missing 'classtype:' option."))
    elif classtype.rstrip(";") not in VALID_CLASSTYPES:
        issues.append(("ERROR", f"Line {line_no}: Unknown classtype '{classtype}'. "
                                 f"Valid: {', '.join(sorted(VALID_CLASSTYPES))}"))

    # Check for dangerous overly broad rules
    if src_ip == "any" and dst_ip == "any" and src_port == "any" and dst_port == "any":
        issues.append(("WARNING", f"Line {line_no}: Rule matches all traffic (any/any → any/any). "
                                   "This will generate massive alert volume — narrow the scope."))

    # Check content options
    if "content:" not in options and "pcre:" not in options and "flow:" not in options:
        if proto in ("tcp", "udp"):
            issues.append(("WARNING", f"Line {line_no}: No content/pcre match — rule may generate many false positives."))

    # Check http_uri used without http protocol context
    if "http_uri" in options and proto != "tcp":
        issues.append(("ERROR", f"Line {line_no}: http_uri modifier requires TCP protocol."))

    if not issues:
        issues.append(("OK", f"Line {line_no}: Rule looks valid (msg='{msg}', sid={sid})."))

    return issues


# ──────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────

def validate_file(filepath):
    errors = 0
    warnings = 0
    ok_count = 0

    continuation = ""
    line_start = 1

    with open(filepath, errors="replace") as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        lineno = i + 1

        # Skip blank lines and pure comment lines
        if not line.strip() or line.strip().startswith("#"):
            i += 1
            continue

        # Handle line continuations (backslash at end)
        full_rule = line
        while full_rule.endswith("\\") and i + 1 < len(lines):
            full_rule = full_rule.rstrip("\\") + " " + lines[i + 1].strip()
            i += 1
        i += 1

        issues = validate_rule(full_rule.strip(), lineno)
        for severity, msg in issues:
            if severity == "ERROR":
                errors += 1
                print(f"[ERROR  ] {msg}")
            elif severity == "WARNING":
                warnings += 1
                print(f"[WARNING] {msg}")
            else:
                ok_count += 1
                print(f"[  OK   ] {msg}")

    print(f"\n{'='*60}")
    print(f"Results: {ok_count} valid rules, {warnings} warnings, {errors} errors")
    if errors > 0:
        print("Fix errors before deploying rules.")
    elif warnings > 0:
        print("Rules are syntactically correct but review warnings.")
    else:
        print("All rules passed validation.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    validate_file(sys.argv[1])
