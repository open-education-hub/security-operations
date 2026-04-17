#!/bin/bash
# collect-findings.sh
# Auto-collect security audit findings from the drill environment.
# Run this inside the container AFTER completing manual investigation.
# Output is a pre-filled skeleton for the Task 6 security report.
#
# Usage: bash /scripts/collect-findings.sh [--report]
#   --report   Write a report file to /tmp/security-report.txt

set -euo pipefail

REPORT_FILE="/tmp/security-report.txt"
WRITE_REPORT=0
[ "${1:-}" = "--report" ] && WRITE_REPORT=1

HOSTNAME=$(hostname)
DATE=$(date '+%Y-%m-%d %H:%M UTC')

# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────
RED='\033[91m'; YELLOW='\033[93m'; GREEN='\033[92m'; RESET='\033[0m'; BOLD='\033[1m'
crit()  { echo -e "${RED}[CRITICAL] $*${RESET}"; }
warn()  { echo -e "${YELLOW}[HIGH]     $*${RESET}"; }
info()  { echo -e "${GREEN}[MEDIUM]   $*${RESET}"; }
hdr()   { echo -e "\n${BOLD}$*${RESET}"; echo "$(printf '%.0s─' {1..60})"; }

# Accumulate findings for report
FINDINGS=""
append() { FINDINGS="${FINDINGS}$*\n"; }

# ─────────────────────────────────────────────────────────────────
# 1. SUID BINARY AUDIT
# ─────────────────────────────────────────────────────────────────
hdr "1. SUID BINARY AUDIT"

EXPECTED_SUID=(
    /usr/bin/su
    /usr/bin/sudo
    /usr/bin/passwd
    /usr/bin/newgrp
    /usr/bin/chfn
    /usr/bin/chsh
    /usr/bin/gpasswd
    /usr/bin/mount
    /usr/bin/umount
    /usr/bin/pkexec
    /usr/lib/openssh/ssh-keysign
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
)

echo "All SUID binaries found:"
while IFS= read -r f; do
    expected=0
    for e in "${EXPECTED_SUID[@]}"; do
        [ "$f" = "$e" ] && expected=1 && break
    done
    if [ "$expected" -eq 0 ]; then
        crit "UNEXPECTED SUID: $f"
        append "CRITICAL: Unexpected SUID binary: $f"
        append "  Risk: Any user can execute $f as root (privilege escalation)"
        append "  Fix:  chmod u-s $f"
    else
        echo -e "  ${GREEN}OK${RESET}  $f"
    fi
done < <(find / -perm -4000 -type f 2>/dev/null | sort)

# ─────────────────────────────────────────────────────────────────
# 2. UID 0 ACCOUNTS
# ─────────────────────────────────────────────────────────────────
hdr "2. USER ACCOUNTS WITH UID 0"

UID0=$(awk -F: '($3 == 0)' /etc/passwd)
if echo "$UID0" | grep -qv "^root:"; then
    while IFS= read -r line; do
        user=$(echo "$line" | cut -d: -f1)
        if [ "$user" != "root" ]; then
            crit "UID 0 account (other than root): $user"
            append "CRITICAL: UID 0 account: $user (full root equivalent)"
            append "  Risk: $user can do anything root can do — likely backdoor"
            append "  Fix:  userdel -r $user   (after verifying it is not needed)"
        fi
    done <<< "$UID0"
else
    echo -e "  ${GREEN}OK${RESET} Only root has UID 0."
fi

# ─────────────────────────────────────────────────────────────────
# 3. SUDO CONFIGURATION
# ─────────────────────────────────────────────────────────────────
hdr "3. SUDO CONFIGURATION"

# Check /etc/sudoers for NOPASSWD
echo "NOPASSWD entries:"
grep -h 'NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | while read -r line; do
    warn "NOPASSWD rule: $line"
    append "HIGH: NOPASSWD sudo rule: $line"
    append "  Risk: User can run privileged commands without entering password"
    append "  Fix:  Remove NOPASSWD or restrict to specific non-dangerous commands"
done

# Check for dangerous ALL=(ALL) ALL rules
echo ""
echo "Full sudo rules (non-comment):"
grep -h -v '^\s*#' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^$' | while read -r line; do
    echo "  $line"
    if echo "$line" | grep -qE '\bALL\b.*\bALL\b.*\bALL\b'; then
        warn "Overly broad sudo rule: $line"
    fi
done

# ─────────────────────────────────────────────────────────────────
# 4. SSH CONFIGURATION
# ─────────────────────────────────────────────────────────────────
hdr "4. SSH DAEMON CONFIGURATION"

if command -v sshd &>/dev/null; then
    SSHD_CONFIG=$(sshd -T 2>/dev/null)

    check_ssh() {
        local key="$1" want="$2" risk="$3" fix="$4"
        val=$(echo "$SSHD_CONFIG" | grep "^${key} " | awk '{print $2}' | tr '[:upper:]' '[:lower:]')
        if [ "$val" = "$want" ]; then
            crit "sshd: ${key}=${val} — ${risk}"
            append "CRITICAL: SSH ${key}=${val}"
            append "  Risk:  $risk"
            append "  Fix:   $fix"
        else
            echo -e "  ${GREEN}OK${RESET}  ${key}=${val}"
        fi
    }

    check_ssh "permitrootlogin"     "yes"  \
        "Direct SSH root login allowed"                              \
        "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"

    check_ssh "passwordauthentication" "yes" \
        "Password authentication enabled (brute-forceable)"          \
        "Set 'PasswordAuthentication no'; use key-based auth only"

    check_ssh "permitemptypasswords" "yes" \
        "Empty passwords accepted — accounts with no password can log in!" \
        "Set 'PermitEmptyPasswords no'"

    maxauth=$(echo "$SSHD_CONFIG" | grep "^maxauthtries " | awk '{print $2}')
    if [ -n "$maxauth" ] && [ "$maxauth" -gt 5 ]; then
        warn "MaxAuthTries=${maxauth} — should be 3–5 to limit brute force window"
        append "HIGH: SSH MaxAuthTries=${maxauth} (should be 3-5)"
    fi
else
    echo "  sshd not running — skipping runtime config check."
fi

# Check for backdoor authorized_keys
echo ""
echo "Authorized keys files:"
find /home /root -name "authorized_keys" 2>/dev/null | while read -r akfile; do
    echo "  $akfile:"
    while IFS= read -r key; do
        [ -z "$key" ] && continue
        comment=$(echo "$key" | awk '{print $NF}')
        if echo "$comment" | grep -qiE 'attacker|malicious|backdoor|evil|hacker|kali|pwn'; then
            crit "  Suspicious authorized key: $comment  in $akfile"
            append "CRITICAL: Backdoor SSH key in $akfile: $comment"
            append "  Risk:  Attacker can SSH in without password"
            append "  Fix:   Remove the key: edit $akfile and delete the line"
        else
            echo -e "    ${YELLOW}REVIEW REQUIRED${RESET}: $comment"
        fi
    done < "$akfile"
done

# ─────────────────────────────────────────────────────────────────
# 5. WORLD-WRITABLE FILES AND DIRECTORIES
# ─────────────────────────────────────────────────────────────────
hdr "5. WORLD-WRITABLE FILES"

echo "World-writable files (excluding /tmp /proc /sys /dev):"
WW_FILES=$(find / -perm -0002 -type f \
    -not -path '/proc/*' -not -path '/sys/*' \
    -not -path '/dev/*' -not -path '/run/*' \
    2>/dev/null)

if [ -z "$WW_FILES" ]; then
    echo -e "  ${GREEN}OK${RESET} No unexpected world-writable files found."
else
    while IFS= read -r f; do
        owner=$(stat -c '%U' "$f" 2>/dev/null || echo "?")
        if echo "$f" | grep -qE '^/etc/cron|^/etc/passwd|^/etc/shadow|^/etc/sudoers'; then
            crit "World-writable critical file: $f (owner: $owner)"
            append "CRITICAL: World-writable critical system file: $f"
            append "  Risk:  Any user can modify $f — privilege escalation / backdoor"
            append "  Fix:   chmod 644 $f   (or 640 for sensitive files)"
        else
            warn "World-writable file: $f (owner: $owner)"
            append "HIGH: World-writable file: $f"
        fi
    done <<< "$WW_FILES"
fi

echo ""
echo "World-writable directories (excluding /tmp /dev /proc /sys /run):"
find / -perm -0002 -type d \
    -not -path '/proc/*' -not -path '/sys/*' \
    -not -path '/dev/*'  -not -path '/run/*' \
    -not \( -path '/tmp' -prune \) \
    2>/dev/null | while read -r d; do
    warn "World-writable directory: $d"
    append "HIGH: World-writable directory: $d"
done

# ─────────────────────────────────────────────────────────────────
# 6. /etc/passwd PERMISSIONS
# ─────────────────────────────────────────────────────────────────
hdr "6. CRITICAL FILE PERMISSIONS"

check_perm() {
    local file="$1" expected_mode="$2" description="$3"
    if [ ! -f "$file" ]; then return; fi
    actual=$(stat -c '%a' "$file")
    if [ "$actual" != "$expected_mode" ]; then
        crit "$file has mode $actual (should be $expected_mode) — $description"
        append "CRITICAL: $file permissions=$actual (expected $expected_mode)"
        append "  Fix:   chmod $expected_mode $file"
    else
        echo -e "  ${GREEN}OK${RESET}  $file (mode $actual)"
    fi
}

check_perm /etc/passwd  644 "world-readable is OK, but must not be writable!"
check_perm /etc/shadow  640 "readable only by root and shadow group"
check_perm /etc/sudoers 440 "immutable sudoers — must not be world-writable"

# ─────────────────────────────────────────────────────────────────
# SUMMARY REPORT
# ─────────────────────────────────────────────────────────────────
hdr "SUMMARY"
CRIT_COUNT=$(echo -e "$FINDINGS" | grep -c '^CRITICAL:' || true)
HIGH_COUNT=$(echo -e "$FINDINGS" | grep -c '^HIGH:' || true)
echo "  Critical findings : $CRIT_COUNT"
echo "  High findings     : $HIGH_COUNT"
echo ""
echo "  Use this output to fill in the Task 6 security report."
echo "  Compare your manual findings against these automated results."

if [ "$WRITE_REPORT" -eq 1 ]; then
    {
        echo "LINUX SECURITY REVIEW — Pre-Production Audit"
        echo "System  : $HOSTNAME"
        echo "Date    : $DATE"
        echo "Script  : collect-findings.sh (automated)"
        echo "$(printf '%.0s─' {1..60})"
        echo ""
        echo -e "$FINDINGS" | sed '/^$/d'
    } > "$REPORT_FILE"
    echo ""
    echo "  Report written to: $REPORT_FILE"
fi
