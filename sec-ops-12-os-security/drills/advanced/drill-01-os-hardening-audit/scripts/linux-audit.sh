#!/bin/bash
# linux-audit.sh — CIS L1 Audit for LNX-DBSERVER-01

PASS=0
FAIL=0
WARN=0

pass() { echo "[PASS] $1"; ((PASS++)); }
fail() { echo "[FAIL] $1"; ((FAIL++)); }
warn() { echo "[WARN] $1"; ((WARN++)); }
section() { echo ""; echo "=== $1 ==="; }

echo "============================================================"
echo " CIS L1 Audit: LNX-DBSERVER-01 (Ubuntu 22.04)"
echo " Audit Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"

section "B1: Filesystem Security"

# /tmp mount options
if mount | grep -q "on /tmp type tmpfs.*nosuid.*noexec.*nodev" 2>/dev/null; then
    pass "/tmp mounted with nosuid,noexec,nodev"
else
    fail "/tmp NOT mounted with nosuid,noexec,nodev (CIS 1.1.2-1.1.4)"
fi

# World-writable files
WW=$(find / -xdev -perm -0002 -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/tmp/*" -not -path "/var/tmp/*" 2>/dev/null | wc -l)
if [ "$WW" -gt 0 ]; then
    fail "World-writable files found outside /tmp: $WW file(s) (CIS 6.1.12)"
    find / -xdev -perm -0002 -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/tmp/*" -not -path "/var/tmp/*" 2>/dev/null | head -10
else
    pass "No world-writable files found outside /tmp"
fi

# SUID binaries
SUID=$(find / -xdev -perm -4000 -type f 2>/dev/null)
SUID_COUNT=$(echo "$SUID" | wc -l)
echo "  SUID binaries found ($SUID_COUNT):"
echo "$SUID" | while read f; do
    case "$f" in
        /usr/bin/passwd|/usr/bin/sudo|/usr/bin/su|/bin/mount|/bin/umount|/usr/bin/newgrp|/usr/sbin/unix_chkpwd)
            echo "    [OK] $f" ;;
        *)
            echo "    [REVIEW] $f" ;;
    esac
done

section "B2: User Accounts and PAM"

# UID 0 accounts
UID0=$(awk -F: '$3 == 0 && $1 != "root"' /etc/passwd)
if [ -n "$UID0" ]; then
    fail "Non-root accounts with UID 0: $UID0 (CIS 6.2.2)"
else
    pass "No non-root UID 0 accounts"
fi

# Password aging
MAX=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
MIN=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
WARN_AGE=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')
[ "$MAX" -le 365 ] 2>/dev/null && pass "PASS_MAX_DAYS=$MAX (≤365)" || fail "PASS_MAX_DAYS=$MAX (should be ≤365, CIS 5.4.1.1)"
[ "$MIN" -ge 1 ] 2>/dev/null && pass "PASS_MIN_DAYS=$MIN (≥1)" || fail "PASS_MIN_DAYS=$MIN (should be ≥1, CIS 5.4.1.2)"
[ "$WARN_AGE" -ge 7 ] 2>/dev/null && pass "PASS_WARN_AGE=$WARN_AGE (≥7)" || fail "PASS_WARN_AGE=$WARN_AGE (should be ≥7, CIS 5.4.1.3)"

# PAM pwquality
if grep -q "pam_pwquality" /etc/pam.d/common-password; then
    MINLEN=$(grep -oP "minlen=\K[0-9]+" /etc/pam.d/common-password 2>/dev/null || echo "not set")
    [ "${MINLEN:-0}" -ge 14 ] 2>/dev/null && pass "PAM pwquality minlen=$MINLEN (≥14)" || fail "PAM pwquality minlen=$MINLEN (should be ≥14, CIS 5.3.1)"
else
    fail "pam_pwquality not configured (CIS 5.3.1)"
fi

section "B3: SSH Configuration"

sshd_check() {
    sshd -T 2>/dev/null | grep -i "^$1 " | awk '{print $2}'
}

PERMIT_ROOT=$(sshd_check "permitrootlogin")
PASS_AUTH=$(sshd_check "passwordauthentication")
MAX_AUTH=$(sshd_check "maxauthtries")
X11=$(sshd_check "x11forwarding")
TCP_FWD=$(sshd_check "allowtcpforwarding")
GRACE=$(sshd_check "logingracetime")
ALIVE=$(sshd_check "clientaliveinterval")

[ "$PERMIT_ROOT" = "no" ] && pass "PermitRootLogin=no" || fail "PermitRootLogin=$PERMIT_ROOT (should be 'no', CIS 5.2.10)"
[ "$PASS_AUTH" = "no" ] && pass "PasswordAuthentication=no" || fail "PasswordAuthentication=$PASS_AUTH (should be 'no', CIS 5.2.12)"
[ "${MAX_AUTH:-10}" -le 4 ] 2>/dev/null && pass "MaxAuthTries=$MAX_AUTH (≤4)" || fail "MaxAuthTries=$MAX_AUTH (should be ≤4, CIS 5.2.7)"
[ "$X11" = "no" ] && pass "X11Forwarding=no" || fail "X11Forwarding=$X11 (should be 'no', CIS 5.2.6)"
[ "$TCP_FWD" = "no" ] && pass "AllowTcpForwarding=no" || fail "AllowTcpForwarding=$TCP_FWD (should be 'no', CIS 5.2.21)"
[ "${GRACE:-120}" -le 60 ] 2>/dev/null && pass "LoginGraceTime=$GRACE (≤60)" || fail "LoginGraceTime=$GRACE (should be ≤60, CIS 5.2.16)"
[ "${ALIVE:-0}" -ge 1 ] 2>/dev/null && pass "ClientAliveInterval=$ALIVE (≥1)" || fail "ClientAliveInterval=$ALIVE (should be set, CIS 5.2.22)"

section "B4: Kernel and Network Security"

sysctl_check() {
    local key=$1 expected=$2 cis=$3
    local val
    val=$(sysctl -n "$key" 2>/dev/null)
    if [ "$val" = "$expected" ]; then
        pass "$key=$val"
    else
        fail "$key=$val (should be $expected, CIS $cis)"
    fi
}

sysctl_check "kernel.randomize_va_space" "2" "1.5.2"
sysctl_check "net.ipv4.ip_forward" "0" "3.1.1"
sysctl_check "net.ipv4.conf.all.accept_redirects" "0" "3.2.2"
sysctl_check "net.ipv4.conf.all.send_redirects" "0" "3.1.2"
sysctl_check "net.ipv4.tcp_syncookies" "1" "3.3.8"
sysctl_check "net.ipv4.conf.all.log_martians" "1" "3.3.1"
sysctl_check "net.ipv4.conf.all.rp_filter" "1" "3.3.4"

section "B5: PostgreSQL Security"

PGCONF="/etc/postgresql/15/main/postgresql.conf"
PGHBA="/etc/postgresql/15/main/pg_hba.conf"

if [ -f "$PGCONF" ]; then
    LISTEN=$(grep "^listen_addresses" "$PGCONF" | grep -oP "'[^']+'" | tr -d "'")
    [ "$LISTEN" = "localhost" ] || [ "$LISTEN" = "127.0.0.1" ] && \
        pass "PostgreSQL listens only on localhost" || \
        fail "PostgreSQL listen_addresses='$LISTEN' (should be 'localhost' if not needed externally)"

    grep -q "^ssl = on" "$PGCONF" && pass "PostgreSQL SSL enabled" || fail "PostgreSQL SSL disabled"
    grep -q "^log_connections = on" "$PGCONF" && pass "PostgreSQL log_connections=on" || fail "PostgreSQL log_connections not enabled"
    grep -q "^password_encryption = scram-sha-256" "$PGCONF" && pass "PostgreSQL using scram-sha-256" || \
        fail "PostgreSQL password_encryption=$(grep password_encryption $PGCONF | head -1) (should be scram-sha-256)"
else
    warn "PostgreSQL config not found at $PGCONF"
fi

if [ -f "$PGHBA" ]; then
    grep -v "^#" "$PGHBA" | grep -v "^$" | grep "0.0.0.0/0\|::/0" && \
        fail "pg_hba.conf allows connections from 0.0.0.0/0 or ::/0 (overly permissive)" || \
        pass "pg_hba.conf does not allow wildcard remote connections"
fi

section "Summary"
echo ""
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  WARN: $WARN"
echo ""
TOTAL=$((PASS + FAIL + WARN))
PCT=$((PASS * 100 / TOTAL))
echo "  Compliance: $PCT% ($PASS/$TOTAL controls passing)"
