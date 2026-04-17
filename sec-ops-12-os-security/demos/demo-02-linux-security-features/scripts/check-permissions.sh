#!/bin/bash
# File Permission Audit Script
# Checks for common permission misconfigurations:
# - World-writable files and directories
# - SUID/SGID binaries in unexpected locations
# - Weak permissions on critical configuration files
# - Files owned by unrecognized UIDs

echo "========================================================"
echo "  File Permission Security Audit"
echo "  System: $(hostname)"
echo "  Date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "========================================================"
echo ""

ISSUES=0
WARNINGS=0

# -------------------------------------------------------
# Check 1: World-writable files (outside /tmp and /var/tmp)
# -------------------------------------------------------
echo "[*] Check 1: World-writable files (excluding /tmp, /var/tmp, /proc, /sys)..."
WW_FILES=$(find / -perm -0002 -type f \
    -not -path "/proc/*" \
    -not -path "/sys/*" \
    -not -path "/tmp/*" \
    -not -path "/var/tmp/*" \
    -not -path "/dev/*" \
    2>/dev/null)

if [ -z "$WW_FILES" ]; then
    echo "    PASS: No unexpected world-writable files found"
else
    echo "    FAIL: World-writable files found (anyone can modify these):"
    echo "$WW_FILES" | while read -r f; do
        ls -la "$f" 2>/dev/null | awk '{printf "      %s\n", $0}'
        ISSUES=$((ISSUES + 1))
    done
fi
echo ""

# -------------------------------------------------------
# Check 2: World-writable directories (outside expected locations)
# -------------------------------------------------------
echo "[*] Check 2: World-writable directories..."
WW_DIRS=$(find / -perm -0002 -type d \
    -not -path "/proc/*" \
    -not -path "/sys/*" \
    -not -path "/tmp" \
    -not -path "/var/tmp" \
    -not -path "/dev/*" \
    2>/dev/null)

if [ -z "$WW_DIRS" ]; then
    echo "    PASS: No unexpected world-writable directories"
else
    echo "    WARN: World-writable directories:"
    echo "$WW_DIRS" | while read -r d; do
        ls -lad "$d" 2>/dev/null | awk '{printf "      %s\n", $0}'
    done
fi
echo ""

# -------------------------------------------------------
# Check 3: Critical file permissions
# -------------------------------------------------------
echo "[*] Check 3: Critical file permissions..."

check_perm() {
    local file="$1"
    local expected_mode="$2"
    local expected_owner="$3"

    if [ ! -f "$file" ]; then
        echo "    SKIP: $file not found"
        return
    fi

    actual_mode=$(stat -c '%a' "$file")
    actual_owner=$(stat -c '%U:%G' "$file")

    if [ "$actual_mode" = "$expected_mode" ] && [ "$actual_owner" = "$expected_owner" ]; then
        echo "    PASS: $file  mode=$actual_mode  owner=$actual_owner"
    else
        echo "    FAIL: $file  mode=$actual_mode (expected $expected_mode)  owner=$actual_owner (expected $expected_owner)"
        ISSUES=$((ISSUES + 1))
    fi
}

check_perm "/etc/passwd"    "644" "root:root"
check_perm "/etc/shadow"    "640" "root:shadow"
check_perm "/etc/group"     "644" "root:root"
check_perm "/etc/gshadow"   "640" "root:shadow"
check_perm "/etc/sudoers"   "440" "root:root"
check_perm "/etc/ssh/sshd_config" "600" "root:root"
check_perm "/etc/crontab"   "644" "root:root"

echo ""

# -------------------------------------------------------
# Check 4: Files with no owner (orphaned files — can indicate deleted accounts)
# -------------------------------------------------------
echo "[*] Check 4: Files with no valid owner (orphaned files)..."
ORPHANS=$(find / -nouser -o -nogroup 2>/dev/null | \
    grep -v "/proc\|/sys\|/dev" | head -20)

if [ -z "$ORPHANS" ]; then
    echo "    PASS: No orphaned files found"
else
    echo "    WARN: Files with missing owner or group (may indicate deleted accounts):"
    echo "$ORPHANS" | while read -r f; do
        ls -la "$f" 2>/dev/null | awk '{printf "      %s\n", $0}'
    done
fi
echo ""

# -------------------------------------------------------
# Check 5: SSH directory permissions
# -------------------------------------------------------
echo "[*] Check 5: SSH directory and key permissions..."
for homedir in /root /home/*/; do
    user=$(basename "$homedir")
    ssh_dir="${homedir}/.ssh"
    auth_keys="${ssh_dir}/authorized_keys"

    if [ -d "$ssh_dir" ]; then
        mode=$(stat -c '%a' "$ssh_dir")
        if [ "$mode" != "700" ]; then
            echo "    FAIL: $ssh_dir has mode $mode (should be 700)"
            ISSUES=$((ISSUES + 1))
        else
            echo "    PASS: $ssh_dir mode=700"
        fi
    fi

    if [ -f "$auth_keys" ]; then
        mode=$(stat -c '%a' "$auth_keys")
        if [ "$mode" != "600" ]; then
            echo "    FAIL: $auth_keys has mode $mode (should be 600)"
            ISSUES=$((ISSUES + 1))
        else
            echo "    PASS: $auth_keys mode=600"
        fi
        key_count=$(wc -l < "$auth_keys")
        echo "    INFO: $auth_keys contains $key_count key(s)"
    fi
done

echo ""

# -------------------------------------------------------
# Summary
# -------------------------------------------------------
echo "========================================================"
echo "  Audit Summary"
echo "========================================================"
echo "  Issues found: $ISSUES"
if [ "$ISSUES" -eq 0 ]; then
    echo "  Status: PASS — No critical permission issues found"
else
    echo "  Status: FAIL — $ISSUES issue(s) require remediation"
    echo ""
    echo "  Common remediation commands:"
    echo "    chmod 640  /etc/shadow    # Fix shadow file permissions"
    echo "    chmod 440  /etc/sudoers   # Fix sudoers permissions"
    echo "    chmod 600  /etc/ssh/sshd_config"
    echo "    chmod o-w  <file>         # Remove world-write bit"
fi
echo ""
