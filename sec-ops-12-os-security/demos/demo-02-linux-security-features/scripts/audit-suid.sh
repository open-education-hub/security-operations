#!/bin/bash
# Audit SUID/SGID Binaries Script
# Scans the system for SUID/SGID binaries and classifies them

echo "========================================================"
echo "  SUID/SGID Binary Audit"
echo "  System: $(hostname)"
echo "  Date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "========================================================"
echo ""

# Known-legitimate SUID binaries on Debian/Ubuntu systems
KNOWN_SUID=(
    "/usr/bin/passwd"
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/newgrp"
    "/usr/bin/chfn"
    "/usr/bin/chsh"
    "/usr/bin/gpasswd"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/pkexec"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    "/usr/lib/policykit-1/polkit-agent-helper-1"
    "/usr/sbin/pppd"
    "/bin/mount"
    "/bin/umount"
    "/bin/su"
    "/bin/ping"
)

echo "[*] Scanning for SUID binaries (files with setuid bit set)..."
echo ""

SUID_FOUND=0
SUSPICIOUS_COUNT=0

while IFS= read -r binary; do
    SUID_FOUND=$((SUID_FOUND + 1))
    IS_KNOWN=0

    for known in "${KNOWN_SUID[@]}"; do
        if [ "$binary" = "$known" ]; then
            IS_KNOWN=1
            break
        fi
    done

    if [ "$IS_KNOWN" -eq 1 ]; then
        echo "  [EXPECTED]  $(ls -la "$binary" 2>/dev/null)"
    else
        echo "  [REVIEW!]   $(ls -la "$binary" 2>/dev/null)  <-- NOT in expected list"
        SUSPICIOUS_COUNT=$((SUSPICIOUS_COUNT + 1))
    fi
done < <(find / -perm -4000 -type f 2>/dev/null | sort)

echo ""
echo "--- SUID Summary ---"
echo "  Total SUID binaries found: $SUID_FOUND"
echo "  Known/expected:            $((SUID_FOUND - SUSPICIOUS_COUNT))"
echo "  Requires review:           $SUSPICIOUS_COUNT"

if [ "$SUSPICIOUS_COUNT" -gt 0 ]; then
    echo ""
    echo "  [ACTION REQUIRED] Investigate unexpected SUID binaries."
    echo "  For each: verify it is needed, check owner, check if on GTFOBins."
    echo "  GTFOBins reference: https://gtfobins.github.io/"
fi

echo ""
echo "[*] Scanning for SGID binaries (files with setgid bit set)..."
echo ""
find / -perm -2000 -type f 2>/dev/null | sort | while read -r binary; do
    echo "  [SGID] $(ls -la "$binary" 2>/dev/null)"
done

echo ""
echo "[*] Audit complete."
