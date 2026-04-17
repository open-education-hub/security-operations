#!/usr/bin/env bash
# collect-artifacts.sh — Forensic artifact collection for OS Forensics Guide
# Run inside the Docker container to collect evidence

set -u
OUTDIR="/evidence/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
echo "[*] Collecting forensic artifacts to $OUTDIR"

# Running processes
ps auxf > "$OUTDIR/processes.txt" 2>/dev/null || true
echo "[+] processes.txt"

# Network connections
ss -tulpn > "$OUTDIR/network_connections.txt" 2>/dev/null || true
echo "[+] network_connections.txt"

# Open files
lsof > "$OUTDIR/open_files.txt" 2>/dev/null || true
echo "[+] open_files.txt"

# Crontabs
crontab -l > "$OUTDIR/crontab_current_user.txt" 2>/dev/null || true
cat /etc/cron* /var/spool/cron/crontabs/* > "$OUTDIR/crontabs_all.txt" 2>/dev/null || true
echo "[+] crontabs"

# User accounts
cat /etc/passwd > "$OUTDIR/passwd.txt"
cat /etc/group > "$OUTDIR/group.txt"
# Show accounts with UID 0
awk -F: '$3 == 0 {print}' /etc/passwd > "$OUTDIR/uid0_accounts.txt"
echo "[+] user accounts ($(wc -l < "$OUTDIR/uid0_accounts.txt") UID-0 accounts)"

# Recently modified files (last 24h)
find / -newer /tmp -not -path "*/proc/*" -not -path "*/sys/*" -type f 2>/dev/null \
  | head -100 > "$OUTDIR/recently_modified.txt"
echo "[+] recently modified files"

# SUID/SGID binaries
find / -perm /6000 -type f 2>/dev/null > "$OUTDIR/suid_sgid.txt"
echo "[+] SUID/SGID binaries ($(wc -l < "$OUTDIR/suid_sgid.txt") found)"

# Hash the evidence
sha256sum "$OUTDIR"/* > "$OUTDIR/manifest.sha256"
echo "[+] manifest.sha256"

echo ""
echo "Collection complete: $OUTDIR"
ls -lh "$OUTDIR"
