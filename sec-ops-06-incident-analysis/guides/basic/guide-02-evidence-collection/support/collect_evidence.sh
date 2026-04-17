#!/bin/bash
# =============================================================================
# Linux Evidence Collection Script
# Security Operations Course - Session 06: Incident Analysis
# Guide 02: Evidence Collection Procedures and Chain of Custody
#
# Purpose: Collect volatile and non-volatile evidence from a live Linux system
#          while maintaining chain of custody integrity.
#
# Usage:   sudo bash collect_evidence.sh [output_dir]
#          Default output: /mnt/usb/evidence/<hostname>-<timestamp>/
#
# IMPORTANT: Run as root. Mount a USB drive or network share at /mnt/usb first.
#            The evidence directory MUST be external to the compromised system.
#
# Chain of custody:
#   - All files are SHA-256 hashed immediately after collection
#   - A manifest file is created listing every artifact and its hash
#   - Collection metadata (who, when, how) is recorded in metadata.txt
# =============================================================================

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────
ANALYST_NAME="${ANALYST_NAME:-UNKNOWN_ANALYST}"
CASE_NUMBER="${CASE_NUMBER:-CASE-UNSET}"
OUTPUT_BASE="${1:-/mnt/usb/evidence}"
HOSTNAME="$(hostname -s)"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
EVIDENCE_DIR="${OUTPUT_BASE}/${HOSTNAME}-${TIMESTAMP}"

# ─── Color output ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*" >&2; }
section() { echo -e "\n${YELLOW}=== $* ===${NC}"; }

# ─── Pre-flight checks ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo bash $0)"
    exit 1
fi

if [[ ! -d "${OUTPUT_BASE}" ]]; then
    error "Output directory ${OUTPUT_BASE} does not exist."
    error "Mount your evidence drive first, or specify a different output path:"
    error "  sudo bash $0 /path/to/evidence/dir"
    exit 1
fi

# ─── Create evidence directory ────────────────────────────────────────────────
mkdir -p "${EVIDENCE_DIR}"
MANIFEST="${EVIDENCE_DIR}/MANIFEST.sha256"
METADATA="${EVIDENCE_DIR}/00-collection-metadata.txt"

info "Evidence directory: ${EVIDENCE_DIR}"

# ─── Helper: hash and record a file ───────────────────────────────────────────
hash_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        sha256sum "$file" >> "${MANIFEST}"
    fi
}

# ─── Collection metadata (Step 0) ─────────────────────────────────────────────
section "Step 0: Recording collection metadata"

cat > "${METADATA}" << EOF
EVIDENCE COLLECTION METADATA
=============================
Case Number:      ${CASE_NUMBER}
Analyst:          ${ANALYST_NAME}
System Hostname:  ${HOSTNAME}
Collection Start: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Hardware Clock:   $(hwclock --show 2>/dev/null || echo "unavailable")
Script Version:   collect_evidence.sh v1.0
OS:               $(uname -a)
Kernel:           $(uname -r)
Uptime:           $(uptime)

NTP Sync Status:
$(timedatectl 2>/dev/null || date -u)

Network Interfaces:
$(ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "unavailable")

EVIDENCE DIRECTORY: ${EVIDENCE_DIR}

NOTE: All timestamps in this directory are UTC.
      System clock offset vs. NTP is recorded above.
      Adjust event timestamps if clock skew is significant.
EOF

info "Metadata saved: ${METADATA}"

# ─── Step 1: System time reference ────────────────────────────────────────────
section "Step 1: System time reference"

{
    echo "=== System Time Reference ==="
    echo "Date (UTC):     $(date -u)"
    echo "Date (local):   $(date)"
    echo "Unix epoch:     $(date +%s)"
    echo ""
    echo "=== NTP Status ==="
    timedatectl 2>/dev/null || ntpdate -q pool.ntp.org 2>/dev/null || echo "NTP status unavailable"
} > "${EVIDENCE_DIR}/01-timestamp.txt"
hash_file "${EVIDENCE_DIR}/01-timestamp.txt"
info "Timestamp saved"

# ─── Step 2: Running processes ────────────────────────────────────────────────
section "Step 2: Running processes (VOLATILE)"

# Full process listing with hierarchy
ps auxf > "${EVIDENCE_DIR}/02-processes-tree.txt" 2>/dev/null || true
hash_file "${EVIDENCE_DIR}/02-processes-tree.txt"

# Detailed process info: PID, PPID, user, start time, command
ps -eo pid,ppid,user,lstart,stat,args --sort=ppid \
    > "${EVIDENCE_DIR}/02-processes-detail.txt" 2>/dev/null || true
hash_file "${EVIDENCE_DIR}/02-processes-detail.txt"

# Hidden processes: compare /proc with ps output
ls /proc | grep -E '^[0-9]+$' | sort -n \
    > "${EVIDENCE_DIR}/02-proc-pids.txt" 2>/dev/null || true
hash_file "${EVIDENCE_DIR}/02-proc-pids.txt"

info "Process listing saved (${EVIDENCE_DIR}/02-processes-*.txt)"

# ─── Step 3: Network state ────────────────────────────────────────────────────
section "Step 3: Network state (VOLATILE)"

# All network connections with PIDs
ss -antup > "${EVIDENCE_DIR}/03-network-connections.txt" 2>/dev/null || \
    netstat -antup > "${EVIDENCE_DIR}/03-network-connections.txt" 2>/dev/null || true
hash_file "${EVIDENCE_DIR}/03-network-connections.txt"

# IP addresses and interfaces
ip addr show > "${EVIDENCE_DIR}/03-ip-addresses.txt" 2>/dev/null || \
    ifconfig -a > "${EVIDENCE_DIR}/03-ip-addresses.txt" 2>/dev/null || true
hash_file "${EVIDENCE_DIR}/03-ip-addresses.txt"

# Routing table
ip route show > "${EVIDENCE_DIR}/03-routing-table.txt" 2>/dev/null || \
    route -n > "${EVIDENCE_DIR}/03-routing-table.txt" 2>/dev/null || true
hash_file "${EVIDENCE_DIR}/03-routing-table.txt"

# ARP cache (shows recently communicated hosts)
arp -a > "${EVIDENCE_DIR}/03-arp-cache.txt" 2>/dev/null || \
    ip neigh show > "${EVIDENCE_DIR}/03-arp-cache.txt" 2>/dev/null || true
hash_file "${EVIDENCE_DIR}/03-arp-cache.txt"

# Firewall rules
iptables -L -n -v 2>/dev/null > "${EVIDENCE_DIR}/03-iptables.txt" || true
hash_file "${EVIDENCE_DIR}/03-iptables.txt"

info "Network state saved (${EVIDENCE_DIR}/03-*.txt)"

# ─── Step 4: Logged-in users ──────────────────────────────────────────────────
section "Step 4: Logged-in users (VOLATILE)"

w > "${EVIDENCE_DIR}/04-logged-in-users.txt" 2>/dev/null || true
last -50 >> "${EVIDENCE_DIR}/04-logged-in-users.txt" 2>/dev/null || true
lastb -20 >> "${EVIDENCE_DIR}/04-logged-in-users.txt" 2>/dev/null || true
hash_file "${EVIDENCE_DIR}/04-logged-in-users.txt"

who -a > "${EVIDENCE_DIR}/04-who.txt" 2>/dev/null || true
hash_file "${EVIDENCE_DIR}/04-who.txt"

info "User sessions saved (${EVIDENCE_DIR}/04-*.txt)"

# ─── Step 5: Open files and handles ───────────────────────────────────────────
section "Step 5: Open files and sockets (VOLATILE)"

lsof 2>/dev/null > "${EVIDENCE_DIR}/05-open-files.txt" || true
hash_file "${EVIDENCE_DIR}/05-open-files.txt"

lsof -i 2>/dev/null > "${EVIDENCE_DIR}/05-network-files.txt" || true
hash_file "${EVIDENCE_DIR}/05-network-files.txt"

info "Open file handles saved (${EVIDENCE_DIR}/05-*.txt)"

# ─── Step 6: Kernel modules ───────────────────────────────────────────────────
section "Step 6: Kernel modules (rootkit check)"

lsmod > "${EVIDENCE_DIR}/06-kernel-modules.txt" 2>/dev/null || true
hash_file "${EVIDENCE_DIR}/06-kernel-modules.txt"

# Check for suspicious module names
if command -v modinfo &>/dev/null; then
    lsmod | tail -n +2 | awk '{print $1}' | while read -r mod; do
        modinfo "$mod" 2>/dev/null | head -3
    done > "${EVIDENCE_DIR}/06-module-details.txt" || true
    hash_file "${EVIDENCE_DIR}/06-module-details.txt"
fi

info "Kernel modules saved (${EVIDENCE_DIR}/06-*.txt)"

# ─── Step 7: Persistence mechanisms ──────────────────────────────────────────
section "Step 7: Persistence mechanisms"

{
    echo "=== /etc/crontab ==="
    cat /etc/crontab 2>/dev/null || echo "not found"

    echo ""
    echo "=== /etc/cron.d/ ==="
    ls -la /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null || echo "empty or not found"

    echo ""
    echo "=== /etc/cron.hourly/ ==="
    ls -la /etc/cron.hourly/ 2>/dev/null || echo "empty or not found"

    echo ""
    echo "=== /etc/cron.daily/ ==="
    ls -la /etc/cron.daily/ 2>/dev/null || echo "empty or not found"

    echo ""
    echo "=== /var/spool/cron/ ==="
    ls -la /var/spool/cron/ 2>/dev/null || echo "empty or not found"
    find /var/spool/cron/ -type f -exec cat {} \; 2>/dev/null || true

    echo ""
    echo "=== User crontabs ==="
    for user in $(cut -d: -f1 /etc/passwd); do
        crontab -u "$user" -l 2>/dev/null && echo "[user: $user]" || true
    done
} > "${EVIDENCE_DIR}/07-cron-persistence.txt"
hash_file "${EVIDENCE_DIR}/07-cron-persistence.txt"

{
    echo "=== /etc/systemd/system/ (non-standard services) ==="
    ls -la /etc/systemd/system/ 2>/dev/null || echo "not found"
    echo ""
    echo "=== Custom service unit files ==="
    find /etc/systemd/system/ -name "*.service" -newer /boot 2>/dev/null -exec cat {} \; || true

    echo ""
    echo "=== /usr/lib/systemd/system/ (recently modified) ==="
    find /usr/lib/systemd/system/ -name "*.service" -newer /boot 2>/dev/null | head -20 || true
} > "${EVIDENCE_DIR}/07-systemd-persistence.txt"
hash_file "${EVIDENCE_DIR}/07-systemd-persistence.txt"

{
    echo "=== ~/.ssh/ directories ==="
    find /home /root -name "authorized_keys" -exec ls -la {} \; 2>/dev/null
    echo ""
    echo "=== authorized_keys contents ==="
    find /home /root -name "authorized_keys" -exec echo "--- {} ---" \; \
        -exec cat {} \; 2>/dev/null || true
} > "${EVIDENCE_DIR}/07-ssh-keys.txt"
hash_file "${EVIDENCE_DIR}/07-ssh-keys.txt"

{
    echo "=== /etc/passwd (users and shells) ==="
    cat /etc/passwd

    echo ""
    echo "=== Users with login shells ==="
    grep -v '/nologin\|/false\|/sync' /etc/passwd | grep -v '^#' || true

    echo ""
    echo "=== Recently created users (last 30 days) ==="
    find /home -maxdepth 1 -type d -newer /etc/passwd -exec ls -la {} \; 2>/dev/null || true

    echo ""
    echo "=== Sudoers ==="
    cat /etc/sudoers 2>/dev/null || echo "permission denied"
    ls /etc/sudoers.d/ 2>/dev/null && cat /etc/sudoers.d/* 2>/dev/null || true
} > "${EVIDENCE_DIR}/07-accounts.txt"
hash_file "${EVIDENCE_DIR}/07-accounts.txt"

info "Persistence artifacts saved (${EVIDENCE_DIR}/07-*.txt)"

# ─── Step 8: Log files ────────────────────────────────────────────────────────
section "Step 8: Log files"

mkdir -p "${EVIDENCE_DIR}/logs"

# Copy key log files
for logfile in /var/log/auth.log /var/log/secure /var/log/syslog \
               /var/log/messages /var/log/kern.log /var/log/dpkg.log \
               /var/log/apt/history.log /var/log/audit/audit.log; do
    if [[ -f "$logfile" ]]; then
        cp "$logfile" "${EVIDENCE_DIR}/logs/$(basename $logfile)" 2>/dev/null || true
        info "  Copied: $logfile"
    fi
done

# Bash history for all users
for home_dir in /root /home/*; do
    if [[ -f "${home_dir}/.bash_history" ]]; then
        user=$(basename "$home_dir")
        cp "${home_dir}/.bash_history" \
           "${EVIDENCE_DIR}/logs/bash_history-${user}" 2>/dev/null || true
        info "  Copied: ${home_dir}/.bash_history"
    fi
done

# Hash all collected logs
for f in "${EVIDENCE_DIR}/logs/"*; do
    [[ -f "$f" ]] && sha256sum "$f" >> "${MANIFEST}"
done

info "Log files saved (${EVIDENCE_DIR}/logs/)"

# ─── Step 9: Memory acquisition note ─────────────────────────────────────────
section "Step 9: Memory acquisition (manual step required)"

cat > "${EVIDENCE_DIR}/09-memory-acquisition-note.txt" << 'EOF'
MEMORY ACQUISITION - MANUAL STEP REQUIRED
==========================================
Memory cannot be acquired automatically by this script.
Full memory acquisition requires a kernel module (LiME) or userspace tool (avml).

Options:
1. AVML (recommended for most Linux systems):
   wget https://github.com/microsoft/avml/releases/latest/download/avml
   chmod +x avml
   sudo ./avml "${EVIDENCE_DIR}/memory.lime"
   sha256sum "${EVIDENCE_DIR}/memory.lime" >> "${EVIDENCE_DIR}/MANIFEST.sha256"

2. LiME kernel module:
   insmod lime.ko "path=${EVIDENCE_DIR}/memory.lime format=lime"
   sha256sum "${EVIDENCE_DIR}/memory.lime" >> "${EVIDENCE_DIR}/MANIFEST.sha256"

3. If neither is available, document in this file that memory was NOT acquired
   and the reason why. This is an important gap to note in the chain of custody.

Memory acquisition time: Must be completed BEFORE any other disk writes.
Recommended memory acquisition window: NOW (before continuing).

EOF
hash_file "${EVIDENCE_DIR}/09-memory-acquisition-note.txt"
warn "Memory acquisition requires manual step - see ${EVIDENCE_DIR}/09-memory-acquisition-note.txt"

# ─── Step 10: Final manifest and verification ─────────────────────────────────
section "Step 10: Finalizing manifest"

# Append collection end time to metadata
{
    echo ""
    echo "Collection End: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Total files collected: $(find "${EVIDENCE_DIR}" -type f | wc -l)"
    echo "Total size: $(du -sh "${EVIDENCE_DIR}" | cut -f1)"
} >> "${METADATA}"

# Final hash of manifest itself
sha256sum "${METADATA}" >> "${MANIFEST}"

info "Manifest written: ${MANIFEST}"
info "Verify integrity with:"
info "  sha256sum -c ${MANIFEST}"

# ─── Summary ──────────────────────────────────────────────────────────────────
section "Collection Complete"
echo ""
echo "Evidence directory: ${EVIDENCE_DIR}"
echo "Total files:        $(find "${EVIDENCE_DIR}" -type f | wc -l)"
echo "Total size:         $(du -sh "${EVIDENCE_DIR}" | cut -f1)"
echo ""
echo "NEXT STEPS:"
echo "  1. Acquire memory (see 09-memory-acquisition-note.txt)"
echo "  2. Complete Chain of Custody form with:"
echo "     - Collection time: ${TIMESTAMP}"
echo "     - Analyst: ${ANALYST_NAME}"
echo "     - Case: ${CASE_NUMBER}"
echo "     - Location: $(pwd)"
echo "  3. Verify manifest: sha256sum -c ${MANIFEST}"
echo "  4. Transfer evidence to secure storage immediately"
echo ""
