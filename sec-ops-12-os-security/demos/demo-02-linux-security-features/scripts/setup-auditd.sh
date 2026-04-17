#!/bin/bash
# auditd Setup Script
# Configures auditd with a security-focused baseline ruleset,
# generates test events, and demonstrates how to query the audit log.

echo "========================================================"
echo "  auditd Configuration and Testing"
echo "========================================================"
echo ""

# -------------------------------------------------------
# Step 1: Start auditd
# -------------------------------------------------------
echo "[*] Starting auditd..."
if command -v auditd &>/dev/null; then
    # Try service first, fall back to direct invocation
    service auditd start 2>/dev/null || \
    auditd -b 8192 2>/dev/null || \
    echo "    NOTE: auditd may already be running or require host capabilities"
    sleep 1
else
    echo "    auditd not found — install with: apt-get install -y auditd"
    exit 1
fi

echo "[*] auditd status:"
auditctl -s 2>/dev/null | head -5
echo ""

# -------------------------------------------------------
# Step 2: Remove any existing rules and load baseline
# -------------------------------------------------------
echo "[*] Loading baseline audit rules..."
auditctl -D 2>/dev/null   # Delete all existing rules

# --- Identity-critical files ---
auditctl -w /etc/passwd       -p wa -k identity
auditctl -w /etc/shadow       -p wa -k identity
auditctl -w /etc/group        -p wa -k identity
auditctl -w /etc/gshadow      -p wa -k identity
auditctl -w /etc/sudoers      -p wa -k identity
auditctl -w /etc/sudoers.d/   -p wa -k identity
echo "    Rule added: identity (watch /etc/passwd, shadow, group, sudoers)"

# --- Privilege escalation commands ---
auditctl -a always,exit -F path=/usr/bin/sudo  -F perm=x -F auid>=1000 -k privileged-sudo
auditctl -a always,exit -F path=/usr/bin/su    -F perm=x -F auid>=1000 -k privileged-su
auditctl -a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -k privileged-newgrp
echo "    Rule added: privileged-sudo, privileged-su (track privilege escalation)"

# --- SSH authorized keys (persistence vector) ---
auditctl -w /root/.ssh/authorized_keys         -p wa -k ssh-keys 2>/dev/null || true
# Watch all home directories for authorized_keys changes
for home_dir in /home/*/; do
    if [ -d "$home_dir" ]; then
        mkdir -p "${home_dir}.ssh"
        auditctl -w "${home_dir}.ssh/authorized_keys" -p wa -k ssh-keys 2>/dev/null || true
    fi
done
echo "    Rule added: ssh-keys (watch authorized_keys files for modifications)"

# --- Cron modifications (persistence) ---
auditctl -w /etc/cron.d/      -p wa -k scheduled-jobs
auditctl -w /etc/crontab      -p wa -k scheduled-jobs
auditctl -w /var/spool/cron   -p wa -k scheduled-jobs
echo "    Rule added: scheduled-jobs (watch cron directories)"

# --- Sensitive data access ---
auditctl -w /root/             -p r  -k sensitive-data 2>/dev/null || true
echo "    Rule added: sensitive-data (read access to /root/)"

# -------------------------------------------------------
# Step 3: Verify rules loaded
# -------------------------------------------------------
echo ""
echo "[*] Loaded audit rules:"
auditctl -l
echo ""

# -------------------------------------------------------
# Step 4: Generate test events
# -------------------------------------------------------
echo "[*] Generating test audit events..."
echo ""

# Trigger identity event: write to /etc/group
echo "# audit-test-comment" >> /etc/group
sed -i '/# audit-test-comment/d' /etc/group
echo "    Generated: identity event (modified /etc/group)"

# Trigger privileged-sudo event
sudo -l > /dev/null 2>&1 || true
echo "    Generated: privileged-sudo event (sudo -l)"

# Touch crontab to trigger scheduled-jobs event
touch /etc/crontab
echo "    Generated: scheduled-jobs event (touched /etc/crontab)"

sleep 1   # Give auditd a moment to write

# -------------------------------------------------------
# Step 5: Query the audit log
# -------------------------------------------------------
echo ""
echo "[*] Querying audit log for generated events..."
echo ""

echo "--- Identity events (last 60 seconds) ---"
ausearch -k identity -ts recent -i 2>/dev/null | \
    grep -E "^type=|time=|comm=|name=" | head -20 || \
    echo "    (no events found yet — may need a moment)"

echo ""
echo "--- Scheduled-job events ---"
ausearch -k scheduled-jobs -ts recent -i 2>/dev/null | \
    grep -E "^type=|comm=|name=" | head -10 || \
    echo "    (no events found yet)"

echo ""
echo "--- Privilege escalation events (today) ---"
ausearch -k privileged-sudo -ts today -i 2>/dev/null | \
    grep -E "^type=|comm=|uid=" | head -20 || \
    echo "    (no events found)"

echo ""
echo "[*] auditd setup complete."
echo ""
echo "Useful commands for further exploration:"
echo "  ausearch -k identity -ts recent -i         # Recent identity events"
echo "  ausearch -k privileged-sudo -ts today -i   # Today's sudo events"
echo "  aureport --summary                         # Full summary report"
echo "  aureport --auth --summary                  # Authentication summary"
echo "  aureport --failed                          # Failed events"
echo "  auditctl -l                                # List active rules"
echo "  auditctl -D                                # Delete all rules (reset)"
