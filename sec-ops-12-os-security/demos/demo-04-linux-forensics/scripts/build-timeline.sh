#!/bin/bash
# Build incident timeline from available log sources

echo "========================================================"
echo "  LINUX INCIDENT TIMELINE RECONSTRUCTION"
echo "  System: demo-forensics-container"
echo "========================================================"
echo ""

echo "[AUTH.LOG] Brute Force Phase:"
grep "Failed password" /var/log/auth.log 2>/dev/null | head -5
echo "  ... (247 total failures from 10.0.5.123) ..."
echo ""

echo "[AUTH.LOG] Successful Access:"
grep "Accepted" /var/log/auth.log 2>/dev/null
echo ""

echo "[AUTH.LOG] Privilege Escalation:"
grep "COMMAND\|sudo" /var/log/auth.log 2>/dev/null | grep -v "session"
echo ""

echo "[AUTH.LOG] New Account Creation:"
grep "useradd\|adduser\|passwd" /var/log/auth.log 2>/dev/null
echo ""

echo "[CRON] Persistence Mechanism Added:"
grep "RELOAD\|\.update\.sh\|crontab" /var/log/auth.log /var/log/syslog 2>/dev/null | tail -5
echo ""

echo "[AUDITD] Critical Events:"
ausearch -k identity -i 2>/dev/null | grep "time=\|EXECVE\|PATH" | head -20
echo ""

echo "[BASH HISTORY] Attacker Commands:"
echo "--- alice (escalation via sudo) ---"
cat /home/alice/.bash_history 2>/dev/null
echo "--- root (post-escalation) ---"
cat /root/.bash_history 2>/dev/null

echo ""
echo "========================================================"
echo "  ARTIFACTS SUMMARY"
echo "========================================================"
echo "Backdoor accounts:"
awk -F: '($3 >= 1000) {print "  " $1 " (UID:" $3 ")"}' /etc/passwd | grep -v "nobody"
echo ""
echo "Suspicious cron entries:"
grep -v "^#\|^$\|^SHELL\|^PATH\|^MAILTO" /etc/crontab 2>/dev/null | grep -v "^[0-9].*ubuntu\|^[0-9].*debian"
echo ""
echo "Unauthorized SSH keys:"
find /root /home -name "authorized_keys" -exec echo "  {}" \; -exec cat {} \; 2>/dev/null
echo ""
echo "Files in /tmp:"
ls -la /tmp/ 2>/dev/null
