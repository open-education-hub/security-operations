#!/bin/bash
# sysmon_simulator.sh
# Simulates suspicious activity inside a Linux container,
# generating Sysmon-format events that would fire on a real Windows host.
# For educational demonstration only.

set -e
LOG_FILE="/var/log/sysmon_events.xml"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")

log_event() {
    echo "$1" >> "$LOG_FILE"
}

echo "<?xml version='1.0' encoding='UTF-8'?>" > "$LOG_FILE"
echo "<Events>" >> "$LOG_FILE"

echo "[*] Simulating attack scenario on Linux (mimicking Windows Sysmon events)"
echo "[*] Output: $LOG_FILE"
echo ""

echo "[STAGE 1] Initial Access — Office document opened"
log_event "<Event><System><EventID>1</EventID><TimeCreated SystemTime='${TIMESTAMP}'/><Computer>WORKSTATION01.corp.local</Computer></System><EventData><Data Name='ProcessId'>3120</Data><Data Name='Image'>C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data><Data Name='CommandLine'>\"WINWORD.EXE\" /n \"C:\Users\jdoe\Downloads\invoice.docm\"</Data><Data Name='ParentImage'>C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE</Data><Data Name='User'>CORP\jdoe</Data><Data Name='Hashes'>MD5=A1B2C3D4,SHA256=ABCDEF1234</Data></EventData></Event>"
sleep 1

echo "[STAGE 2] Execution — PowerShell spawned by Word with encoded command"
log_event "<Event><System><EventID>1</EventID><TimeCreated SystemTime='${TIMESTAMP}'/><Computer>WORKSTATION01.corp.local</Computer></System><EventData><Data Name='ProcessId'>4592</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='CommandLine'>powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdA==</Data><Data Name='ParentImage'>C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data><Data Name='User'>CORP\jdoe</Data><Data Name='CurrentDirectory'>C:\Users\jdoe\AppData\Local\Temp\</Data></EventData></Event>"
sleep 1

echo "[STAGE 3] C2 — PowerShell DNS query to suspicious domain"
log_event "<Event><System><EventID>22</EventID><TimeCreated SystemTime='${TIMESTAMP}'/><Computer>WORKSTATION01.corp.local</Computer></System><EventData><Data Name='ProcessId'>4592</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='QueryName'>update.microsoft-cdn-delivery.com</Data><Data Name='QueryResults'>type: 5 ::185.234.219.47</Data></EventData></Event>"
sleep 1

echo "[STAGE 3] C2 — PowerShell network connection to 185.234.219.47:443"
log_event "<Event><System><EventID>3</EventID><TimeCreated SystemTime='${TIMESTAMP}'/><Computer>WORKSTATION01.corp.local</Computer></System><EventData><Data Name='ProcessId'>4592</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='DestinationIp'>185.234.219.47</Data><Data Name='DestinationPort'>443</Data><Data Name='DestinationHostname'>update.microsoft-cdn-delivery.com</Data><Data Name='Initiated'>true</Data><Data Name='User'>CORP\jdoe</Data></EventData></Event>"
sleep 1

echo "[STAGE 4] Payload — Executable dropped to Temp"
log_event "<Event><System><EventID>11</EventID><TimeCreated SystemTime='${TIMESTAMP}'/><Computer>WORKSTATION01.corp.local</Computer></System><EventData><Data Name='ProcessId'>4592</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='TargetFilename'>C:\Users\jdoe\AppData\Local\Temp\WinUpdate.exe</Data><Data Name='CreationUtcTime'>2024-03-15 14:20:22.345</Data><Data Name='Hashes'>MD5=DEADBEEF,SHA256=CAFEBABE</Data></EventData></Event>"
sleep 1

echo "[STAGE 5] Persistence — Registry Run key set"
log_event "<Event><System><EventID>13</EventID><TimeCreated SystemTime='${TIMESTAMP}'/><Computer>WORKSTATION01.corp.local</Computer></System><EventData><Data Name='EventType'>SetValue</Data><Data Name='ProcessId'>5891</Data><Data Name='Image'>C:\Users\jdoe\AppData\Local\Temp\WinUpdate.exe</Data><Data Name='TargetObject'>HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper</Data><Data Name='Details'>C:\Users\jdoe\AppData\Roaming\Microsoft\wuhelper.exe</Data></EventData></Event>"
sleep 1

echo "[STAGE 6] Credential Access — LSASS memory access"
log_event "<Event><System><EventID>10</EventID><TimeCreated SystemTime='${TIMESTAMP}'/><Computer>WORKSTATION01.corp.local</Computer></System><EventData><Data Name='SourceProcessId'>5891</Data><Data Name='SourceImage'>C:\Users\jdoe\AppData\Local\Temp\WinUpdate.exe</Data><Data Name='TargetProcessId'>648</Data><Data Name='TargetImage'>C:\Windows\System32\lsass.exe</Data><Data Name='GrantedAccess'>0x1FFFFF</Data></EventData></Event>"
sleep 1

echo "[STAGE 7] Injection — CreateRemoteThread into explorer.exe"
log_event "<Event><System><EventID>8</EventID><TimeCreated SystemTime='${TIMESTAMP}'/><Computer>WORKSTATION01.corp.local</Computer></System><EventData><Data Name='SourceProcessId'>5891</Data><Data Name='SourceImage'>C:\Users\jdoe\AppData\Local\Temp\WinUpdate.exe</Data><Data Name='TargetProcessId'>1234</Data><Data Name='TargetImage'>C:\Windows\System32\explorer.exe</Data><Data Name='NewThreadId'>6789</Data><Data Name='StartAddress'>0x7FFE12340000</Data></EventData></Event>"

echo "</Events>" >> "$LOG_FILE"

echo ""
echo "[+] Simulation complete. Events written to $LOG_FILE"
echo "[+] Run: python3 parse_sysmon.py --file $LOG_FILE --detect-suspicious"
