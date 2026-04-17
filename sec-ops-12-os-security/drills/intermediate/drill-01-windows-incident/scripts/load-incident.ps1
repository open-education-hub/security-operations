# Intermediate Drill 01 — Windows Incident Response
# Load this script inside the container: . /drill/scripts/load-incident.ps1

function Show-DrillIntro {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  INTERMEDIATE DRILL 01: Windows Incident Response"           -ForegroundColor Cyan
    Write-Host "  Host: WKS-FINANCE-07  |  Incident Date: 2024-01-15"         -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "SCENARIO:" -ForegroundColor Yellow
    Write-Host "  At 14:32 UTC, Defender flagged credential dumping on this"
    Write-Host "  workstation. 8 minutes later, svc_backup made a network"
    Write-Host "  logon to FS-CORP-01 (file server)."
    Write-Host ""
    Write-Host "EVIDENCE SOURCES:" -ForegroundColor Yellow
    Write-Host "  /drill/logs/Security.evtx.json    - Windows Security events"
    Write-Host "  /drill/logs/Sysmon.evtx.json       - Sysmon events"
    Write-Host "  /drill/logs/PowerShell.evtx.json   - PS script block logs"
    Write-Host "  /drill/artifacts/prefetch/         - Prefetch data"
    Write-Host "  /drill/artifacts/registry/         - Registry exports"
    Write-Host "  /drill/artifacts/netstat.txt       - Network connections"
    Write-Host "  /drill/artifacts/processes.txt     - Process list"
    Write-Host "  /drill/artifacts/mft_timeline.csv  - File system timeline"
    Write-Host ""
    Write-Host "TASKS: 6 tasks (see drill.md for details)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Run 'Get-DrillHelp' for quick command reference." -ForegroundColor DarkGray
}

function Get-DrillHelp {
    Write-Host ""
    Write-Host "=== Quick Command Reference ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Load events:" -ForegroundColor Yellow
    Write-Host '  $events  = Get-Content /drill/logs/Security.evtx.json | ConvertFrom-Json'
    Write-Host '  $sysmon  = Get-Content /drill/logs/Sysmon.evtx.json   | ConvertFrom-Json'
    Write-Host '  $ps      = Get-Content /drill/logs/PowerShell.evtx.json | ConvertFrom-Json'
    Write-Host ""
    Write-Host "Filter by EventID:" -ForegroundColor Yellow
    Write-Host '  $events | Where-Object { $_.EventID -eq 4688 } | Format-Table'
    Write-Host ""
    Write-Host "Filter by user:" -ForegroundColor Yellow
    Write-Host '  $events | Where-Object { $_.SubjectUserName -eq "jdavis" }'
    Write-Host ""
    Write-Host "Decode base64:" -ForegroundColor Yellow
    Write-Host "  [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<b64string>'))"
    Write-Host ""
    Write-Host "Timeline helper: Invoke-DrillTimeline" -ForegroundColor Green
    Write-Host "Report helper:   Invoke-DrillReport" -ForegroundColor Green
}

function Invoke-DrillTimeline {
    Write-Host ""
    Write-Host "=== Attack Timeline ===" -ForegroundColor Cyan
    Write-Host ""

    $events  = Get-Content /drill/logs/Security.evtx.json   | ConvertFrom-Json
    $sysmon  = Get-Content /drill/logs/Sysmon.evtx.json     | ConvertFrom-Json
    $ps      = Get-Content /drill/logs/PowerShell.evtx.json | ConvertFrom-Json

    $timeline = @()

    foreach ($e in $events) {
        $detail = switch ($e.EventID) {
            4688 { "Process Creation: $($e.NewProcessName)" }
            4624 { "Logon (Type $($e.LogonType)): $($e.TargetUserName) from $($e.IpAddress)" }
            4648 { "Explicit Logon: $($e.SubjectUserName) → $($e.TargetUserName) @ $($e.TargetServerName)" }
            7045 { "New Service: $($e.ServiceName) - $($e.ImagePath)" }
            4698 { "Scheduled Task Created: $($e.TaskName)" }
            1102 { "Security Log Cleared by $($e.SubjectUserName)" }
            default { "EventID $($e.EventID)" }
        }
        $timeline += [PSCustomObject]@{
            Time   = $e.TimeCreated
            Source = "Security"
            EID    = $e.EventID
            Detail = $detail
        }
    }

    foreach ($s in $sysmon) {
        $detail = switch ($s.EventID) {
            1  { "Process: $($s.Image) | Parent: $($s.ParentImage)" }
            3  { "Network: $($s.Image) → $($s.DestinationIp):$($s.DestinationPort)" }
            10 { "Process Access: $($s.SourceImage) → $($s.TargetImage) [0x$($s.GrantedAccess)]" }
            11 { "File Created: $($s.TargetFilename) by $($s.Image)" }
            default { "Sysmon EventID $($s.EventID)" }
        }
        $timeline += [PSCustomObject]@{
            Time   = $s.TimeCreated
            Source = "Sysmon"
            EID    = $s.EventID
            Detail = $detail
        }
    }

    foreach ($p in $ps) {
        $snippet = if ($p.ScriptBlockText.Length -gt 80) { $p.ScriptBlockText.Substring(0,80) + "..." } else { $p.ScriptBlockText }
        $timeline += [PSCustomObject]@{
            Time   = $p.TimeCreated
            Source = "PowerShell"
            EID    = $p.EventID
            Detail = "ScriptBlock: $snippet"
        }
    }

    $timeline | Sort-Object Time | Format-Table Time, Source, EID, Detail -Wrap
}

function Invoke-DrillReport {
    Write-Host ""
    Write-Host "=== Incident Report Summary ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "INCIDENT: Credential Dumping + Lateral Movement" -ForegroundColor Yellow
    Write-Host "DATE: 2024-01-15  |  HOST: WKS-FINANCE-07"
    Write-Host ""
    Write-Host "--- Indicators of Compromise ---" -ForegroundColor Yellow
    Write-Host "Files:"
    Write-Host "  C:\Users\jdavis\Documents\Q4_Financial_Report_FINAL.docm  (malicious macro doc)"
    Write-Host "  C:\Users\jdavis\AppData\Local\Temp\stage1.ps1             (downloader)"
    Write-Host "  C:\Users\jdavis\AppData\Local\Temp\beacon.bin             (implant)"
    Write-Host "  C:\Users\jdavis\AppData\Local\Temp\svc.dmp                (LSASS dump)"
    Write-Host "  C:\Windows\Temp\svchost32.exe                             (malware service binary)"
    Write-Host "  C:\Users\jdavis\AppData\Roaming\svchost.exe               (persistence payload)"
    Write-Host ""
    Write-Host "Network:"
    Write-Host "  192.168.1.100:80   (C2 — stage1 download)"
    Write-Host "  192.168.1.100:4443 (C2 — beacon callback)"
    Write-Host "  10.10.10.50:445    (FS-CORP-01 — lateral movement)"
    Write-Host ""
    Write-Host "Registry:"
    Write-Host "  HKCU\...\Run\WindowsDefenderUpdate  → svchost.exe (user persistence)"
    Write-Host "  HKLM\...\Run\WindowsUpdate          → svchost32.exe (system persistence)"
    Write-Host ""
    Write-Host "Services / Tasks:"
    Write-Host "  Service: WinUpdateSvc → C:\Windows\Temp\svchost32.exe"
    Write-Host "  Task: \Microsoft\Windows\MicrosoftEdgeUpdater"
    Write-Host ""
    Write-Host "--- Compromised Accounts ---" -ForegroundColor Yellow
    Write-Host "  jdavis   (Finance Analyst — initial victim)"
    Write-Host "  svc_backup (service account — credentials stolen from LSASS dump)"
    Write-Host ""
    Write-Host "--- Immediate Containment ---" -ForegroundColor Yellow
    Write-Host "  1. Isolate WKS-FINANCE-07 from network"
    Write-Host "  2. Reset passwords for jdavis and svc_backup"
    Write-Host "  3. Disable svc_backup account pending review"
    Write-Host "  4. Block 192.168.1.100 at perimeter firewall"
    Write-Host "  5. Preserve forensic image before remediation"
}

Write-Host "Drill helpers loaded. Run 'Show-DrillIntro' to begin." -ForegroundColor Green
