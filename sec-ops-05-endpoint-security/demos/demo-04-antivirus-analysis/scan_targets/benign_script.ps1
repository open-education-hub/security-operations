# benign_script.ps1 — Clean administrative script (no malicious content)
# Used in Demo 04 as a true-negative control for AV and YARA scanning.
# ClamAV and YARA should produce NO alerts on this file.

Write-Host "System health check starting..." -ForegroundColor Cyan

# Check running services
$services = Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name, Status, StartType
Write-Host "Running services: $($services.Count)"

# Check disk space (simulated output for Linux container)
Write-Host "Disk check complete. All volumes within thresholds."

# Check event log (simulated)
Write-Host "No critical events in the last 24 hours."

Write-Host "Health check complete." -ForegroundColor Green
