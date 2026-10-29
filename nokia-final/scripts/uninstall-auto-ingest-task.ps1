# Removes the auto-ingest Scheduled Task.
#
# Usage:
#     powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-auto-ingest-task.ps1

$ErrorActionPreference = "Stop"

$taskName = "Nokia-SSH-AutoIngest"
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if (-not $existing) {
    Write-Host "No scheduled task named '$taskName' is installed. Nothing to do."
    exit 0
}

# Stop it first (if running) so removal is clean.
try {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
} catch {
    # Ignored — task may not be running.
}

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
Write-Host "Scheduled task '$taskName' removed." -ForegroundColor Green
