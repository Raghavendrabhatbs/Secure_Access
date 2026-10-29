# Registers a Windows Scheduled Task that starts the auto-ingest watcher
# at every user logon. Does NOT need administrator privileges.
#
# Usage:
#     powershell -ExecutionPolicy Bypass -File .\scripts\install-auto-ingest-task.ps1
#
# To remove the task later:
#     powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-auto-ingest-task.ps1

$ErrorActionPreference = "Stop"

$taskName = "Nokia-SSH-AutoIngest"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$runner = Join-Path $scriptDir "run-auto-ingest.ps1"

if (-not (Test-Path $runner)) {
    throw "Runner not found: $runner"
}

$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Removing existing scheduled task: $taskName"
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$runner`""

$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Days 30)

$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Nokia SSH AI Assistant - real-time Warpgate ingestion watcher." | Out-Null

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  Scheduled task installed: $taskName" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "The watcher will now start automatically at every logon."
Write-Host ""
Write-Host "To start it right now without waiting for the next logon:"
Write-Host "    Start-ScheduledTask -TaskName $taskName" -ForegroundColor Cyan
Write-Host ""
Write-Host "To check activity, tail the log file at:"
Write-Host "    .tmp\auto-ingest-logs\auto-ingest-<yyyymmdd>.log" -ForegroundColor Cyan
Write-Host ""
Write-Host "To uninstall the task later:"
Write-Host "    powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-auto-ingest-task.ps1" -ForegroundColor Cyan
