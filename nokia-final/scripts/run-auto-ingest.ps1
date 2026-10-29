# Auto-ingest watcher launcher.
# Called by the Windows Scheduled Task at every user logon. Sets env vars,
# picks up the venv if present, redirects output to a rolling log, and keeps
# the watcher running until the user logs off or Ctrl-C is pressed manually.

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $scriptDir
Set-Location $root

# Warpgate paths (host-side).
$warpgateDataRoot = Join-Path $env:USERPROFILE "warpgate-local\data"
if (-not $env:WARPGATE_DB_PATH) {
    $env:WARPGATE_DB_PATH = Join-Path $warpgateDataRoot "db\db.sqlite3"
}
if (-not $env:WARPGATE_RECORDINGS_HOST_ROOT) {
    $env:WARPGATE_RECORDINGS_HOST_ROOT = Join-Path $warpgateDataRoot "recordings"
}
if (-not $env:WARPGATE_RECORDINGS_ROOT) {
    $env:WARPGATE_RECORDINGS_ROOT = "/data/recordings"
}
if (-not $env:AUTO_INGEST_LIMIT) { $env:AUTO_INGEST_LIMIT = "10000" }

# PostgreSQL settings are loaded from services\api\.env by the ingestion app.

# Pick a Python interpreter — prefer the project venv if present.
$venvPython = @(
    (Join-Path $root ".venv\Scripts\python.exe"),
    (Join-Path $root "services\api\.venv\Scripts\python.exe")
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $venvPython) {
    $venvPython = "python"
}

# Rolling log file (keeps last 5 runs).
$logDir = Join-Path $root ".tmp\auto-ingest-logs"
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }

$logFile = Join-Path $logDir "auto-ingest-$(Get-Date -Format 'yyyyMMdd').log"

# Rotate: keep only the 5 most recent daily log files.
Get-ChildItem -Path $logDir -Filter "auto-ingest-*.log" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip 5 |
    Remove-Item -Force -ErrorAction SilentlyContinue

"$(Get-Date -Format 'u') | run-auto-ingest.ps1 starting: python=$venvPython" | Out-File -FilePath $logFile -Append -Encoding utf8

$scriptPath = Join-Path $root "services\ingestion\auto_ingest.py"

# Use Start-Process with explicit stdout/stderr redirect for reliable logging.
$stdoutLog = Join-Path $logDir "stdout-$(Get-Date -Format 'yyyyMMdd').log"
$stderrLog = Join-Path $logDir "stderr-$(Get-Date -Format 'yyyyMMdd').log"

$proc = Start-Process -FilePath $venvPython `
    -ArgumentList @("`"$scriptPath`"", "--verbose") `
    -WorkingDirectory $root `
    -NoNewWindow `
    -PassThru `
    -RedirectStandardOutput $stdoutLog `
    -RedirectStandardError $stderrLog

"$(Get-Date -Format 'u') | watcher PID=$($proc.Id) - stdout=$stdoutLog stderr=$stderrLog" | Out-File -FilePath $logFile -Append -Encoding utf8

$proc.WaitForExit()

"$(Get-Date -Format 'u') | watcher exited with code $($proc.ExitCode)" | Out-File -FilePath $logFile -Append -Encoding utf8
