# Nokia SSH AI Chatbot launcher (always uses latest code)
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$env:PYTHONPATH = "$ProjectRoot;$ProjectRoot\services\api"

# Ensure Ollama is reachable before starting the chatbot
try {
    $null = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 5
    Write-Host "Ollama: connected on http://localhost:11434"
} catch {
    Write-Host "Ollama: starting service..."
    Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    try {
        $null = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 10
        Write-Host "Ollama: connected"
    } catch {
        Write-Host "Ollama: still not reachable. Chatbot will use rule-based answers only."
    }
}

$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    $Python = Join-Path $ProjectRoot "services\api\.venv\Scripts\python.exe"
}

Write-Host "Using Python: $Python"
& $Python services/api/chatbot_cli.py @args
