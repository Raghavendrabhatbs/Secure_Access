@echo off
setlocal

REM Nokia SSH AI Chatbot launcher for CMD (Command Prompt)
cd /d "%~dp0"

set "PYTHONPATH=%CD%;%CD%\services\api;%CD%\services\ingestion"
set "WARPGATE_DB_PATH=%USERPROFILE%\warpgate-local\data\db\db.sqlite3"
set "WARPGATE_RECORDINGS_ROOT=/data/recordings"
set "WARPGATE_RECORDINGS_HOST_ROOT=%USERPROFILE%\warpgate-local\data\recordings"
set "AUTO_INGEST_LIMIT=10000"

if exist "%CD%\.venv\Scripts\python.exe" (
    set "PYTHON=%CD%\.venv\Scripts\python.exe"
) else if exist "%CD%\services\api\.venv\Scripts\python.exe" (
    set "PYTHON=%CD%\services\api\.venv\Scripts\python.exe"
) else (
    echo ERROR: Python virtual environment not found.
    echo Run: python -m venv .venv
    pause
    exit /b 1
)

echo ========================================================
echo        NOKIA SSH SECURITY AI ASSISTANT
echo ========================================================
echo Using Python: %PYTHON%
echo.

echo Starting real-time Warpgate ingestion watcher...
start "Nokia SSH auto-ingest" /min "%PYTHON%" services\ingestion\auto_ingest.py --debounce 1
echo Auto-ingest watcher started. New sessions should appear within a few seconds.
echo.

curl -s http://localhost:11434/api/tags >nul 2>&1
if %ERRORLEVEL%==0 (
    echo Ollama: connected on http://localhost:11434
) else (
    echo Ollama: not running. Starting ollama serve...
    start "" /B ollama serve
    timeout /t 3 /nobreak >nul
)

echo.
"%PYTHON%" services\api\chatbot_cli.py %*

endlocal
