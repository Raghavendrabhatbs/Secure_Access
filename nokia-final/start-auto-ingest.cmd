@echo off
setlocal

REM Nokia SSH AI Chatbot - real-time Warpgate ingestion watcher.
REM Keep this window open in the background whenever you use Warpgate so that
REM every new SSH session gets ingested into PostgreSQL within a few seconds
REM and the chatbot can answer questions about it immediately.

cd /d "%~dp0"

set "PYTHONPATH=%CD%;%CD%\services\api;%CD%\services\ingestion"
set "WARPGATE_DB_PATH=%USERPROFILE%\warpgate-local\data\db\db.sqlite3"
set "WARPGATE_RECORDINGS_ROOT=/data/recordings"
set "WARPGATE_RECORDINGS_HOST_ROOT=%USERPROFILE%\warpgate-local\data\recordings"
set "AUTO_INGEST_LIMIT=10000"

if exist "%CD%\services\api\.venv\Scripts\python.exe" (
    set "PYTHON=%CD%\services\api\.venv\Scripts\python.exe"
) else if exist "%CD%\.venv\Scripts\python.exe" (
    set "PYTHON=%CD%\.venv\Scripts\python.exe"
) else (
    echo ERROR: Python virtual environment not found.
    echo Run: python -m venv .venv ^&^& .venv\Scripts\pip install -r services/ingestion/requirements.txt
    pause
    exit /b 1
)

echo ========================================================
echo   NOKIA SSH - REAL-TIME WARPGATE INGESTION WATCHER
echo ========================================================
echo Using Python: %PYTHON%
echo.
echo The watcher will detect new Warpgate sessions and ingest
echo them into PostgreSQL automatically. Keep this window open
echo while you use Warpgate.
echo.
echo Press Ctrl+C to stop.
echo.

"%PYTHON%" services\ingestion\auto_ingest.py --verbose %*

endlocal
