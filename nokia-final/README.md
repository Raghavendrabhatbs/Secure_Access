Nokia SSH Intelligence Assistant
================================

The assistant answers SSH/Linux questions with the configured local Ollama
model, retrieves authorized SSH and web-session evidence, and can answer
current-events or upcoming-events questions from a configured live search
provider. Current-information answers include links to the retrieved sources;
they are not available until `BRAVE_SEARCH_API_KEY` is configured for the API.

Start the interactive chatbot from the project root:

	$env:PYTHONPATH="."
	.\.venv\Scripts\python.exe services/api/chatbot_cli.py

Ask a single question:

	.\.venv\Scripts\python.exe services/api/chatbot_cli.py --question "What does ls do?"

Resume a saved conversation:

	.\.venv\Scripts\python.exe services/api/chatbot_cli.py --conversation-id <conversation-id>

The interactive CLI prints the conversation ID. Keep it to resume the same
context later. Type `quit` or `exit` to leave.

Real-time ingestion (auto-ingest watcher)
-----------------------------------------

`services/ingestion/auto_ingest.py` keeps PostgreSQL in sync with Warpgate
without manual reruns. It watches the Warpgate SQLite database and the
recordings directory, including changes to an active terminal object file;
whenever either changes it debounces briefly and then runs the ingestion
pipeline in process. The default 10,000-session limit covers the full current
archive, and updates are upserted so newly completed sessions and commands are
available to the assistant.

On Windows with Warpgate running in WSL, start the watcher with
`.\start-auto-ingest.cmd`. It uses the local Warpgate data directory and loads
PostgreSQL settings from `services\api\.env`. To run it manually:

	$env:WARPGATE_DB_PATH = "$env:USERPROFILE\warpgate-local\data\db\db.sqlite3"
	$env:WARPGATE_RECORDINGS_ROOT = "/data/recordings"
	$env:WARPGATE_RECORDINGS_HOST_ROOT = "$env:USERPROFILE\warpgate-local\data\recordings"

Run a one-time import of the existing sessions and terminal recordings:

	.\services\api\.venv\Scripts\python.exe services\ingestion\auto_ingest.py --once --limit 10000

For continuous updates, leave `.\start-auto-ingest.cmd` running while using
Warpgate, or install the scheduled task with
`.\scripts\install-auto-ingest-task.ps1`.

Date and time questions use UTC by default. Set `APP_TIMEZONE` in `.env` to a
valid IANA timezone such as `Asia/Kolkata` or `America/New_York` when you want
`today` and hour-window questions interpreted in local time.

Handy flags:

- `--db-path` / `--recordings-root` override the env vars.
- `--debounce 1` wait N seconds after the last change before ingesting
	(default 1s).
- `--poll-interval 5` force polling instead of OS file events. Use this on
  network mounts or WSL bridges where inotify does not fire.
- `--limit 200` how many recent Warpgate sessions to consider per cycle.
- `--once` run a single ingestion cycle and exit (great for CI / testing).
- `--verbose` enable debug logging.

The watcher runs an initial ingestion on startup so new PostgreSQL databases
are seeded immediately, then keeps up with new sessions as they arrive.
