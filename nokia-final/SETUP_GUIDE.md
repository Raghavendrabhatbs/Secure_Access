# Nokia NBUC SSH Session Intelligence Platform — Setup Guide

This guide covers Secure Access SSH command inspection and session intelligence,
which share one FastAPI backend, one PostgreSQL database and one local Ollama
model:

1. **Warpgate-native SSH inspection** — inspects SSH commands in Warpgate
   sessions, terminates blocked sessions, and sends email alerts.
2. **AI Chatbot (Session Intelligence)** — answers questions about past SSH
   sessions from data stored in PostgreSQL.

> Commands are for **Windows PowerShell** unless a block says **WSL**.
> The reference setup is Windows 11 + Docker Desktop for data services + WSL2
> (Ubuntu), where the independently built Warpgate runs.

## Warpgate-native command inspection

The native integration lives in the Warpgate source repository; it does not require
changing SSH targets to point at the Secure Access SSH proxy. Once the modified
Warpgate binary is built and launched with `SECUREACCESS_AI_AGENT_URL` (or
`AI_AGENT_URL`) and the same `ALERT_SECRET` used by the API, all SSH sessions
served by that Warpgate process use the integration, including sessions for
existing and newly added targets. A Warpgate restart is required to activate a
new build or environment configuration.

The enforcement boundary differs by SSH request type: non-interactive SSH
`exec` requests are analyzed before forwarding to the target. Interactive shell
commands from both SSH clients and the Secure Access browser terminal are
reconstructed from the target's terminal echo. They are analyzed only after
submission and may already have started; a block then disconnects the target
and browser/SSH session but cannot guarantee the command was prevented. Do not
describe this interactive path as pre-execution blocking. SSH connections that
bypass Warpgate are not covered by this integration and need a separately
enforced proxy or destination-side control.

The native integration is separate from the optional SSH proxy setup described
later in this guide. Do not change Warpgate target routing to proxy ports just
to enable the native integration.

### Active session management

The administrator Sessions page obtains its live list through the FastAPI
backend, which queries Warpgate's `GET /@warpgate/admin/api/sessions` endpoint
with `active_only=true` and `logged_in_only=true`. Completed sessions remain
separate history. Selecting **Terminate** opens a confirmation dialog; the
backend first verifies the exact session UUID is active, requests
`POST /@warpgate/admin/api/sessions/{id}/close`, and rereads the session before
reporting a confirmed result. The request uses the signed Warpgate browser
session and Warpgate's own admin permissions; no admin token is sent to the
browser.

The backend requires the `admin` Secure Access role, and Warpgate must grant
that operator its session-view and session-termination permissions. It reads
`WARPGATE_URL` and optional `WARPGATE_CA_BUNDLE` from the API environment. A
manual termination email is off by default; enable it with
`ALERT_ON_MANUAL_SESSION_TERMINATION=true`.

### Configure and activate native inspection

The API must be reachable from WSL. Find the current Windows host gateway from
the WSL default route instead of saving a WSL IP that may change:

```bash
API_HOST="$(ip route show default | awk 'NR == 1 {print $3}')"
export SECUREACCESS_AI_AGENT_URL="http://${API_HOST}:8765"
read -rsp 'Secure Access ALERT_SECRET: ' ALERT_SECRET
printf '\n'
export ALERT_SECRET
```

Enter the existing `ALERT_SECRET` without displaying it. Configure these
variables in the environment used to launch Warpgate (service manager or
launcher) so they persist across restarts. Do not put secrets on a command line
or commit them.

Build the updated binary in the Warpgate repository from WSL:

```bash
cd /path/to/warpgate
cargo build -p warpgate
```

Then perform a controlled restart using the same configuration and launcher
used by the current independent WSL process. Keep the API URL and secret in
that process environment. The API's analysis endpoint queues security email
alerts for blocked commands and persistently blocks HIGH/CRITICAL usernames;
Warpgate checks that blocklist during later SSH authentication.

**Email setup:** the API reads `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`,
`SMTP_PASS`, and `ALERT_EMAIL` from the project environment. `ALERT_TO` remains
a backward-compatible recipient alias. The local project environment currently
does not define either recipient variable; add `ALERT_EMAIL` locally before
expecting email delivery. Never commit or paste the recipient or SMTP
credentials. The alert service reports missing configuration and SMTP errors
in API logs without exposing credential values.

To send a safe delivery test after configuration, run this from the project
root in PowerShell; it sends a LOW-severity test message and does not run a
remote command:

```powershell
services\api\.venv\Scripts\python.exe -c "from services.agent.email_alerter import send_test_email; raise SystemExit(0 if send_test_email() else 1)"
```

The admin **Sessions** page lists active Warpgate sessions and provides the
confirmed manual termination flow. Its result distinguishes confirmed,
already-ended, and unverified outcomes.

---

## Quick start

Assumes the one-time API and data-service setup is complete. Warpgate runs
independently in WSL and must be restarted only when deploying a new binary or
changing its environment.

```powershell
# 1. Start PostgreSQL if it is not already running
docker start nokia-postgres

# 2. Start Ollama and warm the model (skip if Ollama is already running)
ollama serve            # separate window; then:  ollama run llama3.1:8b "hi"

# 3. Start the API (command verdicts, alerts, live-session operations, chatbot)
cd services\api
$env:PYTHONPATH = "$((Resolve-Path ..\..).Path);$((Get-Location).Path)"
.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8765
```

---

## Architecture

```
  SSH client / Secure Access web terminal
              |
              v
   +-------------------------------+
   | Warpgate SSH server in WSL    |
   | native command guard          |
   +---------------+---------------+
                   | POST /ssh/analyze
                   | /security/block and /security/check
                   v
   +-------------------------------+
   | FastAPI backend (Windows)     |
   | policies, email, live sessions|
   +-----------+----------+--------+
               |          |
               v          v
        Ollama model   SMTP security alerts
      (when required)

  Manual session management:
  Secure Access UI -> authenticated FastAPI -> Warpgate admin API in WSL

  Optional direct-SSH proxy path is described separately below; it is not
  required for sessions already served by the native Warpgate integration.

  Chatbot path:  Web UI / CLI -> FastAPI (/chat/query) -> PostgreSQL + Ollama
```

How a command is judged:

1. **While typing** — the proxy tracks the line character by character. If it
   already matches a dangerous pattern (for example `rm -rf`, `shutdown`,
   `curl ... | sh`), the session is killed **before Enter**.
2. **On Enter** — the proxy checks the finished line locally, then asks
   `POST /ssh/analyze`. The API allows a short list of safe commands
   instantly, blocks known-dangerous patterns, and sends anything else to
   Ollama. If the API or Ollama is unreachable the command is **blocked**
   (fail closed).
3. **On a kill** — the proxy prints the kill message, closes the Warpgate
   session through its admin API, closes both SSH legs, and an alert email is
   sent.

---

## Optional: SSH proxy inspection for direct SSH clients

### 1.1 Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10/11 with WSL2 | Ubuntu distribution; ssh-mitm does not run on native Windows |
| Docker Desktop | Runs PostgreSQL and optional data services |
| Python 3.11+ on Windows | The API uses its own venv in `services/api/.venv` |
| Python 3 + pip in WSL | Ubuntu 24.04 ships Python 3.12 |
| [Ollama](https://ollama.com) for Windows | Local LLM runtime |
| A Gmail account with 2-step verification | For alert emails (App Password) |

### 1.2 Install Ollama and the model

Install Ollama from <https://ollama.com>, then:

```powershell
ollama pull llama3.1:8b
ollama list
```

### 1.3 Python dependencies

**API (Windows):**

```powershell
cd services\api
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m pip install python-dotenv
cd ..\..
```

**Proxy (WSL).** ssh-mitm only runs in WSL/Linux. There is no
`services/agent/requirements.txt`; the proxy's dependencies are `ssh-mitm`,
`pyte`, `requests` and `python-dotenv`. The root `requirements.txt` lists
`ssh-mitm` and `pyte`.

```bash
cd /mnt/c/SecureAccess/nokia-final
~/.venvs/nokia-proxy/bin/python -m pip install -r requirements.txt requests python-dotenv
```

Use the `~/.venvs/nokia-proxy` virtual environment to avoid modifying Ubuntu's
system Python packages.

### 1.4 Configure the environment

There are **two** `.env` files, and both matter:

| File | Read by | Contains |
|---|---|---|
| `.env` (project root) | the SSH proxy, and the API for `ALERT_SECRET` and SMTP | Warpgate, proxy, alert and SMTP settings |
| `services/api/.env` | the API's pydantic settings | database, Valkey, Ollama, Qdrant settings |

**Root `.env`:**

```dotenv
# Warpgate (runs independently in Ubuntu/WSL from C:\SecureAccess\warpgate)
WARPGATE_URL=https://localhost:8888
WARPGATE_TOKEN=<same protected token configured as WARPGATE_ADMIN_TOKEN in WSL Warpgate>
WARPGATE_TARGET_NAME=ssh-demo

# Proxy
PROXY_LISTEN_PORT=2224
PROXY_TARGET_HOST=127.0.0.1
PROXY_TARGET_PORT=22
AI_AGENT_URL=http://172.25.112.1:8765
AI_TIMEOUT_SECONDS=30.0

# Alerts
ALERT_SECRET=<long random string>
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=<your gmail address>
SMTP_PASS=<gmail app password>
ALERT_EMAIL=<recipient address>
```

**`services/api/.env`:**

```dotenv
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=nokia_ssh
POSTGRES_USER=nokia
POSTGRES_PASSWORD=<database password>
VALKEY_HOST=localhost
VALKEY_PORT=6379
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.1:8b
OLLAMA_TIMEOUT_SECONDS=45
BRAVE_SEARCH_API_KEY=<Brave Search API key>
APP_TIMEZONE=UTC
QDRANT_HOST=localhost
QDRANT_PORT=6333
```

Notes:

- Generate `ALERT_SECRET` with:
  `[Convert]::ToBase64String((1..32 | % { [byte](Get-Random -Max 256) })) -replace '[+/=]',''`
- The proxy and the API must use the **same** `ALERT_SECRET`. Keep it only in
  the root `.env`; the API loads that file explicitly.
- **Never commit `.env` files or paste their values into chat or tickets.**
  Both are git-ignored.
- `OLLAMA_HOST` and `OLLAMA_MODEL` go in `services/api/.env`, because that is
  the file the API's settings read.
- The saved `services/agent/anomaly_model.pkl` is an Isolation Forest used for
  session anomaly scoring; it is not a language model. The chatbot uses the
  configured local Ollama model for natural-language synthesis and never sends
  private session data to the public search provider.
- `BRAVE_SEARCH_API_KEY` is optional. When configured, current-affairs,
  current-weather, and upcoming-event questions use Brave Search results and
  return their source links. Without it, the assistant explicitly reports that
  live search is not configured rather than presenting stale model knowledge
  as current.
- `APP_TIMEZONE` controls relative-date interpretation and half-open daily
  query boundaries. Use a valid IANA timezone name.

### 1.5 Find the current Windows gateway IP (optional proxy)

For the optional proxy running in WSL, do not assume Windows `127.0.0.1` is
reachable from WSL. Resolve the current Windows host address from the default
route:

```bash
ip route | grep default | awk '{print $3}'
```
Use that address in `AI_AGENT_URL`. It can change after a reboot; resolve it
again if the proxy stops reaching the API. The native Warpgate integration
instead uses `SECUREACCESS_AI_AGENT_URL` in the Warpgate process environment;
see the activation section above.

### 1.5.1 Optional proxy: enable the Warpgate admin API token

The optional proxy and route audit use Warpgate's admin API to map sessions,
close a Warpgate session explicitly, and verify target routing. The independent
Warpgate process must be started with `--enable-admin-token` and its
`WARPGATE_ADMIN_TOKEN` environment variable set. Configure the same token as
`WARPGATE_TOKEN` in the project-root `.env`; keep it local and do not paste it
into chat. This change requires a controlled Warpgate restart using the same
launcher/service that currently starts the instance. Do not stop the live
process until you are ready for that restart.

For a manually launched instance, after stopping it cleanly through the
terminal or service that currently owns it, run this once in WSL. The token is
generated locally and is not printed:

```bash
cd /mnt/c/SecureAccess/nokia-final
token="$(openssl rand -hex 32)"
printf '\nWARPGATE_TOKEN=%s\n' "$token" >> .env
export WARPGATE_ADMIN_TOKEN="$token"
unset token
cd /mnt/c/SecureAccess/warpgate
./target/debug/warpgate run --enable-admin-token
```

Keep that Warpgate process running. Start the proxy supervisor in a second WSL
terminal. If `WARPGATE_TOKEN` is already in `.env`, do not append another
entry; instead set `WARPGATE_ADMIN_TOKEN` in the existing Warpgate launcher
environment to the existing token value.

### 1.6 Create a Gmail App Password

1. Google Account → **Security** → turn on **2-Step Verification**.
2. Google Account → **Security** → **App passwords** → create one.
3. Copy the 16-character password into `SMTP_PASS`. Spaces are tolerated by the
   SMTP login but remove them to be safe.

### 1.7 Start the services

**Data services:** Warpgate is not a Docker container in this setup; it runs
independently in WSL. Start only the containers actually used by your local
API configuration:

```powershell
docker start nokia-postgres
docker ps
```

**Ollama** (skip if already running; check with
`Invoke-RestMethod http://localhost:11434/api/tags`):

```powershell
ollama serve
ollama run llama3.1:8b "hi"      # warms the model; a cold model is slow
```

**API:**

```powershell
cd services\api
$env:PYTHONPATH = "$((Resolve-Path ..\..).Path);$((Get-Location).Path)"
.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8765
```

> Port 8765 is used because Windows can reserve 8000/8001. Run the API from
> `services/api` as shown; the module path is `app.main:app`.

**SSH proxy (WSL):**

```bash
cd /mnt/c/SecureAccess/nokia-final
~/.venvs/nokia-proxy/bin/python services/agent/run_ssh_proxies.py \
  --config services/agent/ssh_proxy_targets.json
```

Each proxy is a plain Python process, not an `ssh-mitm server` command. The
route supervisor starts one proxy process per entry in
`services/agent/ssh_proxy_targets.json`, setting its target name, destination
host/port and listener port. It reads the project-root `.env` before validating
that `AI_AGENT_URL`, `ALERT_SECRET`, and `WARPGATE_TOKEN` are present. On
start, each child logs its route.

### 1.8 Route Warpgate traffic to the proxy

Warpgate and the proxy both run in Ubuntu/WSL, so Warpgate connects directly to
`127.0.0.1:<proxy-listen-port>`; no Windows `netsh portproxy` is needed between
those two processes and no Docker port mapping is involved. Each SSH target
needs a dedicated proxy listener because
it may forward to a different SSH destination. Add one entry per target in
`services/agent/ssh_proxy_targets.json`, with a unique `listen_port`. This
runtime file is git-ignored and contains routing metadata, not credentials.

### 1.9 Point Warpgate at the proxy

For each SSH target, in the independently running Warpgate admin UI
(`https://localhost:8888/@warpgate/admin` from Windows; accept its
self-signed certificate):

1. Find the route in `ssh_proxy_targets.json`. The route `name` must match the
   Warpgate target name, and `listen_port` must be unique.
2. Set the Warpgate SSH target host to `127.0.0.1` and the port to that route's
   `listen_port`. Keep the target username and authentication
   configured for the real SSH destination.
3. Under **Roles**, retain or assign the intended Warpgate roles.
4. Save and trust the proxy host key if Warpgate prompts after the route change.

The manifest's `host` and `port` are the real SSH destination. The sample uses
`127.0.0.1:22`, the WSL SSH daemon; replace it with the actual destination for
each Warpgate target.

This routing also applies to browser sessions opened by the Secure Access
SSH Access page's **Connect** button: it creates a Warpgate web SSH session
for the selected target. This proxy route is needed only when using the
separate Python SSH proxy layer; the Warpgate-native inspection described
above also covers the browser terminal without changing the target destination.
Avoid enabling both inspection layers for the same traffic unless duplicate
analysis and alerts are intended.

### Provision every SSH target

To enroll all existing SSH targets, add one route-manifest entry for each
target, then point each Warpgate SSH target to its corresponding
`127.0.0.1:<listen_port>` proxy listener. Start or restart the supervisor
after changing the manifest. Do not leave any SSH target pointed directly at
its real destination.

For every future SSH target, follow the same provisioning process **before
granting access**: add its route with a unique listener port, configure the
Warpgate target to use that listener, start/restart the supervisor, and run
`audit_ssh_proxy_routes.py`. Require a passing audit before assigning any
Warpgate role. The Warpgate UI does not enforce this policy itself; restrict
target administration operationally so new SSH targets are created only
through this workflow.

### Inspect direct SSH connections (without Warpgate)

Direct SSH can use the same command inspection and alert path by configuring a
`direct` route. The proxy uses the SSH login name offered by the client for
security checks; a dangerous command closes the proxied SSH transport, sends
an alert, and applies the same persistent username block. Warpgate API tokens
are not needed for routes that are all `direct`.

For this WSL setup, a direct route to the currently configured SSH destination
can listen on port `2226` and forward to `172.25.117.183:22`. That destination
and listener port have been checked as reachable/free in the current WSL
environment. The local, git-ignored manifest has a `direct-wsl-test` entry.
The general route shape is:

```json
{
  "targets": [
    {
      "name": "direct-test-host",
      "mode": "direct",
      "host": "127.0.0.1",
      "port": 2225,
      "listen_port": 2226
    }
  ]
}
```

Set `AI_AGENT_URL` and keep the existing `ALERT_SECRET` in the project-root
`.env`. The configured manifest also contains the Warpgate route, so use
`--direct-only` to start this route without first configuring
`WARPGATE_TOKEN`:

```bash
cd /mnt/c/SecureAccess/nokia-final
~/.venvs/nokia-proxy/bin/python services/agent/run_ssh_proxies.py \
  --config services/agent/ssh_proxy_targets.json --direct-only
```

From WSL, connect to the routed destination using
`ssh -p 2226 <ssh-user>@127.0.0.1`. This tests direct SSH command inspection
without changing the SSH server. This only inspects connections clients make
to the proxy listener; it does **not** transparently capture clients still
connecting to the destination's original port 22.

To enforce coverage for a server's regular direct SSH endpoint, that server's
network must route inbound SSH through the proxy, and clients must be unable
to bypass it. The usual design is to move the real SSH daemon to a private or
loopback-only port, run the proxy on the server's public SSH endpoint, forward
the proxy to the private daemon port, and restrict firewall/security-group
rules so port 22 cannot be reached by another path. For a remote machine, put
the proxy at an enforced network gateway or deploy it on that machine; a proxy
running only on this WSL computer cannot intercept unrelated hosts' direct SSH
traffic. Plan a maintenance window and keep console/out-of-band access while
changing SSH ports or firewall rules. Do not lock out your SSH access.

Before changing production hosts, provide the host OS and whether it is local
WSL, a Windows host, or a remote Linux server, plus how clients reach it.
The SSH daemon/firewall steps differ by platform and network topology.

Changing a route affects new connections only. Drain/terminate active sessions
and have users reconnect after routing existing targets. Direct SSH is covered
only when clients connect through a configured Secure Access proxy route; any
connection path that bypasses the proxy remains uninspected.

### 1.10 Test

Connect through Warpgate with the login format `<warpgate-user>:<target>@host`:

```powershell
ssh -p 2222 admin:ssh-demo@127.0.0.1
```

(or use the Warpgate web terminal). Then:

| Test | Expected |
|---|---|
| `whoami`, `ls -la` | Run immediately (allowlisted) |
| Type `shutdown` slowly, **do not press Enter** | Red `[Nokia Session Kill]` message, session ends, Warpgate shows Disconnected |
| Type `rm -rf` slowly | Same |
| `rm -r build` | Allowed |
| `ls` then `rm -r -f /` pasted on a second line | Killed |
| An alert email | Arrives at `ALERT_EMAIL` with the Warpgate user, command and reason |

Use only harmless targets for destructive tests. A live `rm -rf /` should never
be run, because the proxy is a safety layer and not a sandbox.

### 1.11 Known limits

- Detection is heuristic plus a small local model (llama3.1:8b). It is a layered
  defence, not a guarantee; obfuscation (hex, `eval`, constructed strings) can
  evade the pattern layer, and the model is unreliable on it.
- The mid-typing check reads typed characters. Lines built by history recall or
  tab completion are read from the server's echo at Enter instead.
- Full-screen programs (vim, less) are not scanned while typing, except for
  `:!command` shell escapes. `tmux`, `screen` and `byobu` are blocked, because
  they would hide a shell.
- The API validates the Warpgate session cookie and application role on session,
  chat, and conversation-history endpoints. `/ssh/alert` separately requires
  `ALERT_SECRET`; `/ssh/analyze` and health endpoints are not user-authenticated.
- The SSH proxy maps a Warpgate session only when exactly one active SSH session
  matches the target route. If multiple sessions match, it refuses to guess the
  username/session ID; it still closes its own SSH channels and requests an
  alert for a blocked command.
  Keep the API on a trusted network and do not expose it to untrusted clients.
- The proxy and API run as ordinary processes and must be restarted manually
  after a reboot.

---

## Part 2 — AI Chatbot (Session Intelligence)

### 2.1 What runs

| Component | Where |
|---|---|
| PostgreSQL | Docker container `nokia-postgres`, host port 5433 (container port 5432), database `nokia_ssh` |
| FastAPI backend | The same API as Part 1 (`/chat/query`, `/sessions`, ...) |
| Product chat interface | Role-gated SecureAccess page at `/admin/ai-assistant` in `secure-access-ai` |
| CLI / prototype | `services/api/chatbot_cli.py` and the separate `services/web` preview |
| LLM | Ollama (`llama3.1:8b`) |

The project has two distinct model roles. The chatbot uses the configured Ollama
LLM for natural-language generation; exact database counts and session facts
come from backend queries. The SSH agent separately loads
`services/agent/anomaly_model.pkl`, a scikit-learn `IsolationForest` with eight
session features, through `services/agent/anomaly_detector.py`. The agent uses
it for anomaly scoring; it is not a text-generation model and is not replaced
by Ollama. The checked-in artifact reports scikit-learn 1.9.1 metadata while
the API requirements currently pin 1.8.0, so loading emits a compatibility
warning. The artifact was not retrained or overwritten; align the agent runtime
with its training version before relying on version-sensitive scores.

> The root `docker-compose.yml` and `Makefile` are currently **empty**, so
> `docker-compose up -d` does not start anything. The containers are started
> individually, as shown below. There are no `nokia-api` or frontend containers.

### 2.2 Prerequisites

Docker Desktop running, Python 3.11+, Ollama with `llama3.1:8b` pulled, and
Node.js 20.19+ for the SecureAccess frontend.

### 2.3 Start the database and verify it

```powershell
docker start nokia-postgres nokia-valkey
docker ps
docker exec nokia-postgres psql -U nokia -d nokia_ssh -c "\dt"
```

Expected tables: `alembic_version`, `conversations`, `conversation_messages`,
`incidents`, `session_commands`, `session_events`, `sessions`.

### 2.4 Create or update the schema

If tables are missing, apply the migrations (4 revisions in
`services/api/alembic/versions`):

```powershell
cd services\api
.venv\Scripts\python.exe -m alembic upgrade head
cd ..\agent
..\api\.venv\Scripts\python.exe create_incidents_table.py
```

The latest migration adds the `blocked_users` table used by the SSH proxy to
persist high-severity blocks and reject blocked Warpgate users before opening
their shell. Apply it before starting the updated API or proxy. Block-status
lookups fail closed if the API or database cannot verify the user's status.
The proxy resolves the Warpgate login against active SSH sessions for the
`WARPGATE_TARGET_NAME` configured in the root `.env` (default: `ssh-demo`).
See [the migration notes](services/api/migrations/README.md) for verification
and recovery guidance.

### 2.5 Load session data

Sessions come from Warpgate recordings and its database. Ingest them with:

```powershell
$env:WARPGATE_DB_PATH = "$env:USERPROFILE\warpgate-local\data\db\db.sqlite3"
$env:WARPGATE_RECORDINGS_ROOT = "/data/recordings"
$env:WARPGATE_RECORDINGS_HOST_ROOT = "$env:USERPROFILE\warpgate-local\data\recordings"
.\services\api\.venv\Scripts\python.exe services\ingestion\auto_ingest.py --once --limit 10000
```

The one-time import reads all recorded sessions and parses terminal object
files into PostgreSQL session-command rows. To ingest new and changing
recordings automatically, run `.\start-auto-ingest.cmd` and leave it running,
or install it as a scheduled task with
`.\scripts\install-auto-ingest-task.ps1`. The watcher checks both the
Warpgate SQLite database and recording object files. Other flags:
`--db-path`, `--recordings-root`, `--debounce`, `--poll-interval`, `--limit`,
`--verbose`. Test fixtures are seeded by
`services/api/tests/seed_test_fixtures.py`.

Confirm data is present:

```powershell
docker exec nokia-postgres psql -U nokia -d nokia_ssh -t -c "select count(*) from sessions"
```

### 2.6 Use the chatbot

**Command line** (starts Ollama if needed):

```powershell
.\start-chatbot.ps1
```

```powershell
# single question
services\api\.venv\Scripts\python.exe services\api\chatbot_cli.py --question "show me recent sessions"
```

**HTTP API** (the API from Part 1, port 8765, also serves the chatbot):

Session, chat, and history routes require the signed `warpgate-http-session`
cookie. The API validates it against the Warpgate `@warpgate/api/info`
endpoint configured by root `.env` `WARPGATE_URL`, and permits only `admin`,
`developer`, and `auditor_viewer` application roles. For a self-signed
Warpgate TLS certificate, set `WARPGATE_CA_BUNDLE` to a trusted certificate
bundle; verification remains enabled. Conversation histories are scoped to the
verified Warpgate username. Requests accept `question` or `message` up to
4,000 characters, plus optional `session_id` and `conversation_id`.

The assistant fetches session data when each question is asked; it does not use
a startup snapshot. SSH data comes from PostgreSQL and web recording metadata
comes from Warpgate. Generic session counts/lists include both sources, and new
sessions become searchable once the corresponding system has recorded them.
The PostgreSQL container and Warpgate must be running for combined answers.
The Groq assistant can summarize the PostgreSQL SSH archive and search or scan
all stored SSH commands for recorded risk-rule matches; specific session
questions retrieve that session's command rows. Its risk scan classifies
recorded command input, not arbitrary text found only in terminal output, and
the result should not be treated as a complete security verdict.

**SecureAccess product UI**:

```powershell
cd ..\secure-access-ai
npm run dev
```

Open the Vite URL (normally <http://localhost:5173>) and sign in through
SecureAccess. The assistant uses the same-origin `/ai-api` development proxy;
the Vite server uses localhost for Windows development and discovers the
Windows host gateway when running under WSL. Set `AI_API_TARGET` only when the
API is at a non-default address; it is consumed by Vite and is not embedded as
a frontend secret. Production hosting must provide an equivalent same-origin
reverse proxy to FastAPI. From Sessions, choose **Ask AI** to scope a question
to one session.

**Automated tests** (create the isolated database once; never substitute
`nokia_ssh`):

```powershell
docker exec nokia-postgres psql -U nokia -d postgres -c "CREATE DATABASE nokia_ssh_test"
cd services\api
$env:PYTHONPATH = "$((Resolve-Path ..\..).Path);$((Get-Location).Path)"
$env:POSTGRES_DB = "nokia_ssh_test"
.venv\Scripts\python.exe tests\seed_test_fixtures.py
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_assistant_auth.py" -v
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_warpgate_admin_client.py" -v
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_security_blocklist.py" -v
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_session_query_service_integration.py" -v
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_chatbot_query_integration.py" -v
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_web_session_query_service.py" -v
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_application_knowledge_service.py" -v
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_conversation_context.py" -v
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_session_query_pagination.py" -v
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_existing_anomaly_model.py" -v
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_ollama_timeline_grounding.py" -v
cd ..\..\..\secure-access-ai
node --test src\api\aiAssistant.test.mjs
npm run lint
npm run build
```

The fixture seeder is pinned to `nokia_ssh_test` and clears only those test
tables. It reads the configured PostgreSQL host, port, username, and password.

### 2.7 Session identity and count

The live database was inspected read-only: it contains 87 physical `sessions`
rows, 80 distinct non-null `session_id` values, and seven IDs represented by
both plain and composite keys. Current ingestion writes
`unique_id=session_id`; the composite rows are in the imported dataset but are
not emitted by that writer. Queries group by `coalesce(session_id, unique_id)`,
prefer canonical-row values, and merge non-null recording, command, and risk
metadata from the other representation. Analytics count logical IDs; stored
rows remain unchanged. The dump contains 87 rows, not 87 distinct sessions.

The chatbot supports SSH session counts, time ranges, details, command and
event evidence, recording metadata, and rule-based risk findings where the
PostgreSQL source provides them. Web recordings are separate: Warpgate stores
session/authentication identity in SQLite while rrweb stores recording
metadata and event JSON in separate files. The assistant retrieves authorized
Web metadata through Warpgate's authenticated `@warpgate/rrweb/api/sessions`
and `session-metadata/{id}` routes; the API also provides bounded
`/web-sessions` listing and `/web-sessions/{id}` detail routes. Web counts,
user/target/date filters, page visits, recording status, event counts, and
recording failures are available where captured. Raw rrweb event payloads are
not retrieved or analyzed by chatbot answers, and the Web metadata source has
no risk score; the assistant must not claim an attack or describe clicks or
page content that were not supplied. Ollama is optional for deterministic
counts/listings; summaries use the configured model with bounded metadata.
Combined session overviews query deduplicated SSH sessions in PostgreSQL and
authenticated Web metadata in Warpgate, applying date, user, target, protocol,
and recording filters before pagination. Results are paged (25 per protocol);
ask for the next page to continue. Date-only filters use `APP_TIMEZONE` and
half-open local-day bounds converted to UTC. Recorded activity after the
current instant is excluded from historical/current answers. SSH active status
requires a recorded start lifecycle event with no later end event; the Web
metadata API does not provide a reliable active-session indicator. This
deployment has no scheduled-session source, so the assistant will not report
future sessions as planned or confirmed.
Application architecture questions retrieve bounded excerpts from this setup
guide and the rrweb README before calling the same configured Ollama model;
ordinary SSH/Linux questions keep their existing general-knowledge path.
Missing telemetry is reported as unavailable rather than inferred. Warpgate
must be reachable by the API; identity checks time out after five seconds and
fail closed. Existing conversation histories without owner metadata are not
exposed.

### 2.8 Test questions

- "show me recent sessions"
- "were there any malicious commands today"
- "what did admin run in the last session"
- "what did admin run in the last session"
- "how many Web sessions are recorded?"
- "show Web sessions for alice yesterday"
- "explain the Secure Access architecture"

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `403 Forbidden` on `/ssh/alert` | `ALERT_SECRET` is missing or different between the proxy and the API. Both read the **root** `.env`; set it there and restart both. |
| Alert email not arriving | Check `SMTP_USER`, `SMTP_PASS` (valid Gmail App Password), and `ALERT_EMAIL` (or legacy `ALERT_TO`). A `200` from `/ssh/analyze` means the verdict endpoint responded, not that SMTP delivery succeeded; check API logs for missing recipient, SMTP authentication, or delivery errors. |
| `reboot` or `shutdown` is not inspected in the Secure Access browser terminal | Confirm the rebuilt Warpgate process has `SECUREACCESS_AI_AGENT_URL` and `ALERT_SECRET`, then restart it. Check the Warpgate log for `Shell command` and `Terminating web SSH session for blocked command`, and the API log for analysis/alert results. Interactive shell detection occurs after command submission and cannot promise pre-execution prevention. |
| User can reconnect after a HIGH/CRITICAL block | Check the API `/security/block` request and the Warpgate log for blocklist check errors. With inspection configured, Warpgate rejects later SSH authentication if blocklist lookup fails or the username is actively blocked. |
| Session termination is reported as unverified | Refresh the administrator Sessions page and verify the session in Warpgate. The backend reports confirmation only after rereading an ended timestamp. |
| Live sessions cannot be listed or terminated | Confirm FastAPI `WARPGATE_URL` reaches WSL Warpgate, TLS trusts its certificate through `WARPGATE_CA_BUNDLE` if needed, and the authenticated administrator has Warpgate session-view/termination permissions. |
| Everything is blocked | Ollama is not running or is cold and timed out, so the API fails closed. Start Ollama, warm the model, and confirm `OLLAMA_HOST` in `services/api/.env`. |
| Proxy cannot reach the API | `AI_AGENT_URL` must use the Windows gateway IP from `ip route`, not `localhost`. Confirm the API listens on `0.0.0.0:8765`. |
| `whoami` / `ls` blocked | The safe-command allowlist is in the API; restart the API after code changes and check Ollama is up. |
| The browser terminal remains Connected after a blocked command | Rebuild and restart Warpgate so the Web-SSH session manager uses the command guard and disconnect path. Check the Warpgate log for `Terminating web SSH session for blocked command`. For the separate Python SSH proxy, ensure it closes both SSH transports as well as channels (`_terminate` in `ssh_proxy.py`) and restart the proxy after code changes. |
| Alert email says user `unknown` | The proxy could not map the Warpgate session. Check `WARPGATE_URL` / `WARPGATE_TOKEN` and the proxy log line `Mapped proxy session ... (user ...)`. |
| `Connection refused (111)` in the proxy log | The proxy's real SSH destination is unreachable. Check the route's `host`/`port` and confirm SSH is listening there. |
| Warpgate host key mismatch | The proxy host key changed. Re-trust the proxy host key for the relevant target in the Warpgate UI. |
| Warpgate cannot connect to the proxy | Confirm the route supervisor is running and that the Warpgate SSH target points to `127.0.0.1:<listen_port>`. |
| API fails with import errors | Run it from `services/api` with `PYTHONPATH` set to the project root and `services/api`, using `app.main:app`. |
| `role "postgres" does not exist` | The database user is `nokia` and the database is `nokia_ssh`, not `postgres`. |
| Assistant returns HTTP 503 for database-backed or combined session questions | Check `http://127.0.0.1:8765/health/database`. If it is unhealthy, start Docker Desktop and the `nokia-postgres` container, then restart FastAPI. Web-only questions do not need PostgreSQL conversation history; SSH and combined SSH/web answers do need PostgreSQL. |
| Port 8000 / 8001 unavailable | Windows reserves them; use 8765. |

---

## Environment variables reference

| Variable | Description | Example | Used by |
|---|---|---|---|
| `WARPGATE_URL` | Warpgate base URL used by API identity checks, session management, and the optional proxy | `https://localhost:8888` | API, proxy |
| `WARPGATE_CA_BUNDLE` | Optional trusted CA bundle when the Warpgate certificate is not in the system trust store; verification stays enabled | `<trusted PEM path>` | API, proxy |
| `WARPGATE_TOKEN` | Warpgate admin API token (keep secret) | `<token>` | proxy |
| `WARPGATE_ADMIN_TOKEN` | Token enabled on the independent Warpgate process using `--enable-admin-token`; match `WARPGATE_TOKEN` | `<same token>` | Warpgate |
| `AI_AGENT_URL` | API URL reachable from WSL; use the current WSL default gateway for the optional proxy | `http://<current-host-gateway>:8765` | proxy |
| `SECUREACCESS_AI_AGENT_URL` | API URL used by native Warpgate inspection; alias `AI_AGENT_URL` is also accepted | `http://<current-host-gateway>:8765` | Warpgate |
| `PROXY_LISTEN_PORT` | Per-target proxy listener; set by route supervisor | `2224` | proxy |
| `PROXY_TARGET_HOST` | Per-target SSH destination; set by route supervisor | `127.0.0.1` | proxy |
| `PROXY_TARGET_PORT` | Per-target SSH destination port; set by route supervisor | `22` | proxy |
| `WARPGATE_TARGET_NAME` | Warpgate target name associated with this proxy process | `ssh-demo` | proxy |
| `AI_TIMEOUT_SECONDS` | How long the proxy waits for a verdict before blocking | `30.0` | proxy |
| `ALERT_SECRET` | Shared secret for SSH alerting and the persistent user blocklist | `<random string>` | Warpgate, proxy, API |
| `SMTP_HOST` / `SMTP_PORT` | Mail server | `smtp.gmail.com` / `587` | API (email alerter) |
| `SMTP_USER` | Sender account | `alerts@gmail.com` | API |
| `SMTP_PASS` | Gmail App Password | `<app password>` | API |
| `ALERT_EMAIL` | Alert recipient | `security@example.com` | API |
| `ALERT_TO` | Backward-compatible alias for `ALERT_EMAIL` | `<recipient address>` | API |
| `ALERT_ON_MANUAL_SESSION_TERMINATION` | Send an email when an administrator manually terminates a session | `true` (default off) | API |
| `OLLAMA_HOST` | Ollama URL | `http://localhost:11434` | API (`services/api/.env`) |
| `OLLAMA_MODEL` | Model name | `llama3.1:8b` | API (`services/api/.env`) |
| `OLLAMA_TIMEOUT_SECONDS` | Maximum wait for local Ollama generation | `45` | API (`services/api/.env`) |
| `BRAVE_SEARCH_API_KEY` | Optional key for live public-information search | `<Brave Search API key>` | API (`services/api/.env`) |
| `APP_TIMEZONE` | IANA timezone for relative dates and daily boundaries | `UTC` | API |
| `POSTGRES_HOST` / `POSTGRES_PORT` | Database address from the host | `localhost` / `5433` | API |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | Database credentials | `nokia_ssh` / `nokia` / `<password>` | API |
| `VALKEY_HOST` / `VALKEY_PORT` | Valkey (Redis) address | `localhost` / `6379` | API, agent |
| `QDRANT_HOST` / `QDRANT_PORT` | Qdrant address | `localhost` / `6333` | API |
| `WARPGATE_DB_PATH` | Warpgate SQLite database for ingestion | `C:/warpgate/data/db/db.sqlite3` | ingestion |
| `WARPGATE_RECORDINGS_ROOT` | Recordings directory for ingestion | `C:/warpgate/recordings` | ingestion |
| `VITE_API_BASE_URL` | API URL used by the web UI | `http://127.0.0.1:8765` | web UI |

---

## Other components

The repository also contains a real-time threat-detection agent
(`services/agent/main.py`, watching Warpgate recordings, with a three-layer
classifier, anomaly model and incident logging) and a scheduled auto-ingest
task. They are independent of the pre-execution kill described above and use
the same `.env` settings. Run the agent with:

```powershell
$env:PYTHONPATH = "."
.\.venv\Scripts\python.exe services\agent\main.py
```

Run the test suites with:

```powershell
$env:PYTHONPATH = "."
.\.venv\Scripts\python.exe -m pytest services\api\tests -q
.\.venv\Scripts\python.exe -m pytest services\ingestion\tests -q
```
