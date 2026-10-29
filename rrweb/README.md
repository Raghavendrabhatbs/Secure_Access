# rrweb + Warpgate integration

The Warpgate HTTP proxy, rrweb proxy, and rrweb server must use the same
`RRWEB_SIGNING_SECRET`. If the variable is not set, each component reads or
creates the same persistent secret file:

```text
$XDG_CONFIG_HOME/secureaccess/rrweb-signing-secret
```

When `XDG_CONFIG_HOME` is unset, this defaults to
`$HOME/.config/secureaccess/rrweb-signing-secret`. The file is generated on
first use with 32 random bytes and owner-only permissions. When Warpgate is
started with `sudo`, it uses the invoking user's home and creates the secret
with that user's ownership, so rrweb services launched as that user can read
the same key. Set
`RRWEB_SIGNING_SECRET_FILE` to use a different shared file, or set
`RRWEB_SIGNING_SECRET` explicitly in every process. Run all three components
inside the same WSL distro/account (or configure the same file path for each)
so they resolve the same secret. Do not commit the generated secret.

The rrweb server opens Warpgate's SQLite database read-only. It can discover
standard Linux locations only when exactly one candidate database exists. If
multiple candidates are present, startup fails until `WARPGATE_DATABASE_PATH`
is set to the absolute path of the database used by the active Warpgate server.
This avoids silently reading a stale database that can return plausible but
incomplete session, audit, or recording results. Check the startup log's
`Connected to Warpgate database` path against Warpgate's active configuration.

Keep Warpgate's SQLite database on the WSL Linux filesystem, not under `/mnt/c`;
SQLite WAL mode can fail with disk I/O errors on Windows-mounted filesystems.
Run Warpgate as the Linux account that owns its data directory; launching it
with `sudo` can leave root-owned SQLite files and cause session database I/O
errors when it is later run as your regular user. If the active Warpgate
configuration uses a Windows-mounted data directory, point rrweb to that exact
database explicitly instead of relying on path discovery.

## Recording persistence

Warpgate SQLite stores Warpgate users, roles, target configuration and grants,
and session/authentication data used by the rrweb backend for identity and RBAC
checks. The rrweb backend does **not** store event payloads in SQLite:

- Event arrays are JSON files at `rrweb/server/recordings/<sessionId>.json`.
- Recording metadata is stored separately at
  `rrweb/server/metadata/<sessionId>.json`.
- `<sessionId>` is the canonical `session-...` ID; the backend maps it to both
  files and validates it before accessing them.
- The recordings list scans metadata files, checks whether the matching event
  file exists, and filters the result using the authenticated Warpgate user's
  current recording permissions. Metadata-only sessions remain visible so
  starting and failed recording attempts can be diagnosed.

An entry in Warpgate SQLite alone does not represent a replay file. If metadata
or event JSON is missing or invalid, the list may omit the recording or replay
will show an error. Preserve both directories when backing up recordings; do
not delete or edit these files while the rrweb service is running.

## Recording continuity and navigation

Warpgate signs a recording-session ID into each short-lived rrweb token and
refreshes the token only after rechecking access to the selected HTTP target.
The recorder keeps that ID across page loads, records SPA/page visits, retries
queued event batches, and sends idempotency IDs so a retry is not stored twice.
Sensitive query parameters are redacted from page-visit metadata.

Cross-target links and redirects are routed through Warpgate only when the
destination origin matches an HTTP target authorized for the current user.
Other destinations are blocked. Ticket sessions remain bound to their ticket
target. The standalone rrweb proxy does not fetch arbitrary URLs; use a
Warpgate-configured HTTP target to browse a site.

For an HTTP target configured with a `www.` hostname, navigation to the exact
bare domain is also allowed when the scheme and effective port match. Other
subdomains are not implicitly authorized: configure a separate HTTP target and
grant access to it if users need to navigate there. Redirects and upstream-host
overrides follow the same rule, so a target for `www.example.com` cannot be
used to reach an unassigned sibling such as `admin.example.com`.

## Same-origin delivery and configuration

The browser loads the recorder and calls the recording API through
`/@warpgate/rrweb` on the authenticated Warpgate origin. Warpgate forwards only
the recorder asset and the required recording API routes to the rrweb service.
The service remains bound to `127.0.0.1:3000`; do not expose that port to remote
clients. Writes still require a short-lived recording bearer token, and
recording reads still require a Warpgate session and pass the backend's RBAC
checks. The Secure Access AI frontend uses the same route; its Vite development
server proxies that path to `https://localhost:8888`.

Warpgate's rrweb upstream is configured server-side with `RRWEB_SERVER_URL`.
It defaults to `http://127.0.0.1:3000` and accepts only an HTTP(S) origin, not a
path or embedded credentials. Use HTTPS with a trusted certificate if the
rrweb service is on another host.

The rrweb service verifies viewer cookies against `WARPGATE_API_URL`, which
defaults to `https://localhost:8888`. TLS verification is enabled by default.
Set `WARPGATE_TLS_CA_FILE` to the trusted CA certificate when Warpgate uses a
private CA. For local development with a self-signed certificate only, set
`WARPGATE_INSECURE_TLS=true`; this option is rejected for non-loopback hosts.

Recording tokens are issued only after Warpgate authorizes the authenticated
session for the requested HTTP target. The rrweb backend validates the token's
signature, expiry, authentication type, target, and recording-session binding
for each write; it does not duplicate Warpgate's role/target authorization
against a separately configured SQLite database. It does recheck the current
application role so Auditor/Viewer write access is denied immediately. Both
user and target-scoped ticket tokens are accepted because Warpgate has
authorized their target before signing them. Tokens expire after five minutes
and must be refreshed through Warpgate, so a changed or revoked grant takes
effect on the next token refresh (within five minutes). The database is also
used for recording-list and replay visibility checks. Secure Access
application roles are stored separately from Warpgate target-access roles in
the `secure_access_user_roles` table added by Warpgate migration 80. Users without
an explicit application-role row retain the Developer default; existing
target grants are not changed. Admin is derived from the complete native
Warpgate admin permission set, not from an access-role name. Developers can
view their own recordings only while retaining access to every recorded
target. Auditor/Viewer users can read all recordings across users and targets,
but cannot start, upload, heartbeat, stop, or report failures for recordings.
These checks use the current role on each request, including
for previously issued recording tokens.

The recorder sends a token-authenticated `POST /api/sessions/:sessionId/heartbeat`
every 30 seconds while a browser recording is active. The backend reports
`starting` before the first event batch, `recording` after events arrive,
`stopped` after an explicit stop, and `failed` when a reportable failure occurs
or a persisted active session misses its heartbeat for more than 90 seconds.
Older metadata without lifecycle state is reported as `unknown`, not assumed
to have failed. It records
bounded, deduplicated failure diagnostics through
`POST /api/sessions/:sessionId/failures`; diagnostics contain a fixed stage,
HTTP status when available, and a generic message rather than arbitrary client
error text. A successful event upload resolves the current failure.
`GET /api/sessions` includes status, event count, replay availability, duration,
storage bytes, and the latest failure summary. Storage bytes are the metadata
and event JSON file sizes visible to the authenticated requester.
The read-only `GET /api/warpgate/sessions` route applies the same current
target-grant checks: Admins can list all sessions, Developers see their own
sessions on currently assigned targets, and Auditor/Viewer users can see
sessions across targets.

## Secure Access universal audit log

Secure Access Audit Logs combines Warpgate's server-generated log entries with
Secure Access application activity. The rrweb service persists Secure Access
events in a separate SQLite database at
`rrweb/server/metadata/secure-access-audit.sqlite3`; set
`SECURE_ACCESS_AUDIT_DB_PATH` to override the path. Back up this database with
the other audit data.

Event submissions require an authenticated Warpgate session. The service
verifies the session and records the verified username and server timestamp,
not identity or time values supplied by the browser. Audit-log reads require
an authenticated Admin or Auditor/Viewer. Admins and Auditor/Viewer users can
read the full feed across users and targets. Developers cannot read audit logs.
Application events include
page navigation and UI control/form activity, plus explicit access and replay
actions. Passwords, tokens, and entered field values are not recorded. These
Secure Access UI events are client-reported activity; Warpgate's own log
entries remain the authoritative server-side record of gateway operations.

The Warpgate rrweb proxy explicitly allows the `heartbeat` and `failures` POST
routes in addition to session start, event upload, and stop. These paths remain
bound to a validated `session-...` ID and require the same short-lived recording
token as the other write routes.

`WARPGATE_DATABASE_PATH` should point to the exact SQLite database used by the
running Warpgate instance. Set it explicitly when starting the rrweb service,
especially if both the current and legacy candidate database paths exist.
Database fallback candidates are not a substitute for confirming the active
Warpgate database. Keep that database and its WAL files on the WSL Linux
filesystem, not under `/mnt/c`.

`RRWEB_ALLOWED_ORIGINS` is only needed for an explicitly direct browser-to-
backend development setup. The supported recorder and replay paths use the
same-origin Warpgate proxy and do not require CORS. The default direct-access
allowlist is limited to `http://localhost:5173`; do not add wildcard origins.

## WSL startup

Build the updated Warpgate executable and recorder bundle:

```bash
wsl -d ubuntu
cd /mnt/c/SecureAccess/warpgate
cargo build -p warpgate
```

From PowerShell, the rrweb recorder bundle and Secure Access AI frontend can be
built with:

```powershell
npm run build --prefix C:\SecureAccess\rrweb\client
npm run build --prefix C:\SecureAccess\secure-access-ai
```

Run the focused checks from PowerShell with:

```powershell
npm test --prefix C:\SecureAccess\rrweb\server
npm test --prefix C:\SecureAccess\rrweb\client
```

Run the Warpgate HTTP crate tests in WSL:

```bash
cd /mnt/c/SecureAccess/warpgate
cargo test -p warpgate-protocol-http
```

### Restart the local stack

Use separate terminals. In the terminals currently running Warpgate and rrweb,
press `Ctrl+C` to stop each process cleanly. Do not delete the SQLite database
or the `rrweb/server/recordings` and `rrweb/server/metadata` directories.

Start Warpgate first, using the same config and Linux account that own the
current database. For the setup that uses `/etc/warpgate.yaml` and previously
ran Warpgate with `sudo`, run in WSL:

```bash
cd /mnt/c/SecureAccess/warpgate
cargo build -p warpgate
sudo ./target/debug/warpgate --config /etc/warpgate.yaml --skip-securing-files run
```

`--skip-securing-files` skips file-mode tightening that can fail on `/mnt/c`;
it does not make an unreadable config or database accessible. If this command
reports a permission error, stop and confirm the configured database path and
its owner rather than changing permissions recursively or creating a new DB.

In a second WSL terminal, start rrweb as the Linux account that can read the
active SQLite database. The current local Warpgate instance uses
`/mnt/c/Users/rbhat/warpgate-local/data/db/db.sqlite3`; the similarly named
database at `/home/rbhat/warpgate/data/db/db.sqlite3` is stale for this setup.
Set the path to the active database explicitly:

```bash
cd /mnt/c/SecureAccess/rrweb/server
export WARPGATE_DATABASE_PATH="/mnt/c/Users/rbhat/warpgate-local/data/db/db.sqlite3"
export WARPGATE_API_URL="https://localhost:8888"
export WARPGATE_INSECURE_TLS=true  # local self-signed certificate only
node server.js
```

`WARPGATE_INSECURE_TLS=true` is only for local loopback development with a
self-signed certificate. Omit it when Warpgate has a certificate trusted by
Node.js. The rrweb service reads the shared signing secret from the same WSL
user's persistent config by default.

In PowerShell, start or restart the Secure Access AI development UI:

```powershell
npm run dev --prefix C:\SecureAccess\secure-access-ai -- --host 127.0.0.1
```

If running the frontend from WSL instead, first stop the old Vite process with
`Ctrl+C`, then run:

```bash
cd /mnt/c/SecureAccess/secure-access-ai
npm run dev -- --host 127.0.0.1
```

Run that command from the `secure-access-ai` directory; the workspace root and
`rrweb` directories do not contain the frontend `package.json`. Do not pass a
Windows-style `C:\...` prefix to npm running inside WSL.

The rrweb recorder bundle is generated by the client build above. Rebuild it
after recorder source changes, then restart the rrweb Node process so it serves
the current bundle and backend code.

For remote users, do not expose the rrweb service or rely on Vite's development
proxy. Serve the built Secure Access AI UI and Warpgate route on the same
authenticated origin (or configure an explicitly secured same-origin reverse
proxy). The Vite dev server is loopback-only and is not a production hosting
solution.

## Verification status

Unit tests and builds are not a substitute for logging in through Warpgate and
testing a real configured target. Verify that the current running Warpgate
binary has been rebuilt after source changes: the live OpenAPI document at
`/@warpgate/api/openapi.json` must contain
`/rrweb-recording-token`. Do not treat a route 404 as an authorization failure
until that check passes.
