# Architecture Assessment

## Verified existing architecture

- The UI is a React/Vite app under `services/web`; the API is FastAPI under
  `services/api`.
- The existing assistant uses PostgreSQL session data and an Ollama provider.
  It validates `warpgate-http-session` through Warpgate and permits `admin`,
  `developer`, and `auditor_viewer`.
- PostgreSQL models are `sessions`, `session_commands`, and `session_events`.
  Commands and events refer to the session row's `unique_id`; logical session
  identity is `COALESCE(session_id, unique_id)`.
- Warpgate is the live source for current SSH sessions. The add-on reads its
  authenticated, role-scoped session feed and merges it with PostgreSQL's
  historical archive so sessions not yet mirrored into PostgreSQL remain
  queryable.
- Authenticated API routes expose SSH session summaries/details, commands,
  events, and timelines. Authenticated Web routes expose Warpgate rrweb
  metadata. Session changes are persisted by the existing SSH ingestion
  service; the Web metadata API reads recordings produced through the
  Warpgate/rrweb pipeline.
- The rrweb service exposes Secure Access UI audit events and Warpgate gateway
  audit events through authenticated endpoints. Admins and auditors can read
  them, with each endpoint capped at 500 most recent matching records.
- `services/agent/create_incidents_table.py` and `agent_graph.py` show an
  `incidents` table used for security-alert records; this is separate from the
  two audit-event feeds.
- The Web metadata API exposes recording counts, status, targets, and page
  visits. For a specific authorized, finalized recording, the add-on can read
  the rrweb event file on demand and provide bounded activity statistics; it
  excludes DOM text and input values from Groq evidence.

## Addon request flow

1. A standalone same-origin page posts a question to this addon.
2. The addon independently validates the signed Warpgate cookie and role using
   the Warpgate identity endpoint. It never trusts a role supplied by the UI.
3. Fixed, schema-validated Groq tools query authenticated Secure Access and
   Warpgate routes. No arbitrary SQL or shell tool exists.
4. Developer SSH and Web results are filtered to the authenticated username;
   the existing APIs apply their own developer scope. Audit logs are only
   queried for roles permitted by the audit API (admin and auditor).
5. Tool evidence is minimized and redacted, then sent to the configured Groq
   model. Recording payloads are summarized locally; retrieved content is
   explicitly treated as untrusted evidence.
6. Responses contain evidence mode and source summary. No query results are
   persisted by the addon.

An optional incidents adapter performs only fixed, parameterized `SELECT`
queries in a PostgreSQL read-only transaction. It is enabled only by an
explicit `AUDIT_DATABASE_URL`; it does not fall back to the application's
database credentials.
