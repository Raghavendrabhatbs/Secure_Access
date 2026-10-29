# Standalone Groq AI Addon

This optional addon provides a separate, server-side Groq chatbot that retrieves
evidence from the existing Secure Access APIs. The Secure Access UI can switch
to it using the blank toggle in the AI Assistant toolbar; the add-on remains an
independent service and keeps the Groq key on the server.

## Run locally

1. Create a Python environment inside this directory and install
   `requirements-addon.txt`.
2. Copy `.env.example` to `.env` **inside this directory** and set `GROQ_API_KEY`.
   Do not put the key in frontend code or the existing project `.env`.
   If the addon runs on Windows and the Secure Access API runs in WSL, set
   `SECURE_ACCESS_API_URL` to the Windows WSL gateway IP (the default route
   gateway inside WSL; for example, `http://172.25.112.1:8765`), not
   `127.0.0.1`.
3. Leave `WARPGATE_CA_BUNDLE` blank if Warpgate's certificate is trusted by the
   machine running the addon. If Warpgate uses a private or self-signed
   certificate, set it to the absolute path of the trusted CA bundle (never a
   private key).
4. Start the addon from the project root:

   ```powershell
   $addonEnvFile = 'groq_ai_addon\.env'
   groq_ai_addon\.venv\Scripts\python.exe -m uvicorn backend.app:app `
     --app-dir groq_ai_addon --host 172.25.112.1 --port 8890 --env-file $addonEnvFile
   ```

5. In development, start the Secure Access UI and use the blank square at the
   end of the AI Assistant toolbar to switch to Groq. For a WSL-hosted UI, Vite
   proxies requests to the Windows host gateway on port 8890 and forwards the
   signed Secure Access cookie. The add-on listens only on that gateway
   interface, not on every network interface.

The default Groq model is `openai/gpt-oss-120b`; provider requests may take up
to 90 seconds. The addon does not silently substitute another model.
Provider errors now identify common causes such as invalid credentials, model
access, rate limiting, request/tool-schema rejection, and timeouts without
including provider response bodies or request data. When Groq returns a rate
limit, the add-on respects its retry/reset headers and returns HTTP 429 with a
safe retry delay when available. The assistant keeps the question available
and enables a manual retry when that delay expires; rate limits cannot be
overridden by the application. To configure failover, set `GROQ_API_KEYS` in
`groq_ai_addon\.env` to a comma-separated list of keys. On HTTP 401, 403, or
429, the add-on tries each remaining key for that request and uses the first
one that succeeds. `GROQ_API_KEY` remains supported when only one key is configured.
Keep real keys only in the local ignored `.env`, never in source code or chat.
Groq may enforce quotas at the account, organization, or model level; if the
keys share an exhausted quota, switching keys will not avoid the rate limit.
Tool requests send only the read-only schemas relevant to the question, and
parallel tool calls are explicitly disabled for sequential compatibility with
`openai/gpt-oss-120b`. Tool choice uses the model's automatic mode: Groq returns
HTTP 400 if `required` is set but GPT-OSS does not emit a tool call. For
recognized session questions, the addon performs a bounded, deterministic
read-only lookup through the same authorization-checked tool registry if the
model skips retrieval.
Evidence returned across tool calls is capped per result and across the full
request to prevent oversized Groq payloads. When the overall evidence limit is
reached, the assistant reports that its results may be incomplete. If Groq
still rejects a request for payload size, the add-on progressively compacts
retrieved evidence through progressively smaller limits and retries; answers
produced from compacted evidence are explicitly marked as potentially partial.
If the request remains too large, the add-on returns a clear error instead of
an empty or fabricated answer.

The addon has no write tools and creates no database or cache. Session queries
call the live APIs for each request; newly persisted records are visible on the
next query. Missing API keys, failed identity checks, data-source failures,
rate limits, timeouts, and provider errors are reported explicitly.
Verified architecture and source-availability facts are also available to
answer application-specific questions without relying on model memory.

For questions about all Web recordings, the assistant pages through up to ten
authorized recordings at a time and retrieves bounded activity statistics from
each. It reports incomplete pages and recordings that are still being recorded
or cannot be retrieved. A newly finalized recording appears on the next query;
the addon does not run a continuous background monitor. Recording DOM text and
input values are excluded from model evidence.

Questions about recent high-risk SSH sessions are answered from PostgreSQL
command-risk findings grouped by session, including recorded session and
command timestamps where present. These are rule-based command matches; they
do not imply that the platform assigned a HIGH session-level risk rating.

## Data limitations

- Current SSH sessions are read from Warpgate's authenticated, role-scoped
  session feed and combined with historical session records in PostgreSQL.
  Commands and session events remain available from the Secure Access API
  archive. Archive-wide SSH command summaries and risk-rule scans query
  PostgreSQL command rows. Archive summaries include global totals and paged
  per-session counts, risk categories, and representative command inputs;
  individual-session command retrieval is paged and includes each stored
  command input and terminal output. Long outputs are paged in 4,000-character
  chunks, with continuation metadata; complete outputs remain in PostgreSQL.
  Risk results classify recorded
  command input, not arbitrary text that appears only in terminal output.
- Web sessions and recording metadata are read through the authenticated
  Warpgate-backed API. For an authorized finalized recording, the assistant
  can retrieve a bounded activity summary on demand; DOM text and input values
  are excluded.
- Admins and auditors can query the existing Secure Access UI audit feed and
  Warpgate gateway audit feed. Each API currently returns at most its 500 most
  recent matching events. Developers are not authorized to read these audit
  feeds.
- The project also contains an `incidents` table used by the agent for alerts.
  Incident retrieval is disabled unless `AUDIT_DATABASE_URL` points to a
  dedicated read-only database account.
- Active SSH status uses Warpgate's live session state, with lifecycle events
  as the archive fallback. Web metadata has no reliable active indicator.
- Data and prompts selected for grounded answers are sent to Groq. Secret-like
  fields and common inline credentials are redacted before provider requests.
- The assistant retrieves relevant evidence live for each question, so newly
  persisted sessions and finalized recordings are available on the next
  request. It does not train or permanently ingest private records into Groq.

See [ARCHITECTURE.md](./ARCHITECTURE.md), [SECURITY.md](./SECURITY.md), and
[INTEGRATION_GUIDE.md](./INTEGRATION_GUIDE.md).
