# Technical Assessment

> Baseline snapshot from before the integration fix. See
> [IMPLEMENTATION.md](./IMPLEMENTATION.md) for the reproduced HTTP 400 cause
> and applied changes.

## Scope

This is a proposal-only review. No existing project file, database, environment, or deployment was modified. The isolated prototype is not wired into the application.

## Active implementations

Two separate chatbot entry points exist:

- The standard UI calls `POST /chat/query` in `services/api/app/api/routes.py`. It routes unified SSH/Web overviews and Web-specific questions to dedicated services; other questions use `services/api/app/services/chatbot_service.py`, whose default provider is Ollama.
- The optional Groq add-on exposes `POST /api/chat` in `groq_ai_addon/backend/app.py`. It independently validates the Warpgate cookie, creates its own tool registry/client, and uses `groq_ai_addon/backend/chatbot_service.py`.

The standard service does not instantiate the Groq add-on. Runtime active selection must be confirmed from the deployed UI proxy/configuration; source review alone cannot establish which mode the user had selected when the error appeared.

## Verified capabilities

- Groq tool calls use a fixed allowlist of Pydantic-validated read operations.
- The add-on uses authenticated Secure Access API calls and scopes developer access.
- Tools cover session counts/lists/details, command logs, Web recording activity, archive command analysis, session events, audit logs, incidents (optional source), data-source status, and application architecture knowledge.
- Evidence has per-result and cumulative request limits; command and Web recording data have further bounds.
- Groq model defaults to `openai/gpt-oss-120b`.
- The UI error corresponds to HTTP 400. The provider adapter maps all HTTP 400 responses to one generic “request format/tool schema” message and logs only the error class and status; the exact Groq validation response is not retained for diagnosis.

## Highest-impact findings

### P1 — Likely mismatch: GPT-OSS 120B has no parallel tool-call support

The installed Groq SDK exposes the `parallel_tool_calls` request field. Groq's tool-use model matrix lists `openai/gpt-oss-120b` as supporting tool use but not parallel tool use. The add-on does not set `parallel_tool_calls`, and its orchestration loop accepts multiple calls in one assistant response. A multi-call request/response under this model is therefore a strong candidate for the observed 400.

This is the most specific evidence available, but not a confirmed root cause: the application intentionally discards the provider's 400 message. An incompatible tool schema, unsupported argument, or different provider validation issue remains possible.

**Proposed fix:** explicitly set `parallel_tool_calls=False` when tools are sent to GPT-OSS 120B, and process one tool call per round. Add a regression test that asserts the request parameter and validates sequential orchestration.

### P1 — 400 diagnostics are too generic to isolate remaining causes

Every 400 is presented as model/tool schema rejection. The add-on does not distinguish unsupported parallel calls, invalid tool schema, malformed conversation tool-call history, and other provider validation errors.

**Proposed fix:** map only safe, recognized provider error codes/categories to actionable messages. Do not log prompts, tools' private results, credentials, or raw response bodies.

### P1 — Two independent chatbot paths can drift

The standard API and optional Groq add-on have separate routing, evidence, context and response contracts. An add-on fix does not repair standard mode, and vice versa.

### P1 — Broad requests may rely on model-driven pagination

Archive and Web tools expose page/completeness metadata, but continuation is partly directed by prompt instructions. Backend-controlled paging is safer for explicit all-record requests.

### P2 — Tool schemas are large and include nullable union types

The tool registry defines many functions at once; parameters include JSON Schema union forms such as `["string", "null"]`, optional fields, and constraints. These are standard schema constructs, but any future schema simplification must be validated against the actual Groq error before changing the schema.

### P2 — No baseline metrics

No latency, tool-call, evidence-size or live-provider measurements were collected. No speedup is claimed.

## Data sources and boundaries

- SSH session metadata/commands/events: authenticated Secure Access API backed by live Warpgate and PostgreSQL.
- Web session/recording metadata and bounded rrweb activity: authenticated Warpgate-backed API.
- Audit events: Secure Access UI and Warpgate feeds; role-restricted and bounded.
- Incidents: optional separate read-only PostgreSQL source.
- A separate universal-log source is not verified in the reviewed add-on architecture.
- Groq receives the user question and selected, sanitized tool evidence. This is external data transmission.
- Neither chatbot endpoint alone guarantees background ingestion; freshness depends on the relevant live API/ingestion.

## Security assessment

No arbitrary SQL or shell tool was identified in the reviewed add-on tool registry. Authentication and role checks are implemented separately in both paths. This review is limited to the inspected source and is not a security certification.
