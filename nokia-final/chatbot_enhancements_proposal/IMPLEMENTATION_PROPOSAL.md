# Implementation Proposal

## Integration boundary

Keep `services/api` as the authority for identity, session query semantics, protocol identity, PostgreSQL data, and source status. Keep `groq_ai_addon` optional as a provider adapter. Avoid creating a third chatbot or copying query logic into the UI.

The standard API remains usable without Groq. If the user selects Groq, the UI reaches the standalone add-on through the existing authenticated proxy. Both paths should consume the same query/evidence contract, either through a shared internal package or an authenticated API response; do not create a bypass endpoint or duplicate permission logic.

## Proposed internal contracts

### Query intent

```text
QueryIntent
  domain: ssh | web | audit | incident | mixed | application | general
  action: count | list | latest | details | commands | output | risk | summarize | explain
  protocol: ssh | web | all | unspecified
  session_id: optional validated ID
  username, target: optional validated filters
  time_range: optional [start, end) in configured application timezone
  active_only, has_recording: optional booleans
  detail_level: concise | detailed
  requires_complete_coverage: boolean
```

Precedence proposal:

1. Validate an explicit session ID and supported protocol.
2. Parse exact dates, relative date ranges, UUIDs and unambiguous counts using existing parsing helpers.
3. Select a deterministic query route when intent and filters are clear.
4. Use model-assisted interpretation only for ambiguity, with a strict schema and no execution authority.
5. If ambiguity remains material (for example, “that one” after multiple candidate sessions), ask one clarification.

### Evidence envelope

```text
EvidenceResult
  source: postgresql | warpgate_live | rrweb | audit_ui | audit_gateway | incidents
  query: normalized filters and logical session ID
  status: complete | partial | empty | unavailable | failed | denied
  records: typed, provenance-labelled records
  total_count: optional exact count
  page: offset/cursor, next cursor, has_more
  truncation: output/record limits and continuation cursor
  warnings: safe, user-displayable reasons
  timings: internal duration and record counts (no private content)
```

The response contract should preserve the existing API fields while adding structured completeness/source metadata in a backward-compatible way. Do not let an LLM infer `complete` from seeing a page with few records.

### Evidence provenance

Each command-related item should carry:

- `recorded_input`: the command input captured in the SSH recording.
- `recorded_output`: terminal output attached to that input, if stored.
- `executed_at`: timestamp and timezone, or an explicit unknown value.
- `exit_code`: recorded value or unknown.
- `risk_findings`: platform rule, severity, and category.
- `source_session_id` and stable sequence number.

Text found only in output, a test marker, an event, or an LLM inference must not be rendered as an executed command.

## Query-specific execution

| User request | Proposed execution | Avoid |
|---|---|---|
| Count SSH sessions today | One filtered SSH count query using configured timezone and logical identity | Listing sessions, command archive scan, LLM tool planning |
| Show today's sessions | One paged session listing with protocol and date filters | Counting as a substitute for a list; hard-coded SSH labels |
| Current active SSH sessions | Live Warpgate state plus documented lifecycle fallback; explicit incomplete status if either source is capped/unavailable | Assuming no end timestamp alone proves active |
| Web recording summary | Fetch authorized Web metadata and bounded local rrweb activity summary | SSH archive scan; raw DOM/input values to provider |
| Commands in session X | Validate access, fetch session metadata and command pages for X | Cross-archive search |
| What did command Y return? | Retrieve matching command row and only the required output chunks; preserve truncation markers | Returning unrelated session output |
| Risky commands across archive | Scan all eligible PostgreSQL SSH command inputs, page findings to budget, include execution times, counts, completeness and platform rules | Calling a 25-result sample “all”; classifying output text as input |
| Why is session X high risk? | Fetch X metadata, commands, platform findings and relevant events; explain exact rules and gaps | Inferring compromise from command name alone |
| Audit / universal log | Query authorized audit feeds; clearly separate UI events, gateway events and incident alerts | Calling an incidents table a universal log |
| “That session” follow-up | Resolve against the same authenticated conversation's structured session entities, then re-fetch live evidence | Using stale conversation text as current evidence |

## Risk explanation policy

1. Start with authoritative stored findings and their application severity.
2. State whether evidence is command input, command output, a platform finding, a related event, or an inference.
3. Explain the relevant rule/category and its limits.
4. Include command execution time and session time when present.
5. Describe output or observed effects only when stored evidence supports the statement.
6. Do not upgrade/downgrade a platform severity silently. If contextual analysis suggests a discrepancy, state both.
7. Use cautious language: “flagged by rule X,” “potentially suspicious,” or “confirmed event Y” as warranted.
8. Recommend investigation only when relevant and proportional; do not declare compromise from command text alone.

## Tool loop and budgets

- Keep existing JSON schema validation and `SecureAccessClient` role scoping.
- For deterministic cases, bypass model tool selection and retrieve the minimum evidence directly.
- For ambiguous cases, validate each tool call before execution and record a normalized request key for same-request duplicate suppression.
- Enforce separate limits for tool calls per round, tool calls per question, total evidence bytes, rows, output characters and archive pages.
- Preserve current caps as safe ceilings until load measurements justify changes.
- Execute independent read-only queries concurrently only after explicit load testing; execute pagination and dependent detail lookups sequentially.
- Make archive pagination a backend loop with a clear budget. If the budget ends before `complete=true`, return `partial` with remaining cursor/count. Never ask the model to turn a sample into a complete report.
- Keep no cross-request result cache for active sessions, risk, audit data, or recent activity.

## Errors and empty data

Map source outcomes to explicit safe messages:

- `empty`: source responded successfully and no matching record exists.
- `unavailable`: identity/source endpoint could not be reached or is not configured.
- `failed`: source responded with an error or invalid payload.
- `denied`: authenticated role is not permitted.
- `partial`: data returned, but a cap, page budget or truncation prevents complete coverage.
- `not_stored`: source is healthy, but the requested field is absent from the returned record.
- `ambiguous`: multiple records or interpretations remain.

Keep internal exception details out of user-facing text and logs. Do not convert these outcomes to a success-shaped empty list.

## Core correction proposal

In `ChatbotQueryService._answer_session_listing`, compute the normalized requested protocol once. Use that value both in `query_sessions` and in the answer title/empty-result message. When no protocol is requested, do not describe the total as SSH-only; either report separate protocol counts or delegate the generic session listing to `UnifiedSessionQueryService`. Keep explicit date and username/target filters intact.

## Rollout / integration requirements

1. Confirm the deployed frontend's active API route and Groq proxy; source contains separate standard and optional paths.
2. Preserve Warpgate cookie forwarding and enforce identity in the backend on every request.
3. Verify admin, auditor and developer scopes independently against both backends.
4. Confirm the configured Groq provider/model and data-sharing approval before sending session output.
5. Keep `AUDIT_DATABASE_URL` separate and read-only if incident reads are enabled.
6. Confirm time zone configuration and present timestamps with explicit zone abbreviations/offsets.
7. Ensure the ingestion watcher is running before asserting PostgreSQL freshness; the chatbot does not itself guarantee continuous ingestion.
8. Deploy with a rollback path to the existing standard API behavior.

No source changes are proposed as approved implementation in this phase. The file and symbol names above identify likely integration points only.
