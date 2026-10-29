# Chatbot Enhancement Assessment

## Scope and constraints

This is a read-only assessment prepared under the user's proposal-only instruction. No existing source, test, configuration, environment, database, or deployment file was modified. The assessment follows the request to wait for explicit approval before integrating any change.

Reviewed the standard API chatbot, session and evidence query services, API routing and authentication, the standalone Groq add-on, its tool registry and data client, related tests, frontend references, and add-on deployment documentation. Existing changes elsewhere in the worktree were left untouched.

## Implementation map

There are two separately implemented assistant paths:

1. **Standard Secure Access API:** `services/api/app/api/routes.py` handles `POST /chat/query`. It routes session overviews through `UnifiedSessionQueryService`, web questions through `WebSessionQueryService`, and other questions through the large `ChatbotQueryService`. The latter uses `OllamaProvider` by default and has deterministic answers plus grounded evidence retrieval.
2. **Optional Groq add-on:** `groq_ai_addon/backend/app.py` exposes `POST /api/chat`. Its `ChatbotService` independently authenticates the Warpgate cookie, builds a `SecureAccessClient` and `ToolRegistry`, calls Groq, and retrieves evidence from authenticated Secure Access APIs. Its README and integration guide describe a separate UI/proxy route.

The standard API does not instantiate the Groq add-on. Therefore, changes made only to one path will not necessarily affect the other. Which path is active depends on the UI route/proxy and deployment configuration; that was not assumed from source alone.

## Highest-impact findings

### P0 — No confirmed P0 defect in the reviewed paths

No confirmed authentication bypass, arbitrary SQL/shell tool, or write-capable chatbot tool was identified in the reviewed routes. Both paths validate Warpgate identity; the add-on uses fixed, schema-validated read tools, and its tests cover important role boundaries. This is a bounded source review, not a security certification.

### P1 — Duplicate assistant implementations can produce inconsistent answers

The API and Groq add-on have different routers, providers, evidence retrieval, and context handling. The core route decides which service handles a query before answer generation; the add-on has its own endpoint and prompt/tool loop. Consequently, a fix to session selection, risk wording, timestamps, or completeness in one path can leave the other path wrong. The prior execution-time formatting fix in the standard API does not automatically update the Groq archive formatter.

**Evidence:** `services/api/app/api/routes.py` (`chat_query`); `services/api/app/services/chatbot_service.py` (`build_llm_provider`, `answer_question`); `groq_ai_addon/backend/app.py`; `groq_ai_addon/backend/chatbot_service.py`.

### P1 — Core session-listing helper labels unfiltered results as SSH

`ChatbotQueryService._answer_session_listing` filters by SSH only when the question contains “ssh”; otherwise it asks `SessionQueryService` without a protocol filter. It nevertheless formats empty results as “No SSH sessions” and non-empty results as “distinct SSH session(s).” This can misstate scope when the query is not SSH-specific and the backing session table contains multiple protocols.

**Proposed correction:** derive the display label and filter from one normalized protocol/scope value; when scope is all protocols, report all protocols and per-protocol totals or route through the unified session service.

### P1 — Archive risk evidence starts with a bounded sample, not a guaranteed complete result

The Groq service prefetches archive-wide risk evidence with `limit: 25`, then gives the model tool access. The underlying archive endpoint exposes `match_count`, `matches_complete`, offsets, and completion metadata, but the prefetch itself does not continue through every match. The model is instructed to page through results, but a system prompt is not an enforcement mechanism; the final answer can still summarize the first page unless the model makes and correctly processes continuation calls.

The archive formatter reports when the displayed sample is smaller than the match count, which is helpful, but the overall interaction still relies on model behavior for exhaustive analysis.

**Proposed correction:** make completeness a backend-owned invariant. For explicit all-archive questions, retrieve pages programmatically up to an agreed budget; only report complete after terminal pagination metadata, otherwise mark the answer partial and state what remains.

### P1 — Archive analysis does full database work before returning a page

`SessionQueryService.analyze_command_archive` calls `list_all_sessions`, loads matching command rows, classifies the command archive in Python, builds all per-session summaries and matches, then slices the requested page. This is correct for bounded current data, but query pagination does not bound the scan's memory or classification work. The endpoint can become slow or memory-heavy as history grows.

**Proposed correction:** measure first, then move filtering, stable ordering, and aggregation into paged/database-side operations where practical. Preserve exact classification semantics and complete counts; avoid introducing a cache that can make security results stale.

### P1 — Evidence availability and completeness need a consistent contract

The Groq loop has per-result and cumulative serialized-output limits and signals incomplete retrieval, and tool results carry source-specific completeness flags. However, the answer loop delegates page continuation to the model. `sanitize_for_llm` also truncates strings and lists; for generic payloads, truncation is not uniformly represented as a top-level completeness signal. The core API and Groq add-on return different metadata shapes and error semantics.

**Proposed correction:** normalize evidence status (`complete`, `partial`, `empty`, `unavailable`, `failed`, `denied`) and retain truncation/page metadata end-to-end. Never turn unavailable or capped evidence into “no activity.”

### P2 — Tool calls are not deduplicated and execute sequentially

The Groq service accepts multiple tool calls in a response and executes them sequentially. It has a round limit and evidence-size budgets but no per-request normalized `(tool, arguments)` duplicate guard. Repeated equivalent calls therefore consume API latency and output budget. Parallel calls should not be added indiscriminately; dependent calls such as “fetch page, inspect cursor, fetch next page” must stay ordered.

**Proposed correction:** deduplicate identical read calls within one request after validation; do not reuse results across requests. Cap calls per round/request separately from pagination rounds. Parallelize only independent read operations after checking API/database capacity.

### P2 — Session, output, risk and archive answers need source-aware formatting

The Groq archive risk formatter lists command and risk categories but omits `executed_at`, although the archive endpoint returns it. The standard assistant has a different timestamp formatter. Risk findings are rule-based command-input classifications; they are not proof of malicious intent or confirmation that an effect occurred. Session-specific command output can be retrieved, but archived risk samples deliberately remove output before the model sees it.

**Proposed correction:** share a formatting contract across providers. Include recorded execution time and timezone when present; distinguish missing time from missing records. Explain the exact rule finding, keep command input separate from output text, and describe observed effects only when evidence supports them.

### P2 — Groq follow-up context is weaker than the standard API path

The standard API resolves follow-ups using stored conversation history and structured entities. The add-on's request model accepts only a single `message`; its service constructs a fresh prompt and does not receive conversation ID/history. Thus references such as “that session” may not carry over when using Groq, even though the standard path has context support.

**Proposed correction:** pass a bounded, authenticated, same-conversation context envelope or resolve context in the shared API before calling the add-on. Revalidate session facts live; never use previous evidence as proof of current state.

### P2 — Some data sources are explicitly bounded or unavailable

The add-on client caps SSH/Web row scans at 10,000, audit records at 500, and active SSH event checks at 25 candidates. Web recording analysis pages at most 10 recordings per tool call. The add-on documentation states there is no separate universal-log source and incidents are available only when a separate read-only database URL is configured. These are valid constraints, but answers must retain them and not imply exhaustive coverage.

**Proposed correction:** expose caps, source status and pagination in answer evidence; distinguish a missing universal-log integration from an empty log query.

### P3 — There is no measured latency baseline in this proposal

The source contains explicit timeouts and evidence-size limits, but no baseline numbers were collected for end-to-end latency, tool calls, provider calls, retrieved rows, or serialized evidence. No performance gain should be claimed until the same representative cases are measured before and after.

## Existing strengths to preserve

- Authenticated identity is checked against Warpgate rather than trusted from caller-provided role fields.
- The Groq add-on validates tool arguments with Pydantic and has no arbitrary SQL/shell tool.
- Developer-specific SSH/Web scoping and audit-role restrictions have existing tests.
- Session identity is deduplicated using a logical identifier in core session queries.
- Date/time query parsing and timezone-aware query bounds already exist.
- Web recording summaries omit DOM text and input values.
- Command archive and per-command output have bounded paging; the Groq client checks response shapes and reports common source failures.
- Tests already cover multiple core and Groq behaviors, including role scoping, duplicate Web IDs, unavailable sources, tool limits, and grounded tool retrieval.

These mechanisms should be extended, not replaced wholesale.
