# Architecture Proposal

## Preserve the existing boundary

Do not create a third chatbot implementation. Keep `services/api` authoritative for identity, permissions, session identity, source availability, and PostgreSQL semantics. Keep the Groq add-on optional and provider-focused.

### Current flow

```text
Secure Access UI
  ├─ Standard mode → FastAPI POST /chat/query → unified SSH/Web, Web query, or core chatbot → PostgreSQL/Warpgate/Ollama
  └─ Groq mode     → Vite proxy → Groq add-on POST /api/chat → Groq tool loop → authenticated Secure Access APIs
```

The routing/proxy path active in a particular browser deployment must be verified at runtime; repository code shows both paths.

## Immediate 400 compatibility adjustment

`openai/gpt-oss-120b` supports tool use but is listed by Groq as not supporting parallel tool calls. Set `parallel_tool_calls=False` on tool-bearing requests for that model. Treat the tool loop as serial: one call, one result, then another model turn if needed. This avoids depending on model/provider parallel-call behavior and keeps evidence paging ordered.

The add-on currently handles tool calls sequentially in Python, but that alone does not disable parallel generation or guarantee a compatible conversation shape; the API request needs to explicitly disable it. The current generic 400 response prevents confirmation of this diagnosis, so retain a safe categorized provider error path.

## Proposed shared query/evidence contract

Introduce only after approval, ideally in an existing shared backend module:

```text
QueryIntent
  domain, action, protocol, session_id
  username, target, time_range
  active_only, recording_filter, detail_level
  requires_complete_coverage

EvidenceResult
  source, normalized_scope, status
  records, total_count, cursor, has_more
  output_truncation, warnings, retrieval_duration
```

Allowed statuses: `complete`, `partial`, `empty`, `unavailable`, `failed`, `denied`, `not_stored`, `ambiguous`.

The core API should perform deterministic counts, exact-session lookups, explicit protocol/date filters, authorization, and pagination. Models may interpret ambiguous language and explain evidence but cannot authorize access or redefine completeness.

## Question-to-source examples

| Question | Minimum evidence path |
|---|---|
| SSH count today | Timezone-aware SSH count only |
| Commands in session UUID | Authorized session metadata and paged command log for that ID |
| What did a command return? | Matching command input and only its output pages |
| Risky commands in the full archive | Archive-risk pages through completion or a disclosed scan budget |
| Latest Web recording | Web metadata and bounded rrweb activity summary |
| Audit event query | Authorized UI/gateway audit sources; separate incident records |
| General technical explanation | Model knowledge; no private tools unless installation-specific claims are requested |

## Answer/provenance model

Keep input commands, output text, platform risk findings, audit events, incidents, and inference separate. Include a timestamp only when the source provides one, with timezone. Preserve platform severity and explain the rules; do not assert compromise from a command name alone.

Treat retrieved data as untrusted evidence, never instructions. Send only relevant, sanitized data to Groq. Do not send private evidence to public search.

## Uncertainty and errors

Distinguish an empty query from source outage, invalid response, denied access, missing stored fields, incomplete pagination, and ambiguous intent. Never replace failures with successful-looking empty evidence.

## Integration required

The isolated prototype cannot repair the running app by itself. After approval, the exact provider-level integration point is `GroqProvider.complete` in `groq_ai_addon/backend/groq_client.py`; the orchestration guard belongs in `groq_ai_addon/backend/chatbot_service.py`. The actual 400 category should be confirmed from sanitized provider validation diagnostics or a safe request test before altering tool schemas.
