# Proposed Groq Tool-Calling Fix

## Status

Proposal only. Existing project files are unchanged. Wait for explicit
approval before integrating any recommendation below.

## Minimal, evidence-led approach

1. **Keep the configured model.** `openai/gpt-oss-120b` is documented for local
   tool use. Keep `parallel_tool_calls=False` whenever tools are present. Do not
   silently substitute a model.
2. **Keep `tool_choice="auto"` for tool requests.** `required` is a documented
   option, but can itself return 400 if the model does not emit a tool call.
   Preserve the existing bounded, authorization-checked evidence fallback for
   recognized questions when no tool is called.
3. **Add safe request diagnostics.** For provider exceptions, retain status,
   model, whether tools were included, tool count/names, tool-choice category,
   streaming state, request round, and whether evidence/tool execution has
   occurred. Extract only allowlisted provider error `code`, `type`, and
   redacted/truncated message. Never log API keys, authorization headers,
   prompts, session records, command output, or raw request/response bodies.
4. **Classify provider errors.** Distinguish 401/403 auth/permission, 404
   unsupported model, 413 payload size, 429 rate-limit, 400 invalid request
   (with subcategories only when the provider code/message safely identifies
   one), context length, timeouts/connections, and provider 5xx. Do not retry
   deterministic 400 errors. Keep retry behavior for payload-size errors only
   when evidence compaction actually changes the request.
5. **Validate before sending.** Add startup/test-time validation of function
   envelopes, names, uniqueness, supported JSON Schema keywords and root
   object parameters. Reject malformed or unknown `tool_choice`, unsupported
   model-feature combinations, and schemas that exceed Groq's documented
   function-count limit. Preserve Pydantic's strict argument validation.
6. **Validate response history.** Before the next provider request, require
   unique nonempty call IDs, valid function names, JSON-object arguments, and
   exactly one matching `role="tool"` result for every assistant call. Preserve
   bounded/sanitized result serialization. Handle every call in a response
   before asking the model again; if a call fails, abort rather than send an
   incomplete/orphaned history.
7. **Retain evidence limits.** Keep the existing 10,000-character per-result
   and 32,000-character cumulative caps; report incomplete/compacted evidence.
   Do not increase limits as a workaround for a request-format error.

## Existing files that would need edits after approval

- `groq_ai_addon/backend/groq_client.py` — categorized, redacted provider
  diagnostics; request metadata; validated model/tool parameters.
- `groq_ai_addon/backend/chatbot_service.py` — tool-call response/history
  validation and precise round/outcome metadata.
- `groq_ai_addon/backend/tool_registry.py` — only if schemas need a concrete,
  provider-verified adjustment; no schema change is presently justified.
- `groq_ai_addon/tests/test_addon.py` — integrate the regression coverage
  represented in this directory.
- `groq_ai_addon/README.md` — describe diagnostics and model limitations.
- Optionally `groq_ai_addon/backend/app.py` — expose a concise safe provider
  category in HTTP 502 responses while leaving detailed redacted diagnostics
  server-side.

No environment file, dependency manifest, database, or model setting should
change for this proposal.

## Why no schema/model change is proposed yet

The current full schema set is 12 functions / 6,291 bytes and passes the local
structural audit. Groq accepted a current synthetic tool request using the
actual model and the current risk-query subset. There is no captured provider
error identifying a bad schema or unsupported model. Changing the schema/model
now would be speculation and could reduce behavior without resolving the
actual 400.

## Optional live test after review

`tests/test_live_groq.py` is intentionally opt-in. It requires
`GROQ_API_KEY`, sends only synthetic prompt/tool definitions, requests a tool
call, and never connects to Secure Access or sends real evidence. It can be
run only after setting `RUN_GROQ_LIVE_TEST=1`. It reports provider status,
allowlisted error code/type/message with redaction; never prints credentials.
