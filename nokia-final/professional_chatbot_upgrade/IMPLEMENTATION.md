# Isolated Implementation and Integration Notes

## Prototype contents

`prototype/groq_compat.py` builds Groq completion arguments with
`parallel_tool_calls=False` whenever tools are supplied. It also provides a
guard against an unexpected multi-call batch from a sequential-only model.
This is an isolated compatibility prototype, not imported by the application.

It uses only the Python standard library and can be tested without a Groq key.

## Integrated fix

The user subsequently approved fixing the observed request-size failure. The
application changes are now in:

- `groq_ai_addon/backend/groq_client.py`: explicitly disables parallel calls
  for tool-bearing requests, matching GPT-OSS 120B's sequential tool-use
  capability.
- `groq_ai_addon/backend/chatbot_service.py`: sends only relevant read-only
  tool definitions, uses `tool_choice="auto"` to avoid Groq's HTTP 400 when
  GPT-OSS doesn't emit a forced tool call, and routes recognized questions to
  an authorization-checked read-only fallback when the model skips retrieval.
  Recent high-risk session questions are deterministically answered from
  PostgreSQL risk matches grouped by session, with recorded timestamps.
- Payload-size retries compact evidence through progressively smaller limits.
- `groq_ai_addon/tests/test_addon.py`: adds coverage for sequential provider
  requests and relevant tool selection.
- `groq_ai_addon/README.md`: documents the request behavior and retry limits.

The HTTP 400 was reproduced safely with a synthetic prompt and no session
evidence. Groq returned `Tool choice is required, but model did not call a
tool` for `tool_choice="required"`. Using automatic tool choice avoids that
provider error; deterministic fallback keeps recognizable activity questions
grounded when the model returns no tool call. The exact “explain recent high
risk sessions” question was also tested end-to-end against Groq with synthetic
evidence and now uses the archive risk route without requiring a model tool
call.

The add-on was restarted on the UI proxy interface and its `/health` endpoint
returned `healthy`.

## Run the prototype tests

From this directory:

```powershell
python -m unittest discover -s tests -v
```

## Changes made

1. `groq_ai_addon/backend/groq_client.py`
   - Pass `parallel_tool_calls=False` to `chat.completions.create` when a tool list is present and model is `openai/gpt-oss-120b` (optionally apply to all configured models if sequential calls are an intentional policy).
   - Preserve current API-key handling and do not log the request body.
2. `groq_ai_addon/backend/chatbot_service.py`
   - Keep tool calls serial. Validate any returned batch against the selected model capability; fail explicitly rather than constructing unsupported parallel tool history.
   - Preserve current evidence budgets and partial-result notices.
3. `groq_ai_addon/tests/test_addon.py`
   - Add tests for provider request kwargs, one-call sequencing, invalid multi-call responses, and error categorization.
4. `groq_ai_addon/README.md`
   - Document sequential tool calling, automatic selection, and the fallback.

These application changes are implemented. Existing uncommitted files were
preserved; no unrelated files were changed.

## Diagnostic boundary

This reproduction verified the tool-choice error, not every possible cause of
HTTP 400. Other provider 400 errors remain handled through the existing safe
generic error and do not expose raw provider response bodies or request data.

## Not implemented in this isolated prototype

The prototype does not connect to PostgreSQL, Warpgate, rrweb, the UI, or Groq;
does not authenticate users; does not call the provider; and does not change
the running application. Broader routing, evidence, conversation, and
cross-source improvements require integration changes after approval.
