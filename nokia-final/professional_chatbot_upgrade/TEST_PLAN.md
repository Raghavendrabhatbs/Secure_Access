# Test Plan

## Isolated prototype tests

`tests/test_groq_compat.py` covers:

- Tool-bearing Groq requests explicitly disable parallel tool calls.
- General non-tool requests omit the parallel-tool field.
- One tool call is accepted.
- Unexpected batches are rejected for sequential-only execution.

Run:

```powershell
python -m unittest discover -s tests -v
```

These tests need no network, provider credentials, application database, or project dependencies.
The isolated prototype suite and Groq add-on unittest suite should be run
separately. The add-on suite passed all 53 tests after reproducing and fixing
the required-tool-choice failure and adding high-risk session routing;
Python syntax compilation also passed.

## Integration regressions

1. Groq SDK receives `parallel_tool_calls=False` for `openai/gpt-oss-120b` — covered.
2. Other tool-capable models retain their documented intended behavior.
3. System-data questions still require evidence retrieval.
4. Tool-call messages and result IDs form valid sequential history.
5. Tool schemas still validate and preserve argument constraints.
6. Provider 400 errors remain safe and actionable without leaking request or response secrets.
7. Provider 413 evidence compaction remains partial and is not mistaken for complete results.
8. HTTP 401/403, 404, 429, 5xx, timeout, and connection errors preserve their current safe messages.
9. Role-boundary, developer scoping, and audit restrictions remain unchanged.
10. Risk/archive and Web pagination report incomplete coverage when capped.

## Broader chatbot test cases

Use the scenarios in `EVALUATION_DATASET.md`, plus invalid tool arguments, duplicate calls, empty/unavailable sources, partial pagination, prompt injection in outputs, duplicated session identities, new record visibility, and ambiguous follow-ups.

Use mocks for normal tests. Use an isolated temporary DB for integration tests; never reset or seed the shared live database. Do not require a live Groq key for ordinary tests.

## Exit criteria

- Every tool-bearing GPT-OSS call includes `parallel_tool_calls=False`.
- Tool conversation history is strictly sequential.
- All auth and evidence-completeness tests pass.
- No unsupported claim or successful-looking fallback occurs on provider/source failure.
- A live smoke check, if later approved, uses a non-sensitive prompt and does not send session evidence solely to diagnose tool formatting.
