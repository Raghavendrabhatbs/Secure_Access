# Groq Tool-Calling Regression Test Plan

## Read-only test setup

The tests in this directory import the current add-on modules without changing
them. Run from the project root with Python and the add-on test dependencies:

```powershell
python -m unittest discover -s .\groq_toolcalling_fix\tests -v
```

Ordinary tests use mocks and do not need a Groq key, API request, Secure Access
session, PostgreSQL, or Warpgate.

## Required test coverage

`tests/test_toolcalling_contract.py` covers:

1. Valid function envelope and JSON Schema validation for all tools.
2. Rejection of malformed envelopes, duplicate names, invalid required
   fields, unsupported schema keywords, and double-encoded parameters.
3. Maximum function count and serialized-schema-size reporting.
4. Supported (`auto`, `required`, `none`, and supported named-function
   choice) and unsupported `tool_choice` values.
5. Model feature validation for GPT-OSS 120B local tools, no parallel tool
   calls, JSON mode, and unsupported/unverified combinations.
6. Non-streaming completion request shape and no implicit JSON response
   format.
7. Normal response without a tool call.
8. One tool call and matching result ID/name.
9. Multiple calls in a single response, each with one matching result before
   the next provider round.
10. Invalid tool argument JSON/schema rejection without arbitrary execution.
11. Current provider HTTP auth, permission, model-not-found, malformed request,
    413, 429, timeout, connection, and 5xx handling without secret/body
    leakage. The isolated proposed classifier separately checks context-length,
    tool-schema, and unsupported-feature categories.
12. Missing Groq configuration.
13. Evidence retrieval, sanitization, JSON serialization, per-result and
    cumulative output limits.

The current implementation is characterized where possible; tests for new
diagnostic categorization and stricter assistant-tool-history validation are
marked as proposed-contract tests and should be wired into application tests
only after approval.

## Optional live test

`tests/test_live_groq.py` is skipped unless both `RUN_GROQ_LIVE_TEST=1` and
`GROQ_API_KEY` are set. It sends a synthetic user prompt and function schema
only; no Secure Access client or session evidence is instantiated. It captures
only safe provider error fields. A live result is not required for ordinary
test success.

## Acceptance criteria

- All current tool definitions pass structural validation.
- Invalid schemas, choices, model combinations, arguments, and histories fail
  locally before a provider call.
- Every assistant tool call has exactly one correctly named/id'd result.
- Multiple calls are completed in a single response cycle; never submit
  orphaned results.
- Sensitive request data and secrets never appear in logs or error text.
- Existing evidence limits and partial-result reporting remain unchanged.
- Provider errors reach the UI as understandable categories; diagnostics stay
  redacted and server-side.
