# Prioritized Improvement Plan

## P0 — Preserve authorization and evidence integrity

- Keep Warpgate identity validation and role-scoped access on every request.
- Keep tools read-only and schema validated; no arbitrary SQL or shell.
- Treat command output, events, and recordings as untrusted data.
- Preserve platform risk classifications; separate suspicious indicators from confirmed incidents.

No confirmed P0 defect was identified in the reviewed source.

## P1 — Resolve Groq 400 compatibility

1. Set `parallel_tool_calls=False` for Groq requests that include tools while using `openai/gpt-oss-120b`.
2. Process one tool call at a time; preserve the assistant/tool message sequence.
3. Add a unit test asserting the flag and a simulated serial multi-turn flow.
4. Add safe provider-error categories so HTTP 400 can distinguish recognized tool-validation problems without logging prompt or evidence.
5. If 400 remains after this fix, capture only sanitized provider error code/category and validate tool schemas independently. Do not silently remove security controls or tools.

## P1 — Make deterministic routing authoritative

- Parse explicit session IDs, protocol, dates, counts and limits deterministically.
- Use the correct dedicated service for SSH, Web recordings, audit feeds and incidents.
- Fix the standard helper's SSH-only labels when the query did not request SSH.
- Use logical session identity consistently and clearly mark capped/partial queries.

## P1 — Backend-owned completeness

- Page archive-wide risk and recording requests in backend code up to a documented budget.
- Only claim complete coverage when the data source confirms the terminal page.
- Preserve cursor and truncation metadata through sanitization and answer creation.

## P2 — Professional reasoning and follow-ups

- Use a common evidence envelope with source/scope/status/provenance.
- Revalidate current state for follow-ups; resolve references only when unambiguous.
- Ask a short clarification when multiple entities match.
- Answer concise by default; format detailed investigations with findings, evidence, confidence/limitations and next steps.

## P2 — Efficiency with correctness

- Do not call the LLM for count-only or exact-ID lookups when backend logic suffices.
- Deduplicate identical read calls within one request after validation.
- Do not cache live security evidence across requests.
- Parallelize only independent requests when both model and source capacity support it.

## P3 — Measure before optimizing

- Collect privacy-safe provider/tool/query timings, call counts, evidence bytes and completeness.
- Benchmark identical workloads before/after; report median/p95 and correctness together.
- Profile archive scans before query-side aggregation or indexing changes.

## Safe rollout order

1. Integrate the serial-call flag and test; deploy behind existing auth.
2. Confirm 400 resolution without exposing private session evidence.
3. Fix protocol-scope labeling and deterministic query routing.
4. Make completeness and pagination backend enforced.
5. Add structured evidence and follow-up integration.
6. Benchmark, then optimize confirmed hotspots.
