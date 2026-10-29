# Prioritized Improvement Plan

## Guiding rules

1. Keep the current API, PostgreSQL, Warpgate, rrweb and provider architecture.
2. Make the backend—not the LLM—responsible for deterministic filters, authorization, paging, source status and completeness.
3. Preserve the distinction between input commands, terminal output, lifecycle events, audit events, risk-rule findings and confirmed incidents.
4. Retrieve the smallest evidence sufficient for the question. Do not send raw Web DOM/input data or unrelated command output to a provider.
5. Report limits, uncertainty and source failures. A partial scan is never an archive-wide conclusion.
6. Do not make live-data freshness, background monitoring, or performance claims without runtime evidence.

## P0 — Security conclusions and evidence integrity

No confirmed P0 issue was found in this review. Before rollout:

- Keep identity verification, role enforcement, developer scoping, and read-only tool allowlists in both entry paths.
- Add adversarial tests for instructions embedded in command output, logs, and rrweb metadata. Such text is evidence only, never instructions.
- Keep the rule engine authoritative for configured findings. The model may explain a finding or note contextual limitations but cannot silently replace its severity.
- Ensure the provider receives only question-relevant, redacted evidence; record that a cloud provider receives the remaining content.
- Add a provenance label to every fact: `recorded_input`, `recorded_output`, `platform_finding`, `audit_event`, `inference`, or `not_available`.

**Exit criteria:** no authorization regression; injected evidence cannot change tool permissions or system policy; risk claims map to evidence IDs and scope.

## P1 — Correct routing and session evidence

1. Define a small internal `QueryIntent` representation: domain, action, protocol, session ID, user/target, time range, active/recording filters, requested detail, and whether complete coverage is required.
2. Resolve exact IDs, explicit protocols, explicit dates, counts, latest-session lookups and common command-output requests deterministically. Use an LLM planner only for genuinely ambiguous questions and validate its proposed filters against allowed schemas.
3. Make the current core session-listing helper use a single normalized scope value for query filters and answer labels. Route all-protocol listings to the unified query service.
4. Use one evidence envelope across both paths. Include source, filters applied, retrieved count, total count when known, page cursor, truncation, warnings, and a status (`complete`, `partial`, `empty`, `unavailable`, `failed`, `denied`).
5. For one session, retrieve its metadata and only requested command/event data. Preserve the logical session ID and use stable ordering for command pages.
6. For exact counts, call the count path only; do not retrieve session or archive pages.
7. For latest-session queries, make protocol explicit when present and scope to authenticated identity in every source.
8. Expose command timestamps with timezone and command outputs only when requested or necessary to answer a summary. State when an execution time, output, target or recording is not stored.
9. Keep SSH and Web recording analyses distinct. Cross-protocol requests should combine their sources explicitly and disclose source-specific incompleteness.

**Exit criteria:** the standard API and Groq add-on agree on scope and provenance for matched evaluation cases; no labels claim a narrower or broader scope than the query.

## P2 — Risk, tools, context and answer shaping

1. Make archive paging deterministic in backend code. For “all archive” queries, page until complete or a fixed budget is reached; include exact scanned scope and cursor state in the evidence envelope.
2. Add per-request duplicate-call suppression after tool-schema validation. Cache only within that request; do not reuse old security evidence across questions.
3. Keep the existing per-result and cumulative evidence budgets. Add a separate maximum call count and enforce the budget across calls in a single model response, not only across rounds.
4. Let the model explain context, not set facts: present command, recorded execution time, platform finding, related events and output as separate evidence fields. Distinguish a suspicious indicator from a confirmed incident.
5. Preserve evidence excerpts with truncation flags. If the question requires omitted output or a missing page, fetch only that continuation or state that the evidence is partial.
6. Add a bounded context contract shared by standard and Groq paths. Resolve unambiguous “that session” references; ask a short clarification if there are multiple candidates. Re-fetch live facts.
7. Standardize concise answer shapes: direct answer first; then supporting fields; then limitations. Expand only when the question asks for a report or analysis.
8. Represent audit/universal-log and incidents as distinct sources. A missing integration is `unavailable/not configured`, not a clean result.

**Exit criteria:** ordinary single-source questions use no redundant tools; complete archive questions either prove completion or clearly disclose the stopping point; follow-ups resolve to the expected entity or request clarification.

## P3 — Observability and modest optimization

1. Record privacy-safe metrics: intent, provider-call count, tool-call count, tool durations, records/pages retrieved, serialized evidence size, truncation and completion status, total latency, and error class.
2. Exclude prompts, commands, outputs, cookies, authorization headers, credentials, and raw rrweb payloads from metrics.
3. Benchmark existing behavior before changing query execution. If archive scans are dominant, add database indexes/query-side aggregation or streaming/batched classification only after validating semantic parity.
4. Parallelize only independent, read-only source calls after load testing. Keep pagination and dependent lookups sequential.
5. Set budgets by question class: short for counts and lookups; a separately governed larger budget for explicitly exhaustive archive reviews.

**Exit criteria:** report a measured baseline and comparison, with unchanged evidence correctness and authorization tests.

## Suggested implementation sequence after approval

1. Add shared evidence contract and protocol-label correction in core; add focused regression tests.
2. Add deterministic query-intent dispatch for exact IDs/counts/latest/session-specific requests.
3. Refactor Groq prefetch and archive completion handling to use backend-owned paging and explicit partial results.
4. Add normalized per-request call deduplication and budget accounting.
5. Add bounded conversation-context handoff.
6. Add cross-path acceptance evaluation and privacy-safe telemetry.
7. Optimize archive database work only if the baseline confirms it is material.

Do not combine these into one broad rewrite. Each step should be independently testable and retain a rollback path.
