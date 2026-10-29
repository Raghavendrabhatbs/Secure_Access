# Performance Plan

## Baseline status

No before/after latency or throughput measurement was collected as part of this proposal. The source establishes configured caps and identifies likely expensive paths, but source inspection is not a performance benchmark. Do not claim a speedup until measured on the same deployment class and evaluation set.

## Instrumentation

Add privacy-safe measurements at the API and optional Groq boundary:

- Total wall-clock latency and server-side handling latency.
- Intent route and provider name/model identifier (not credentials).
- Provider completion count and duration.
- Tool name, call count, duration and status.
- Query row count, page count, page completion and source warnings.
- Serialized evidence size before/after sanitization.
- Output/page truncation and remaining cursor.
- Error class and HTTP status.

Never log question text, conversation contents, session identifiers, command strings, command output, rrweb payloads, cookies, authorization headers, API keys, or secrets as metric dimensions or labels. Keep high-cardinality and sensitive fields out of general telemetry.

## Benchmark procedure

1. Use the 12-question evaluation set in `TEST_PLAN.md`.
2. Run the same fixture/database snapshot, app timezone, model, model settings, network path, and concurrency for baseline and candidate.
3. Warm the process and provider separately; record cold-start and warm request results independently.
4. Run each case at least 20 times for warm latency if a stable test environment is available; report median and p95, not only average.
5. Record number of SQL/API pages, rows, tool calls, provider calls and evidence bytes alongside latency.
6. Run count, exact-session, output, risk-archive, Web recording and audit cases separately so an archive scan does not hide simple-query performance.
7. Re-run correctness and authorization assertions for every candidate optimization.

## Expected hotspots to validate

1. `SessionQueryService.analyze_command_archive` loads all sessions/command rows and classifies in Python before slicing pages. Measure duration, peak memory, row counts and DB time as the archive grows.
2. `SecureAccessClient.list_ssh_sessions` combines the live Warpgate feed with a PostgreSQL session scan up to configured limits. Measure which source dominates and how often `complete` is false.
3. Groq archive-risk prefetch transfers up to 25 matches plus summary metadata before the model may request more pages. Measure evidence size and subsequent repeated calls.
4. Web recording analysis makes a separate request per recording and per page. Measure service capacity before considering safe bounded concurrency.
5. Multi-round Groq tool calling and final generation can add serial provider latency. Measure actual round count, not the configured 12-round maximum.
6. Standard API grounded analysis may retrieve commands and events per session. Measure query count and evidence size for multi-session risk questions.

## Safe optimization candidates

- Use a count query for counts; avoid retrieving records solely to count.
- Fetch exact session detail and commands by ID rather than scanning the archive.
- Add same-request deduplication for identical normalized read-only tool calls.
- Move archive filtering/aggregation into PostgreSQL or batched iteration if benchmarks prove Python materialization is material.
- Avoid fetching command output unless requested or needed for the answer; preserve bounded excerpts and continuation metadata.
- Parallelize independent reads only when measured API/database capacity and authorization boundaries support it. Keep dependent pagination serial.
- Consider query-plan indexes only after inspecting actual PostgreSQL query plans; write a migration proposal only after separate approval.

## Optimization guardrails

- Do not add a cross-request cache for current sessions, recent activity, incidents, audit events, or risk findings.
- Do not shrink evidence or skip a source to make an answer look faster.
- Do not increase limits without load, privacy, and provider-context review.
- If the budget ends first, preserve a `partial` status and disclose the boundary.
- Report correctness and latency together; performance is not improved if records or findings are lost.
