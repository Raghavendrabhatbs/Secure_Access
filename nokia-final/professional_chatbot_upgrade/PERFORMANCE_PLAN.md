# Performance Plan

## Baseline

No latency or throughput benchmark was run. The observed 400 is a compatibility failure, not a measured performance problem. Disabling parallel tools for GPT-OSS can increase turns for multi-source questions; measure that tradeoff rather than making a speed claim.

## Measurements

Record privacy-safe metrics:

- Total latency and provider completion count/duration.
- Tool count/name/duration and success category.
- Pages/rows returned and completion status.
- Sanitized evidence byte count and truncation status.
- Provider HTTP status/error category.

Never use prompts, command text/output, session IDs, cookies, credentials, or raw recordings as logs or metric labels.

## Benchmark method

Run the same representative fixture and configured model before/after. Separate:

1. Count/exact-ID questions.
2. One-session command/output lookup.
3. Multi-tool cross-source investigation.
4. Archive-wide risk and Web recording pagination.

Report median/p95, provider calls, tool calls, record/pages and evidence size. Run at least 20 warm repetitions where a stable test environment permits. Compare correctness and completeness with latency.

## Optimization guardrails

- Keep dependent pagination serial.
- Parallelize only where model capability and source capacity both allow it.
- Do not cache live security evidence across requests.
- Do not remove required sources to reduce latency.
- Explicitly report partial results when budgets end before completion.
- Profile archive database operations before changing query plans or adding indexes.
