# Evaluation Dataset

Use synthetic or isolated fixtures for automated tests. Real system records, if used later, must be accessed read-only and only by an authorized identity.

| ID | Question | Expected route | Expected evidence and answer traits |
|---|---|---|---|
| E01 | How many unique SSH sessions were recorded today? | SSH count | Timezone-aware scope, logical identity, exact count, no command scan |
| E02 | Show yesterday's Web sessions | Web list | Correct local-date bounds, page status, Web metadata only |
| E03 | What happened in the latest SSH session? | Latest SSH detail | Correct protocol, ID, user, timestamps and available command evidence |
| E04 | What commands ran in session `<UUID>`? | Session command log | Only requested ID, stable order, completeness disclosed |
| E05 | What did `pwd` return in session `<UUID>`? | Command output | Matching input/output pair, no unrelated output |
| E06 | Which commands were flagged in the full SSH archive? | Archive risk | Full pagination or explicit partial status, authoritative rule labels |
| E07 | Why was session `<UUID>` marked HIGH? | Session risk explanation | Rule/category and timestamp, no unsupported compromise conclusion |
| E08 | Which browser actions were recorded for session `<web-id>`? | Web recording | Bounded activity stats, no DOM text/input values |
| E09 | Search gateway audit events for user `<name>` | Audit query | Admin/auditor only, UI/gateway sources distinguished, caps disclosed |
| E10 | Did the incident table record an alert for `<name>`? | Incident query | Optional source status, not conflated with audit events |
| E11 | What should I check if a new SSH session is missing from PostgreSQL? | Troubleshooting | Verified architecture separated from plausible hypotheses; safe checks |
| E12 | Explain that further | Context follow-up | Resolve only if previous assistant turn provides one clear referent |
| E13 | Why is it unavailable? | Clarify/context | Ask clarification if no unique source/session can be resolved |
| E14 | Explain authentication vs authorization | General technical | No private data tool call |
| E15 | What public cybersecurity news happened today? | Current public information | State live search availability; do not send private records to public search |

For each run record expected/actual intent, tool selection, source/scope, IDs/counts, completeness, factuality, uncertainty, provider calls, tool calls, evidence bytes, latency and errors. No evaluation results are claimed in this proposal.
