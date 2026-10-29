from __future__ import annotations

import re


STOP_WORDS = {
    "a",
    "an",
    "and",
    "all",
    "are",
    "did",
    "everything",
    "find",
    "for",
    "from",
    "happened",
    "in",
    "list",
    "me",
    "modify",
    "of",
    "on",
    "show",
    "the",
    "to",
    "used",
    "use",
    "using",
    "was",
    "were",
    "what",
    "which",
    "where",
    "who",
    "with",
    "this",
    "commands",
    "command",
    "sessions",
    "session",
}

TEMPORAL_TOKENS = {
    "today",
    "yesterday",
    "tomorrow",
    "day",
    "days",
    "week",
    "weeks",
    "month",
    "months",
    "year",
    "years",
    "now",
    "till",
    "until",
    "since",
    "ago",
    "between",
    "before",
    "after",
    "this",
    "last",
    "next",
    "so",
    "far",
    "on",
    "at",
    "by",
    "through",
    "from",
    "to",
}

SESSION_ID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


def extract_search_terms(question: str) -> list[str]:
    """Extract deterministic search terms from a natural-language question."""

    if not question:
        return []

    question_lower = question.lower()
    tokens = re.findall(r'[/\w.-]+', question_lower)

    terms: list[str] = []

    for token in tokens:
        if token in STOP_WORDS or token in TEMPORAL_TOKENS:
            continue

        if SESSION_ID_RE.fullmatch(token):
            continue

        if re.fullmatch(r"\d{1,4}", token):
            continue

        if re.fullmatch(r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}", token):
            continue

        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", token):
            continue

        if len(token) < 2:
            continue

        if token not in terms:
            terms.append(token)

    return terms