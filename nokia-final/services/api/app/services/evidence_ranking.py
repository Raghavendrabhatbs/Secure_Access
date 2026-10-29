from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any


def rank_command_matches(matches: Sequence[Any], search_terms: Sequence[str], limit: int | None = None) -> list[Any]:
    normalized_terms = _normalize_terms(search_terms)
    session_coverage: dict[str, set[str]] = {}
    for match in matches:
        session_id = getattr(match, "session_id", "")
        session_coverage.setdefault(session_id, set()).update(
            _matched_terms(match, normalized_terms)
        )
    ranked = sorted(
        matches,
        key=lambda match: (
            -len(session_coverage.get(getattr(match, "session_id", ""), set())),
            *_command_sort_key(match, normalized_terms),
        ),
    )
    if limit is None:
        return ranked
    return ranked[:limit]


def rank_session_matches(matches: Sequence[Any], search_terms: Sequence[str], limit: int | None = None) -> list[Any]:
    normalized_terms = _normalize_terms(search_terms)
    ranked: list[Any] = []

    for match in matches:
        matching_commands = list(getattr(match, "matching_commands", []))
        ranked_commands = rank_command_matches(matching_commands, normalized_terms)
        setattr(match, "matching_commands", ranked_commands)
        ranked.append(match)

    ranked.sort(key=lambda match: _session_sort_key(match, normalized_terms))
    if limit is None:
        return ranked
    return ranked[:limit]


def _session_sort_key(match: Any, search_terms: Sequence[str]) -> tuple[Any, ...]:
    commands = list(getattr(match, "matching_commands", []))
    matched_terms = getattr(match, "matched_terms", None) or _collect_matched_terms(commands)
    best_command_signal = max((_command_signal(command, search_terms) for command in commands), default=(0, 0, 0))
    best_command_text = min(
        ((getattr(command, "command", "") or "") for command in commands),
        default="",
    )
    earliest_sequence = min(
        (getattr(command, "sequence_number", 0) or 0 for command in commands),
        default=0,
    )
    return (
        -len(matched_terms),
        -best_command_signal[0],
        -best_command_signal[1],
        -best_command_signal[2],
        best_command_text,
        -len(commands),
        earliest_sequence,
        -_timestamp(getattr(match, "started_at", None)),
        getattr(match, "session_id", ""),
    )


def _command_sort_key(match: Any, search_terms: Sequence[str]) -> tuple[Any, ...]:
    command_hits, output_hits, matched_term_count = _command_signal(match, search_terms)
    return (
        -command_hits,
        -output_hits,
        -matched_term_count,
        getattr(match, "sequence_number", 0) or 0,
        -_timestamp(getattr(match, "started_at", None)),
        getattr(match, "session_id", ""),
        getattr(match, "command", "") or "",
    )


def _command_signal(match: Any, search_terms: Sequence[str]) -> tuple[int, int, int]:
    command_text = (getattr(match, "command", "") or "").lower()
    output_text = (getattr(match, "output", "") or "").lower()
    matched_terms = getattr(match, "matched_terms", None) or [
        term for term in search_terms if term in command_text or term in output_text
    ]

    command_hits = sum(1 for term in search_terms if term in command_text)
    output_hits = sum(1 for term in search_terms if term in output_text and term not in command_text)
    matched_term_count = len(matched_terms)
    return command_hits, output_hits, matched_term_count


def _matched_terms(match: Any, search_terms: Sequence[str]) -> list[str]:
    command_text = (getattr(match, "command", "") or "").lower()
    output_text = (getattr(match, "output", "") or "").lower()
    return [term for term in search_terms if term in command_text or term in output_text]


def _collect_matched_terms(commands: Sequence[Any]) -> list[str]:
    terms: list[str] = []
    for command in commands:
        for term in getattr(command, "matched_terms", []) or []:
            if term not in terms:
                terms.append(term)
    return terms


def _normalize_terms(search_terms: Sequence[str]) -> list[str]:
    normalized: list[str] = []
    for term in search_terms:
        normalized_term = term.strip().lower()
        if normalized_term and normalized_term not in normalized:
            normalized.append(normalized_term)
    return normalized


def _timestamp(value: datetime | None) -> float:
    return value.timestamp() if value is not None else 0.0