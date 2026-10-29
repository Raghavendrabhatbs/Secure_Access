from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from collections.abc import Sequence

from app.services.risk_aggregator import aggregate_session_risks
from app.services.risk_classifier import RiskFinding
from app.services.timeline import TimelineEntry, sort_timeline_entries


SIGNIFICANT_EVENT_TYPES = {
    "SESSION_STARTED",
    "SESSION_ENDED",
    "AUTHENTICATION",
    "DISCONNECT",
}


@dataclass(frozen=True)
class TimelineAnalysis:
    entry_count: int
    command_count: int
    event_count: int

    first_timestamp: datetime | None
    last_timestamp: datetime | None

    commands: tuple[str, ...]
    event_types: tuple[str, ...]

    risk_findings: tuple[RiskFinding, ...]
    high_count: int
    medium_count: int
    low_count: int
    risk_categories: tuple[str, ...]

    overall_severity: str
    significant_events: tuple[str, ...]


def analyze_timeline(entries: Sequence[TimelineEntry] | None) -> TimelineAnalysis:
    ordered = sort_timeline_entries(entries)

    command_entries = [entry for entry in ordered if entry.event_type == "COMMAND"]
    event_entries = [entry for entry in ordered if entry.event_type != "COMMAND"]

    commands = tuple(entry.command for entry in command_entries if entry.command)
    event_types = tuple(entry.event_type for entry in event_entries if entry.event_type)

    findings_list = [
        finding
        for entry in ordered
        for finding in (entry.risk_findings or ())
    ]
    risk_summary = aggregate_session_risks(findings_list)

    significant_events = _extract_significant_events(event_entries)

    timestamps = [entry.timestamp for entry in ordered if isinstance(entry.timestamp, datetime)]
    first_timestamp = timestamps[0] if timestamps else None
    last_timestamp = timestamps[-1] if timestamps else None

    return TimelineAnalysis(
        entry_count=len(ordered),
        command_count=len(command_entries),
        event_count=len(event_entries),
        first_timestamp=first_timestamp,
        last_timestamp=last_timestamp,
        commands=commands,
        event_types=event_types,
        risk_findings=tuple(findings_list),
        high_count=risk_summary.high_count,
        medium_count=risk_summary.medium_count,
        low_count=risk_summary.low_count,
        risk_categories=tuple(risk_summary.categories),
        overall_severity=risk_summary.overall_severity,
        significant_events=significant_events,
    )


def _extract_significant_events(entries: Sequence[TimelineEntry]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []

    for entry in entries:
        event_type = (entry.event_type or "").strip().upper()
        if event_type in SIGNIFICANT_EVENT_TYPES and event_type not in seen:
            seen.add(event_type)
            result.append(event_type)

    return tuple(result)
