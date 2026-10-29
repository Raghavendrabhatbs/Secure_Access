from __future__ import annotations

from collections.abc import Sequence
from typing import Any


_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def format_first_risky_timeline_entry(
    timeline: Sequence[dict[str, Any]] | None,
) -> str:
    """Return the chronologically first timeline entry that carries a risk finding."""
    entries = list(timeline or [])
    if not entries:
        return "No timeline entries were identified in the retrieved session evidence."

    for entry in entries:
        findings = list(entry.get("risk_findings", []) or [])
        if not findings:
            continue

        command_text = str(entry.get("command", "") or "").strip()
        categories = sorted(
            {str(finding.get("category", "")).strip() for finding in findings if finding.get("category")}
        )
        top_severity = min(
            (str(finding.get("severity", "")).upper() for finding in findings),
            key=lambda severity: _SEVERITY_ORDER.get(severity, len(_SEVERITY_ORDER)),
            default="",
        )

        lines = ["First risky action:", "", f"Command: {command_text}"]
        if top_severity:
            lines.append(f"Risk: {top_severity}")
        if categories:
            lines.append(f"Category: {', '.join(categories)}")
        return "\n".join(lines)

    return "No risky timeline entries were identified in the retrieved session evidence."


def format_when_risk_occurred(
    timeline: Sequence[dict[str, Any]] | None,
    category: str,
) -> str:
    """Return every chronologically ordered occurrence of a risk category, with timestamps."""
    entries = list(timeline or [])
    normalized_category = (category or "").strip().upper()
    if not normalized_category:
        return "No risk category was recognized in the question."

    occurrences: list[dict[str, Any]] = []
    for entry in entries:
        for finding in entry.get("risk_findings", []) or []:
            if str(finding.get("category", "")).strip().upper() == normalized_category:
                occurrences.append(
                    {
                        "timestamp": entry.get("timestamp"),
                        "command": str(entry.get("command", "") or "").strip(),
                        "severity": str(finding.get("severity", "")).upper(),
                    }
                )
                break

    if not occurrences:
        return f"No {normalized_category} findings were found in this session."

    lines = [f"{normalized_category} occurred at:", ""]
    for index, occurrence in enumerate(occurrences, start=1):
        timestamp = occurrence["timestamp"]
        timestamp_text = str(timestamp) if timestamp is not None else "unknown"
        lines.append(f"{index}. {timestamp_text}")
        lines.append(f"   Command: {occurrence['command']}")
        lines.append(f"   Risk: {occurrence['severity']}")
        lines.append(f"   Category: {normalized_category}")

    return "\n".join(lines)


def format_last_command_entry(
    timeline: Sequence[dict[str, Any]] | None,
) -> str:
    """Return the chronologically last COMMAND entry, ignoring trailing session events."""
    entries = list(timeline or [])
    if not entries:
        return "No timeline entries were identified in the retrieved session evidence."

    for entry in reversed(entries):
        if str(entry.get("event_type", "") or "").upper() == "COMMAND":
            command_text = str(entry.get("command", "") or "").strip()
            return f"Last command:\n\n{command_text}"

    return "No commands were identified in the retrieved session evidence."


def find_timeline_anchor_index(
    timeline: Sequence[dict[str, Any]] | None,
    command_text: str,
) -> int | None:
    """Return the index of the COMMAND entry exactly matching command_text, or None if absent."""
    entries = list(timeline or [])
    normalized_anchor = (command_text or "").strip().lower()
    if not normalized_anchor:
        return None

    for index, entry in enumerate(entries):
        if str(entry.get("event_type", "") or "").upper() != "COMMAND":
            continue
        entry_command = str(entry.get("command", "") or "").strip().lower()
        if entry_command == normalized_anchor:
            return index

    return None


def format_timeline_relative_to_command(
    timeline: Sequence[dict[str, Any]] | None,
    command_text: str,
    direction: str,
) -> str:
    """Return timeline entries strictly before/after a literal command anchor."""
    entries = list(timeline or [])
    anchor_text = (command_text or "").strip()
    relation_normalized = (direction or "").strip().lower()

    if not entries:
        return "No timeline entries were identified in the retrieved session evidence."

    anchor_index = find_timeline_anchor_index(entries, anchor_text)
    if anchor_index is None:
        return f'I couldn\'t find the command "{anchor_text}" in this session timeline.'

    if relation_normalized == "before":
        subset = entries[:anchor_index]
        if not subset:
            return f'No entries occurred before "{anchor_text}".'
        heading = f'Entries before "{anchor_text}":'
    else:
        subset = entries[anchor_index + 1 :]
        if not subset:
            return f'No entries occurred after "{anchor_text}".'
        heading = f'Entries after "{anchor_text}":'

    lines: list[str] = [heading, ""]
    for index, entry in enumerate(subset, start=1):
        lines.extend(_format_entry(index, entry))

    return "\n".join(lines)


def format_timeline_summary(
    timeline: Sequence[dict[str, Any]] | None,
    analysis: dict[str, Any] | None,
) -> str:
    entries = list(timeline or [])
    summary = analysis or {}

    if not entries:
        return "No timeline entries were identified in the retrieved session evidence."

    lines: list[str] = ["Session timeline:", ""]
    for index, entry in enumerate(entries, start=1):
        lines.extend(_format_entry(index, entry))

    lines.append("")
    lines.append(f"Overall risk: {summary.get('overall_severity', 'NONE')}")
    lines.append(
        "Entries: "
        f"{summary.get('entry_count', 0)}; "
        f"Commands: {summary.get('command_count', 0)}; "
        f"Events: {summary.get('event_count', 0)}"
    )

    categories = list(summary.get("risk_categories", []) or [])
    if categories:
        lines.append(f"Risk categories: {', '.join(categories)}")

    return "\n".join(lines)


def format_timeline_relative_to_risk(
    timeline: Sequence[dict[str, Any]] | None,
    analysis: dict[str, Any] | None,
    risk_category: str,
    relation: str,
) -> str:
    entries = list(timeline or [])
    normalized_category = (risk_category or "").strip().upper()
    relation_normalized = (relation or "").strip().lower()

    if not entries:
        return "No timeline entries were identified in the retrieved session evidence."

    match_index = _first_entry_index_with_category(entries, normalized_category)
    if match_index is None:
        return (
            f"No timeline entries with {normalized_category} were identified "
            "in the retrieved session evidence."
        )

    if relation_normalized == "before":
        subset = entries[:match_index]
        if not subset:
            return f"No timeline entries occurred before the first {normalized_category} finding."
        heading = f"Timeline entries before the first {normalized_category} finding:"
    else:
        subset = entries[match_index + 1 :]
        if not subset:
            return f"No timeline entries occurred after the first {normalized_category} finding."
        heading = f"Timeline entries after the first {normalized_category} finding:"

    lines: list[str] = [heading, ""]
    for index, entry in enumerate(subset, start=1):
        lines.extend(_format_entry(index, entry))

    summary = analysis or {}
    lines.append("")
    lines.append(f"Overall risk: {summary.get('overall_severity', 'NONE')}")
    return "\n".join(lines)


def _first_entry_index_with_category(entries: list[dict[str, Any]], category: str) -> int | None:
    for index, entry in enumerate(entries):
        for finding in entry.get("risk_findings", []) or []:
            if str(finding.get("category", "")).upper() == category:
                return index
    return None


def _format_entry(index: int, entry: dict[str, Any]) -> list[str]:
    timestamp = entry.get("timestamp")
    timestamp_text = str(timestamp) if timestamp is not None else "unknown"
    event_type = str(entry.get("event_type", "") or "")
    command_text = str(entry.get("command", "") or "").strip()

    if event_type == "COMMAND":
        line = f"{index}. {timestamp_text} - {command_text or '[command unavailable]'}"
    else:
        line = f"{index}. {timestamp_text} - {event_type or 'EVENT'}: {command_text or 'event'}"

    lines = [line]
    findings = entry.get("risk_findings", []) or []
    if findings:
        labels = [
            f"{finding.get('category', '')} / {str(finding.get('severity', '')).upper()}"
            for finding in findings
            if finding.get("category")
        ]
        if labels:
            lines.append(f"   Risk: {'; '.join(labels)}")

    return lines