from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from app.services.timeline import TimelineEntry, sort_timeline_entries


# Events of this type merely restate a command already present in session_commands;
# including both would duplicate the same action in the assembled timeline.
_COMMAND_ECHO_EVENT_TYPE = "command_executed"


def assemble_session_timeline(
    commands: Sequence[Any] | None,
    events: Sequence[Any] | None = None,
) -> list[TimelineEntry]:
    """Assemble a deterministic chronological timeline from command and event records."""
    entries: list[TimelineEntry] = []

    for item in commands or []:
        entries.append(
            TimelineEntry(
                timestamp=getattr(item, "executed_at", None),
                sequence_number=getattr(item, "sequence_number", None),
                event_type="COMMAND",
                command=getattr(item, "command", "") or "",
                output=getattr(item, "output", "") or "",
                risk_findings=tuple(getattr(item, "risk_findings", ()) or ()),
            )
        )

    for event in events or []:
        raw_event_type = str(getattr(event, "event_type", "") or "").strip()
        if raw_event_type.lower() == _COMMAND_ECHO_EVENT_TYPE:
            continue

        event_type = raw_event_type or "EVENT"
        entries.append(
            TimelineEntry(
                timestamp=getattr(event, "timestamp", None),
                sequence_number=_extract_event_sequence_number(event),
                event_type=event_type,
                command=_extract_event_command(event, event_type),
                output=_extract_event_output(event),
                risk_findings=(),
            )
        )

    return sort_timeline_entries(entries)


def _extract_event_sequence_number(event: Any) -> int | None:
    direct_sequence = getattr(event, "sequence_number", None)
    if isinstance(direct_sequence, int):
        return direct_sequence

    payload = getattr(event, "payload", None)
    if isinstance(payload, dict):
        for key in ("sequence_number", "sequence", "seq"):
            value = payload.get(key)
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)

    return None


def _extract_event_command(event: Any, event_type: str) -> str:
    message = getattr(event, "message", None)
    if message is not None:
        text = str(message).strip()
        if text:
            return text
    return event_type


def _extract_event_output(event: Any) -> str:
    payload = getattr(event, "payload", None)
    if payload is None:
        return ""

    if isinstance(payload, str):
        return payload

    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
    except TypeError:
        return str(payload)
