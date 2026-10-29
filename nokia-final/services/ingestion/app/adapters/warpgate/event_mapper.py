from datetime import datetime, timezone
from hashlib import sha1

from app.domain.command import ParsedCommand
from app.domain.event import SessionEventRecord
from app.domain.session import SessionRecord

MANAGED_EVENT_TYPES = {
    "session_started",
    "session_ended",
    "recording_attached",
    "command_executed",
}


class WarpgateEventMapper:
    @staticmethod
    def map(
        session: SessionRecord,
        commands: list[ParsedCommand],
    ) -> list[SessionEventRecord]:
        events: list[SessionEventRecord] = []

        if session.started_at is not None:
            events.append(
                SessionEventRecord(
                    id=_event_id(
                        session.session_id,
                        "session_started",
                        session.started_at.isoformat(),
                    ),
                    event_type="session_started",
                    timestamp=session.started_at,
                    severity=None,
                    message="Session started",
                    payload={
                        "protocol": session.protocol,
                        "remote_address": session.remote_address,
                    },
                )
            )

        if session.recording_path and session.started_at is not None:
            events.append(
                SessionEventRecord(
                    id=_event_id(
                        session.session_id,
                        "recording_attached",
                        session.recording_id or session.recording_path,
                    ),
                    event_type="recording_attached",
                    timestamp=session.started_at,
                    severity=None,
                    message="Recording attached to session",
                    payload={
                        "recording_id": session.recording_id,
                        "recording_path": session.recording_path,
                    },
                )
            )

        for command in commands:
            timestamp = command.executed_at or session.started_at
            if timestamp is None:
                continue

            events.append(
                SessionEventRecord(
                    id=_event_id(
                        session.session_id,
                        "command_executed",
                        str(command.sequence_number),
                    ),
                    event_type="command_executed",
                    timestamp=timestamp,
                    severity=None,
                    message=f"Command executed: {command.command}",
                    payload={
                        "sequence_number": command.sequence_number,
                        "command": command.command,
                        "has_output": bool(command.output),
                    },
                )
            )

        if session.ended_at is not None:
            events.append(
                SessionEventRecord(
                    id=_event_id(
                        session.session_id,
                        "session_ended",
                        session.ended_at.isoformat(),
                    ),
                    event_type="session_ended",
                    timestamp=session.ended_at,
                    severity=None,
                    message="Session ended",
                    payload=None,
                )
            )

        events.sort(key=lambda x: x.timestamp)
        return events


def _event_id(session_id: str, event_type: str, key: str) -> str:
    digest = sha1(f"{session_id}|{event_type}|{key}".encode("utf-8")).hexdigest()
    return f"evt:{digest}"
