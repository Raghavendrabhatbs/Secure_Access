import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / ".env")
load_dotenv(PROJECT_ROOT / "services" / "api" / ".env")

from app.adapters.warpgate.event_mapper import WarpgateEventMapper
from app.adapters.warpgate.mapper import WarpgateSessionMapper
from app.adapters.warpgate.recording_mapper import WarpgateRecordingMapper
from app.adapters.warpgate.recording_parser import WarpgateRecordingParser
from app.adapters.warpgate.recording_repository import WarpgateRecordingRepository
from app.adapters.warpgate.sqlite_reader import WarpgateSQLiteReader
from app.domain.command import ParsedCommand
from app.domain.recording import RecordingRecord
from app.domain.session import SessionRecord
from app.repositories.command_repository import CommandRepository
from app.repositories.event_repository import EventRepository
from app.repositories.session_repository import SessionRepository
from shared.db.database import create_database_engine, create_session_factory
from shared.risk.aggregator import aggregate_session_risks
from shared.risk.classifier import classify_command_risks


def _get_database_path() -> str:
    return os.getenv(
        "WARPGATE_DB_PATH",
        r"/opt/nokia-ssh/warpgate_data/db/db.sqlite3",
    )


def _get_postgres_settings() -> tuple[str, int, str, str, str]:
    return (
        os.getenv("POSTGRES_HOST", "localhost"),
        int(os.getenv("POSTGRES_PORT", "5432")),
        os.getenv("POSTGRES_DB", "nokia_ssh"),
        os.getenv("POSTGRES_USER", "nokia"),
        os.getenv("POSTGRES_PASSWORD", "nokia123"),
    )


def _get_recordings_root() -> str:
    return os.getenv(
        "WARPGATE_RECORDINGS_ROOT",
        "/data/recordings",
    )


def _get_recordings_host_root() -> str | None:
    return os.getenv("WARPGATE_RECORDINGS_HOST_ROOT")


def _get_prompt_suffixes() -> tuple[str, ...]:
    raw = os.getenv("WARPGATE_PROMPT_SUFFIXES")
    if not raw:
        return ("$ ", "# ")

    suffixes = tuple(
        value for value in (x.lstrip() for x in raw.split(",")) if value
    )
    return suffixes or ("$ ", "# ")


def _get_prompt_regexes() -> tuple[str, ...]:
    raw = os.getenv("WARPGATE_PROMPT_REGEXES")
    if not raw:
        return ()

    return tuple(value for value in (x.strip() for x in raw.split(",")) if value)


def _resolve_recording_path_for_runtime(
    recording_path: str,
    container_root: str,
    host_root: str | None,
) -> str:
    if host_root is None:
        return recording_path

    normalized_container_root = container_root.rstrip("/")
    if recording_path.startswith(normalized_container_root + "/"):
        suffix = recording_path[len(normalized_container_root) + 1 :]
        return os.path.join(host_root, suffix)

    return recording_path


def _select_latest_recordings(
    recordings: list[RecordingRecord],
) -> dict[str, RecordingRecord]:
    selected: dict[str, RecordingRecord] = {}

    for recording in recordings:
        existing = selected.get(recording.session_id)

        if existing is None:
            selected[recording.session_id] = recording
            continue

        existing_started = existing.started_at
        candidate_started = recording.started_at

        if existing_started is None and candidate_started is not None:
            selected[recording.session_id] = recording
            continue

        if (
            existing_started is not None
            and candidate_started is not None
            and candidate_started > existing_started
        ):
            selected[recording.session_id] = recording

    return selected


def _enrich_sessions_with_recordings(
    sessions: list[SessionRecord],
    recordings: dict[str, RecordingRecord],
) -> list[SessionRecord]:
    enriched: list[SessionRecord] = []

    for session in sessions:
        recording = recordings.get(session.session_id)

        if recording is None:
            enriched.append(session)
            continue

        enriched.append(
            SessionRecord(
                session_id=session.session_id,
                username=session.username,
                protocol=session.protocol,
                remote_address=session.remote_address,
                started_at=recording.started_at or session.started_at,
                ended_at=recording.ended_at or session.ended_at,
                recording_id=recording.recording_id,
                recording_path=recording.recording_path,
            )
        )

    return enriched


def run_ingestion(limit: int = 10000) -> dict[str, int]:
    reader = WarpgateSQLiteReader(_get_database_path())
    rows = reader.get_recent_sessions(limit=limit)
    sessions = [WarpgateSessionMapper.map(row) for row in rows]

    recording_repository = WarpgateRecordingRepository(_get_database_path())
    recording_rows = recording_repository.get_recent_recordings(
        limit=max(limit * 5, 100)
    )
    recording_root = _get_recordings_root()
    recording_records = [
        WarpgateRecordingMapper.map(
            row,
            recordings_root=recording_root,
        )
        for row in recording_rows
    ]
    selected_recordings = _select_latest_recordings(recording_records)
    sessions = _enrich_sessions_with_recordings(
        sessions,
        selected_recordings,
    )

    host, port, database, username, password = _get_postgres_settings()
    engine = create_database_engine(host, port, database, username, password)
    session_factory = create_session_factory(engine)
    session_repository = SessionRepository(session_factory)
    command_repository = CommandRepository(session_factory)
    event_repository = EventRepository(session_factory)
    parser = WarpgateRecordingParser(
        prompt_suffixes=_get_prompt_suffixes(),
        prompt_regexes=_get_prompt_regexes(),
    )

    upserted_session_ids = session_repository.upsert_sessions(sessions)

    upserted_commands = 0
    upserted_events = 0
    host_recordings_root = _get_recordings_host_root()

    for session in sessions:
        if not session.recording_path:
            continue

        runtime_recording_path = _resolve_recording_path_for_runtime(
            recording_path=session.recording_path,
            container_root=recording_root,
            host_root=host_recordings_root,
        )

        if not os.path.exists(runtime_recording_path):
            continue

        commands: list[ParsedCommand] = parser.parse_file(
            file_path=runtime_recording_path,
            recording_started_at=session.started_at,
        )
        upserted_commands += command_repository.upsert_commands(
            session_id=session.session_id,
            commands=commands,
        )

        events = WarpgateEventMapper.map(session=session, commands=commands)
        upserted_events += event_repository.upsert_events(
            session_id=session.session_id,
            events=events,
        )

        commands_data = [command.command for command in commands]
        flagged_data = [
            {
                "command": command.command,
                "category": finding.category,
                "severity": finding.severity,
                "rule": finding.rule,
            }
            for command in commands
            for finding in classify_command_risks(command.command)
        ]
        summary = aggregate_session_risks(
            [
                finding
                for command in commands
                for finding in classify_command_risks(command.command)
            ]
        )
        session_repository.update_session_summary(
            session_id=session.session_id,
            total_commands=len(commands),
            commands=commands_data,
            flagged=flagged_data,
            risk=summary.overall_severity,
        )

    return {
        "sessions": len(upserted_session_ids),
        "commands": upserted_commands,
        "events": upserted_events,
    }


def main() -> None:
    stats = run_ingestion(limit=10000)
    print(
        "Ingestion service started; "
        f"upserted {stats['sessions']} sessions and "
        f"{stats['commands']} commands and "
        f"{stats['events']} events"
    )


if __name__ == "__main__":
    main()
