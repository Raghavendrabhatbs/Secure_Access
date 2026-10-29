"""Seed the dedicated test database with the two deterministic fixture sessions
used across the integration test suite. Safe to re-run (idempotent upsert).

Usage:
    $env:PYTHONPATH="<repo root>"
    $env:POSTGRES_DB="nokia_ssh_test"
    python tests/seed_test_fixtures.py
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

API_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = API_ROOT.parents[1]
for import_root in (PROJECT_ROOT, API_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from app.core.config import settings
from shared.db.base import Base
from shared.db.database import create_database_engine, create_session_factory
from shared.models.command import Command
from shared.models.event import Event
from shared.models.session import Session as SessionModel


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(timezone.utc)


SESSIONS = [
    {
        "unique_id": "d21a4035-7ecc-4e42-9feb-b9bf7f343d43",
        "session_id": "d21a4035-7ecc-4e42-9feb-b9bf7f343d43",
        "username": "admin",
        "protocol": "SSH",
        "remote_address": "[::ffff:172.18.0.1]:56448",
        "started_at": _dt("2026-08-03 05:59:11.571374+00:00"),
        "ended_at": _dt("2026-08-03 06:00:02.722643+00:00"),
        "recording_id": "71efcfa3-bec8-4a1a-b5ca-e06a98b64034",
        "recording_path": "/data/recordings/d21a4035-7ecc-4e42-9feb-b9bf7f343d43/71efcfa3-bec8-4a1a-b5ca-e06a98b64034",
        "session_type": "SSH",
    },
    {
        "unique_id": "f9ba2142-8680-40e9-bebe-cc7ba5806af8",
        "session_id": "f9ba2142-8680-40e9-bebe-cc7ba5806af8",
        "username": "admin",
        "protocol": "SSH",
        "remote_address": "[::ffff:172.18.0.1]:47822",
        "started_at": _dt("2026-07-30 06:01:40.043002+00:00"),
        "ended_at": _dt("2026-08-03 05:14:58.788659+00:00"),
        "recording_id": "a9573cac-8f98-4d63-85b9-b938c83eb788",
        "recording_path": "/data/recordings/f9ba2142-8680-40e9-bebe-cc7ba5806af8/a9573cac-8f98-4d63-85b9-b938c83eb788",
        "session_type": "SSH",
    },
    {
        "unique_id": "79a6a8f5-4e28-4a1d-8e85-2df716113d8b",
        "session_id": "79a6a8f5-4e28-4a1d-8e85-2df716113d8b",
        "username": "admin",
        "protocol": "SSH",
        "remote_address": "[::ffff:172.18.0.1]:50001",
        "started_at": _dt("2026-08-20 09:00:00+00:00"),
        "ended_at": _dt("2026-08-20 09:15:00+00:00"),
        "session_type": "SSH",
    },
    {
        "unique_id": "f331c40a-c366-464c-ad60-2001c01d517e",
        "session_id": "f331c40a-c366-464c-ad60-2001c01d517e",
        "username": "operator",
        "protocol": "SSH",
        "remote_address": "[::ffff:172.18.0.1]:50002",
        "started_at": _dt("2026-08-20 12:00:00+00:00"),
        "ended_at": _dt("2026-08-20 12:10:00+00:00"),
        "session_type": "SSH",
    },
    {
        "unique_id": "4c1a3d9e-6b7f-4e2a-9c11-8d5f0a2b7e44",
        "session_id": "4c1a3d9e-6b7f-4e2a-9c11-8d5f0a2b7e44",
        "username": "admin",
        "protocol": "SSH",
        "remote_address": "[::ffff:172.18.0.1]:50003",
        "started_at": _dt("2026-08-20 15:00:00+00:00"),
        "ended_at": _dt("2026-08-20 15:20:00+00:00"),
        "session_type": "SSH",
    },
    {
        "unique_id": "b7e2f4c8-1a6d-4f30-8b95-2c7e9d0a5f61",
        "session_id": "b7e2f4c8-1a6d-4f30-8b95-2c7e9d0a5f61",
        "username": "admin",
        "protocol": "SSH",
        "remote_address": "[::ffff:172.18.0.1]:50004",
        "started_at": _dt("2026-08-20 18:00:00+00:00"),
        "ended_at": _dt("2026-08-20 18:05:00+00:00"),
        "session_type": "SSH",
    },
]

COMMANDS = [
    ("d21a4035-7ecc-4e42-9feb-b9bf7f343d43", 1, "whoami", "sumukh_bhat", "2026-08-03 05:59:38.923924+00:00"),
    ("d21a4035-7ecc-4e42-9feb-b9bf7f343d43", 2, "hostname", "DESKTOP-L7RS68G", "2026-08-03 05:59:42.297271+00:00"),
    ("d21a4035-7ecc-4e42-9feb-b9bf7f343d43", 3, "date", "Mon Aug  3 05:59:48 UTC 2026", "2026-08-03 05:59:48.327914+00:00"),
    ("d21a4035-7ecc-4e42-9feb-b9bf7f343d43", 4, 'echo "test august 3"', "test august 3", "2026-08-03 06:00:00.275289+00:00"),
    ("f9ba2142-8680-40e9-bebe-cc7ba5806af8", 1, "sudo su -", "[sudo] password for sumukh_bhat: ", "2026-07-30 06:01:50.166587+00:00"),
    ("f9ba2142-8680-40e9-bebe-cc7ba5806af8", 2, "sudo useradd hacker123", None, "2026-07-30 06:02:07.285386+00:00"),
    ("f9ba2142-8680-40e9-bebe-cc7ba5806af8", 3, "chmod 777 /etc/passwd", None, "2026-07-30 06:02:20.394114+00:00"),
    ("f9ba2142-8680-40e9-bebe-cc7ba5806af8", 4, "history -c", None, "2026-07-30 06:02:27.33776+00:00"),
    ("79a6a8f5-4e28-4a1d-8e85-2df716113d8b", 1, "whoami", "admin", "2026-08-20 09:00:10+00:00"),
    ("79a6a8f5-4e28-4a1d-8e85-2df716113d8b", 2, "sudo -n true", None, "2026-08-20 09:01:00+00:00"),
    ("f331c40a-c366-464c-ad60-2001c01d517e", 1, "whoami", "operator", "2026-08-20 12:00:10+00:00"),
    ("f331c40a-c366-464c-ad60-2001c01d517e", 2, "hostname", "TEST-HOST", "2026-08-20 12:00:20+00:00"),
    ("4c1a3d9e-6b7f-4e2a-9c11-8d5f0a2b7e44", 1, "ls", "", "2026-08-20 15:00:10+00:00"),
    ("b7e2f4c8-1a6d-4f30-8b95-2c7e9d0a5f61", 1, "sudo", None, "2026-08-20 18:00:10+00:00"),
]

EVENTS = [
    ("d21a4035-7ecc-4e42-9feb-b9bf7f343d43", "session_started", "2026-08-03 05:59:11.571374+00:00", "Session started"),
    ("d21a4035-7ecc-4e42-9feb-b9bf7f343d43", "recording_attached", "2026-08-03 05:59:11.571374+00:00", "Recording attached to session"),
    ("d21a4035-7ecc-4e42-9feb-b9bf7f343d43", "command_executed", "2026-08-03 05:59:38.923924+00:00", "Command executed: whoami"),
    ("d21a4035-7ecc-4e42-9feb-b9bf7f343d43", "command_executed", "2026-08-03 05:59:42.297271+00:00", "Command executed: hostname"),
    ("d21a4035-7ecc-4e42-9feb-b9bf7f343d43", "command_executed", "2026-08-03 05:59:48.327914+00:00", "Command executed: date"),
    ("d21a4035-7ecc-4e42-9feb-b9bf7f343d43", "command_executed", "2026-08-03 06:00:00.275289+00:00", 'Command executed: echo "test august 3"'),
    ("d21a4035-7ecc-4e42-9feb-b9bf7f343d43", "session_ended", "2026-08-03 06:00:02.722643+00:00", "Session ended"),
    ("f9ba2142-8680-40e9-bebe-cc7ba5806af8", "session_started", "2026-07-30 06:01:40.043002+00:00", "Session started"),
    ("f9ba2142-8680-40e9-bebe-cc7ba5806af8", "recording_attached", "2026-07-30 06:01:40.043002+00:00", "Recording attached to session"),
    ("f9ba2142-8680-40e9-bebe-cc7ba5806af8", "command_executed", "2026-07-30 06:01:50.166587+00:00", "Command executed: sudo su -"),
    ("f9ba2142-8680-40e9-bebe-cc7ba5806af8", "command_executed", "2026-07-30 06:02:07.285386+00:00", "Command executed: sudo useradd hacker123"),
    ("f9ba2142-8680-40e9-bebe-cc7ba5806af8", "command_executed", "2026-07-30 06:02:20.394114+00:00", "Command executed: chmod 777 /etc/passwd"),
    ("f9ba2142-8680-40e9-bebe-cc7ba5806af8", "command_executed", "2026-07-30 06:02:27.33776+00:00", "Command executed: history -c"),
    ("f9ba2142-8680-40e9-bebe-cc7ba5806af8", "session_ended", "2026-08-03 05:14:58.788659+00:00", "Session ended"),
]


def seed(engine) -> None:
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    db = session_factory()

    try:
        db.query(Event).delete()
        db.query(Command).delete()
        db.query(SessionModel).delete()
        db.commit()

        for row in SESSIONS:
            db.add(SessionModel(**row))
        db.flush()

        for session_id, seq, command, output, executed_at in COMMANDS:
            db.add(
                Command(
                    id=f"{session_id}:{seq}",
                    session_id=session_id,
                    sequence_number=seq,
                    command=command,
                    output=output,
                    executed_at=_dt(executed_at),
                )
            )
        db.flush()

        for index, (session_id, event_type, timestamp, message) in enumerate(EVENTS, start=1):
            db.add(
                Event(
                    id=f"evt:{session_id}:{index}",
                    session_id=session_id,
                    event_type=event_type,
                    timestamp=_dt(timestamp),
                    message=message,
                )
            )

        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def main() -> None:
    engine = create_database_engine(
        settings.postgres_host,
        settings.postgres_port,
        "nokia_ssh_test",
        settings.postgres_user,
        settings.postgres_password,
    )
    seed(engine)
    print("Seeded test fixtures into nokia_ssh_test.")


if __name__ == "__main__":
    main()
