import sqlite3
import uuid
from datetime import datetime
from typing import Any


class WarpgateSQLiteReader:
    def __init__(self, database_path: str):
        self.database_path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            f"file:{self.database_path}?mode=ro",
            uri=True,
        )

        connection.row_factory = sqlite3.Row

        return connection

    @staticmethod
    def _normalize_uuid(value: Any) -> str:
        if isinstance(value, bytes):
            return str(uuid.UUID(bytes=value))

        if isinstance(value, str):
            return str(uuid.UUID(value))

        raise ValueError(
            f"Unsupported Warpgate UUID type: {type(value).__name__}"
        )

    @staticmethod
    def _parse_timestamp(value: str | None) -> datetime | None:
        if value is None:
            return None

        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

    def get_recent_sessions(
        self,
        limit: int = 100,
    ) -> list[dict]:
        if limit <= 0:
            raise ValueError("limit must be greater than zero")

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    username,
                    remote_address,
                    started,
                    ended,
                    protocol
                FROM sessions
                ORDER BY started DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        sessions = []

        for row in rows:
            sessions.append(
                {
                    "id": self._normalize_uuid(row["id"]),
                    "username": row["username"],
                    "remote_address": row["remote_address"],
                    "started": self._parse_timestamp(row["started"]),
                    "ended": self._parse_timestamp(row["ended"]),
                    "protocol": row["protocol"],
                }
            )

        return sessions

    def get_recent_recordings(
        self,
        limit: int = 200,
    ) -> list[dict]:
        if limit <= 0:
            raise ValueError("limit must be greater than zero")

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    name,
                    started,
                    ended,
                    session_id,
                    kind,
                    metadata
                FROM recordings
                ORDER BY started DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        recordings = []

        for row in rows:
            recordings.append(
                {
                    "id": self._normalize_uuid(row["id"]),
                    "name": row["name"],
                    "started": self._parse_timestamp(row["started"]),
                    "ended": self._parse_timestamp(row["ended"]),
                    "session_id": self._normalize_uuid(row["session_id"]),
                    "kind": row["kind"],
                    "metadata": row["metadata"],
                }
            )

        return recordings
