from collections.abc import Callable

from sqlalchemy.orm import Session as SqlAlchemySession

from app.domain.session import SessionRecord
from shared.models.session import Session as SessionModel


class SessionRepository:
    def __init__(self, session_factory: Callable[[], SqlAlchemySession]):
        self._session_factory = session_factory

    def upsert_sessions(self, records: list[SessionRecord]) -> list[str]:
        if not records:
            return []

        session = self._session_factory()

        try:
            inserted_ids: list[str] = []

            for record in records:
                existing = session.get(SessionModel, record.session_id)

                if existing is None:
                    existing = SessionModel(
                        unique_id=record.session_id,
                        session_id=record.session_id,
                        username=record.username,
                        protocol=record.protocol,
                        remote_address=record.remote_address,
                        started_at=record.started_at,
                        ended_at=record.ended_at,
                        recording_id=record.recording_id,
                        recording_path=record.recording_path,
                    )
                    session.add(existing)
                else:
                    existing.unique_id = record.session_id
                    existing.session_id = record.session_id
                    existing.username = record.username or existing.username
                    existing.protocol = record.protocol or existing.protocol
                    existing.remote_address = (
                        record.remote_address or existing.remote_address
                    )
                    existing.started_at = record.started_at or existing.started_at
                    existing.ended_at = record.ended_at or existing.ended_at
                    existing.recording_id = (
                        record.recording_id or existing.recording_id
                    )
                    existing.recording_path = (
                        record.recording_path or existing.recording_path
                    )

                inserted_ids.append(record.session_id)

            session.commit()
            return inserted_ids
        except Exception:
            session.rollback()
            raise

    def update_session_summary(
        self,
        session_id: str,
        total_commands: int,
        commands: list[str],
        flagged: list[dict],
        risk: str,
    ) -> None:
        db_session = self._session_factory()

        try:
            existing = db_session.get(SessionModel, session_id)

            if existing is None:
                return

            existing.total_commands = total_commands
            existing.commands = commands
            existing.flagged = flagged
            existing.risk = risk

            db_session.commit()
        except Exception:
            db_session.rollback()
            raise
        finally:
            db_session.close()
