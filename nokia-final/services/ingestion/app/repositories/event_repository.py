from collections.abc import Callable

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as SqlAlchemySession

from app.adapters.warpgate.event_mapper import MANAGED_EVENT_TYPES
from app.domain.event import SessionEventRecord
from shared.models.event import Event as EventModel


class EventRepository:
    def __init__(self, session_factory: Callable[[], SqlAlchemySession]):
        self._session_factory = session_factory

    def upsert_events(
        self,
        session_id: str,
        events: list[SessionEventRecord],
    ) -> int:
        if not events:
            return 0

        db_session = self._session_factory()

        try:
            upserted = 0

            for event in events:
                existing = db_session.get(EventModel, event.id)

                if existing is None:
                    existing = EventModel(
                        id=event.id,
                        session_id=session_id,
                        event_type=event.event_type,
                        timestamp=event.timestamp,
                        severity=event.severity,
                        message=event.message,
                        payload=event.payload,
                    )
                    db_session.add(existing)
                else:
                    existing.session_id = session_id
                    existing.event_type = event.event_type
                    existing.timestamp = event.timestamp
                    existing.severity = event.severity
                    existing.message = event.message
                    existing.payload = event.payload

                upserted += 1

            event_ids = {event.id for event in events}
            db_session.execute(
                delete(EventModel).where(
                    EventModel.session_id == session_id,
                    EventModel.event_type.in_(MANAGED_EVENT_TYPES),
                    EventModel.id.not_in(event_ids),
                )
            )

            db_session.commit()
            return upserted
        except Exception:
            db_session.rollback()
            raise
