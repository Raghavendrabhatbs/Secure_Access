import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from shared.db.base import Base


class Event(Base):
	__tablename__ = "session_events"

	id: Mapped[uuid.UUID] = mapped_column(
		Text,
		primary_key=True,
		default=lambda: str(uuid.uuid4()),
	)

	session_id: Mapped[str] = mapped_column(
		Text,
		ForeignKey("sessions.unique_id", ondelete="CASCADE"),
		nullable=False,
		index=True,
	)

	event_type: Mapped[str] = mapped_column(
		String(100),
		nullable=False,
		index=True,
	)

	timestamp: Mapped[datetime] = mapped_column(
		DateTime(timezone=True),
		nullable=False,
	)

	severity: Mapped[str | None] = mapped_column(
		String(20),
		nullable=True,
	)

	message: Mapped[str | None] = mapped_column(
		Text,
		nullable=True,
	)

	payload: Mapped[dict | None] = mapped_column(
		JSONB,
		nullable=True,
	)
