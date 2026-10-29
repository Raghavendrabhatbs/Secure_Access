import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from shared.db.base import Base


class Command(Base):
	__tablename__ = "session_commands"

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

	sequence_number: Mapped[int] = mapped_column(
		Integer,
		nullable=False,
	)

	command: Mapped[str] = mapped_column(
		Text,
		nullable=False,
	)

	output: Mapped[str | None] = mapped_column(
		Text,
		nullable=True,
	)

	executed_at: Mapped[datetime | None] = mapped_column(
		DateTime(timezone=True),
		nullable=True,
	)

	exit_code: Mapped[int | None] = mapped_column(
		Integer,
		nullable=True,
	)
