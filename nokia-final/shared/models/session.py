from datetime import datetime

from sqlalchemy import REAL, Date, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from shared.db.base import Base


class Session(Base):
	__tablename__ = "sessions"

	unique_id: Mapped[str] = mapped_column(
		Text,
		primary_key=True,
	)

	session_id: Mapped[str | None] = mapped_column(
		Text,
		nullable=True,
		index=True,
	)

	recording_id: Mapped[str | None] = mapped_column(
		Text,
		nullable=True,
	)

	session_type: Mapped[str | None] = mapped_column(
		Text,
		nullable=True,
		default="SSH",
	)

	username: Mapped[str | None] = mapped_column(
		Text,
		nullable=True,
	)

	target: Mapped[str | None] = mapped_column(
		Text,
		nullable=True,
	)

	login_time: Mapped[datetime | None] = mapped_column(
		DateTime,
		nullable=True,
	)

	logout_time: Mapped[datetime | None] = mapped_column(
		DateTime,
		nullable=True,
	)

	date: Mapped[datetime | None] = mapped_column(
		Date,
		nullable=True,
	)

	duration: Mapped[str | None] = mapped_column(
		Text,
		nullable=True,
	)

	duration_seconds: Mapped[float | None] = mapped_column(
		REAL,
		nullable=True,
	)

	total_commands: Mapped[int | None] = mapped_column(
		Integer,
		nullable=True,
		default=0,
	)

	commands: Mapped[list | None] = mapped_column(
		JSONB,
		nullable=True,
	)

	flagged: Mapped[list | None] = mapped_column(
		JSONB,
		nullable=True,
	)

	risk: Mapped[str | None] = mapped_column(
		Text,
		nullable=True,
	)

	created_at: Mapped[datetime | None] = mapped_column(
		DateTime,
		nullable=True,
	)

	protocol: Mapped[str | None] = mapped_column(
		String(50),
		nullable=True,
	)

	remote_address: Mapped[str | None] = mapped_column(
		String(255),
		nullable=True,
	)

	started_at: Mapped[datetime | None] = mapped_column(
		DateTime(timezone=True),
		nullable=True,
	)

	ended_at: Mapped[datetime | None] = mapped_column(
		DateTime(timezone=True),
		nullable=True,
	)

	recording_path: Mapped[str | None] = mapped_column(
		Text,
		nullable=True,
	)
