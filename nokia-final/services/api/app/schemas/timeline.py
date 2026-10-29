from datetime import datetime

from pydantic import BaseModel

from app.schemas.command import CommandRead
from app.schemas.event import EventRead
from app.schemas.session import SessionDetail


class SessionTimeline(BaseModel):
    session: SessionDetail
    commands: list[CommandRead]
    events: list[EventRead]
    started_at: datetime | None = None
    ended_at: datetime | None = None
