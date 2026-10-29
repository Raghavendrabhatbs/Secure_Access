from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    username: str | None
    protocol: str
    remote_address: str
    started_at: datetime | None
    ended_at: datetime | None
    recording_id: str | None = None
    recording_path: str | None = None
