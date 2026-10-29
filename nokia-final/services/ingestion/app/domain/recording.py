from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class RecordingRecord:
    session_id: str
    recording_id: str
    recording_path: str
    started_at: datetime | None
    ended_at: datetime | None
    kind: str | None
    metadata: str | None
