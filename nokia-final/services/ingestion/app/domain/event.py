from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class SessionEventRecord:
    id: str
    event_type: str
    timestamp: datetime
    severity: str | None
    message: str | None
    payload: dict | None
