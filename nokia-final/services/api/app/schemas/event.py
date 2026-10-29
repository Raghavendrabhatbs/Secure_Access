from datetime import datetime

from pydantic import BaseModel, ConfigDict


class EventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    event_type: str
    timestamp: datetime
    severity: str | None = None
    message: str | None = None
    payload: dict | None = None
