from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SessionSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    session_id: str
    unique_id: str
    username: str | None = None
    protocol: str | None = None
    remote_address: str | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    recording_id: str | None = None
    recording_path: str | None = None
    total_commands: int | None = None


class SessionDetail(SessionSummary):
    session_type: str | None = None
    target: str | None = None
    login_time: datetime | None = None
    logout_time: datetime | None = None
    duration: str | None = None
    duration_seconds: float | None = None
    created_at: datetime | None = None
    risk: str | None = None
