from datetime import datetime

from pydantic import BaseModel, ConfigDict


class CommandRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    sequence_number: int
    command: str
    output: str | None = None
    executed_at: datetime | None = None
    exit_code: int | None = None
