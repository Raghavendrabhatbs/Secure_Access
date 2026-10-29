from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ParsedCommand:
    sequence_number: int
    command: str
    output: str | None
    executed_at: datetime | None
    exit_code: int | None = None
