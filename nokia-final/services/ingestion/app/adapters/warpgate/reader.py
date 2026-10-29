from typing import Protocol

from app.domain.session import SessionRecord


class WarpgateReader(Protocol):

    def get_recent_sessions(
        self,
        limit: int = 100,
    ) -> list[SessionRecord]:
        ...
