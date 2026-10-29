from app.domain.session import SessionRecord


class WarpgateSessionMapper:

    @staticmethod
    def map(row: dict) -> SessionRecord:
        return SessionRecord(
            session_id=row["id"],
            username=row["username"],
            protocol=row["protocol"],
            remote_address=row["remote_address"],
            started_at=row["started"],
            ended_at=row["ended"],
        )
