from app.domain.recording import RecordingRecord


class WarpgateRecordingMapper:
    @staticmethod
    def map(row: dict, recordings_root: str) -> RecordingRecord:
        session_id = row["session_id"]
        recording_id = row["name"]

        return RecordingRecord(
            session_id=session_id,
            recording_id=recording_id,
            recording_path=(
                f"{recordings_root.rstrip('/')}/{session_id}/{recording_id}/data.ndjson"
            ),
            started_at=row["started"],
            ended_at=row["ended"],
            kind=row["kind"],
            metadata=row["metadata"],
        )
