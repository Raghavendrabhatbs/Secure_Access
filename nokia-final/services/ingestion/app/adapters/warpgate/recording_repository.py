from app.adapters.warpgate.sqlite_reader import WarpgateSQLiteReader


class WarpgateRecordingRepository:
    def __init__(self, database_path: str):
        self._reader = WarpgateSQLiteReader(database_path)

    def get_recent_recordings(self, limit: int = 200) -> list[dict]:
        return self._reader.get_recent_recordings(limit=limit)
