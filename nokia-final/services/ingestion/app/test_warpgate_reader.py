from app.adapters.warpgate.mapper import WarpgateSessionMapper
from app.adapters.warpgate.sqlite_reader import WarpgateSQLiteReader


DATABASE_PATH = r"C:\CHANGE_ME\warpgate_db.sqlite3"


def main():
    reader = WarpgateSQLiteReader(DATABASE_PATH)

    rows = reader.get_recent_sessions(limit=5)

    print()
    print("=" * 60)
    print("WARPGATE SESSION TEST")
    print("=" * 60)

    print(f"Sessions found: {len(rows)}")

    for row in rows:
        session = WarpgateSessionMapper.map(row)

        print()
        print("Session ID :", session.session_id)
        print("Username   :", session.username)
        print("Protocol   :", session.protocol)
        print("Remote     :", session.remote_address)
        print("Started    :", session.started_at)
        print("Ended      :", session.ended_at)


if __name__ == "__main__":
    main()
