import sys
from datetime import datetime, timezone
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.domain.session import SessionRecord
from app.repositories.session_repository import SessionRepository


class FakeSession:
    def __init__(self):
        self.added = []
        self._stores = {}
        self.committed = 0

    def add(self, obj):
        self.added.append(obj)

    def get(self, model, key):
        return self._stores.get((model.__name__, key))

    def commit(self):
        self.committed += 1
        for obj in self.added:
            self._stores[(obj.__class__.__name__, obj.unique_id)] = obj
        self.added.clear()

    def rollback(self):
        self.added.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            self.rollback()


class FakeSessionFactory:
    def __init__(self):
        self.session = FakeSession()

    def __call__(self):
        return self.session


class SessionRepositoryTest(unittest.TestCase):
    def test_upsert_sessions_is_idempotent(self):
        session_factory = FakeSessionFactory()
        repository = SessionRepository(session_factory)

        record = SessionRecord(
            session_id="session-123",
            username="alice",
            protocol="ssh",
            remote_address="10.0.0.5",
            started_at=datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc),
            ended_at=datetime(2026, 8, 8, 12, 10, tzinfo=timezone.utc),
        )

        first_result = repository.upsert_sessions([record])
        second_result = repository.upsert_sessions([record])

        self.assertEqual(first_result, ["session-123"])
        self.assertEqual(second_result, ["session-123"])
        self.assertEqual(session_factory.session.committed, 2)
        self.assertEqual(len(session_factory.session.added), 0)


if __name__ == "__main__":
    unittest.main()
