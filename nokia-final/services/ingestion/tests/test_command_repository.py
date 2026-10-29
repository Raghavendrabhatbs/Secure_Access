import sys
from pathlib import Path
import unittest
from unittest.mock import Mock

SERVICE_ROOT = Path(__file__).resolve().parents[1]
if str(SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVICE_ROOT))

from app.repositories.command_repository import CommandRepository


class CommandRepositoryTest(unittest.TestCase):
    def test_empty_reparse_deletes_stale_commands(self):
        db_session = Mock()
        repository = CommandRepository(lambda: db_session)

        updated = repository.upsert_commands("session-1", [])

        self.assertEqual(updated, 0)
        db_session.execute.assert_called_once()
        db_session.commit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
