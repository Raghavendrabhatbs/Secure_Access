import sys
from datetime import date
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.session_query_service import SessionQueryService


class SyntheticPagedSessionQueryService(SessionQueryService):
    def __init__(self, records):
        super().__init__(None)
        self.records = records
        self.offsets = []

    def list_sessions(self, limit=100, offset=0):
        self.offsets.append(offset)
        return self.records[offset : offset + limit]

    def list_sessions_started_between(self, start_date, end_date, limit=10000, offset=0):
        self.offsets.append(offset)
        return self.records[offset : offset + limit]


class SessionQueryPaginationTest(unittest.TestCase):
    def test_full_session_listing_reads_past_multiple_pages(self):
        records = [SimpleNamespace(unique_id=f"session-{index}") for index in range(2105)]
        service = SyntheticPagedSessionQueryService(records)

        result = service.list_all_sessions(page_size=700)

        self.assertEqual(len(result), 2105)
        self.assertEqual(service.offsets, [0, 700, 1400, 2100])

    def test_large_internal_session_limit_means_all_records(self):
        service = SessionQueryService(None)
        records = [SimpleNamespace(unique_id=f"session-{index}") for index in range(12005)]
        with patch.object(service, "list_all_sessions", return_value=records) as list_all:
            result = service.list_sessions(limit=10000, offset=5)
        list_all.assert_called_once_with()
        self.assertEqual(len(result), 12000)

    def test_full_date_listing_reads_past_multiple_pages(self):
        records = [SimpleNamespace(unique_id=f"session-{index}") for index in range(1801)]
        service = SyntheticPagedSessionQueryService(records)

        result = service.list_all_sessions_started_between(
            date(2026, 1, 1),
            date(2026, 12, 31),
            page_size=600,
        )

        self.assertEqual(len(result), 1801)
        self.assertEqual(service.offsets, [0, 600, 1200, 1800])


if __name__ == "__main__":
    unittest.main()
