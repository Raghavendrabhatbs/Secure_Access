import sys
from datetime import datetime, timezone
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.adapters.warpgate.event_mapper import WarpgateEventMapper
from app.adapters.warpgate.recording_parser import WarpgateRecordingParser
from app.domain.session import SessionRecord


class EventMapperGoldenTest(unittest.TestCase):
    def test_event_counts_for_verified_recording(self):
        parser = WarpgateRecordingParser()
        fixture_path = (
            ROOT
            / "tests"
            / "fixtures"
            / "warpgate_recording_sample_71efcfa3.jsonl"
        )
        commands = parser.parse_file(
            file_path=str(fixture_path),
            recording_started_at=datetime(
                2026,
                8,
                3,
                5,
                59,
                11,
                571374,
                tzinfo=timezone.utc,
            ),
        )

        session = SessionRecord(
            session_id="d21a4035-7ecc-4e42-9feb-b9bf7f343d43",
            username="sumukh_bhat",
            protocol="ssh",
            remote_address="127.0.0.1",
            started_at=datetime(
                2026,
                8,
                3,
                5,
                59,
                11,
                571374,
                tzinfo=timezone.utc,
            ),
            ended_at=datetime(
                2026,
                8,
                3,
                6,
                0,
                2,
                722643,
                tzinfo=timezone.utc,
            ),
            recording_id="71efcfa3-bec8-4a1a-b5ca-e06a98b64034",
            recording_path="/data/recordings/d21a4035-7ecc-4e42-9feb-b9bf7f343d43/71efcfa3-bec8-4a1a-b5ca-e06a98b64034",
        )

        events = WarpgateEventMapper.map(session=session, commands=commands)
        event_types = [event.event_type for event in events]

        self.assertEqual(event_types.count("session_started"), 1)
        self.assertEqual(event_types.count("recording_attached"), 1)
        self.assertEqual(event_types.count("session_ended"), 1)
        self.assertEqual(event_types.count("command_executed"), 4)
        self.assertEqual(len(events), 7)


if __name__ == "__main__":
    unittest.main()
