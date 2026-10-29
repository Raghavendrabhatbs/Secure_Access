import sys
from datetime import datetime, timezone
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.adapters.warpgate.event_mapper import WarpgateEventMapper
from app.domain.command import ParsedCommand
from app.domain.session import SessionRecord


class EventMapperTest(unittest.TestCase):
    def test_maps_session_and_command_events(self):
        session = SessionRecord(
            session_id="s-1",
            username="alice",
            protocol="ssh",
            remote_address="10.0.0.1",
            started_at=datetime(2026, 8, 8, 10, 0, tzinfo=timezone.utc),
            ended_at=datetime(2026, 8, 8, 10, 5, tzinfo=timezone.utc),
            recording_id="r-1",
            recording_path="/data/recordings/s-1/r-1",
        )

        commands = [
            ParsedCommand(
                sequence_number=1,
                command="whoami",
                output="alice",
                executed_at=datetime(2026, 8, 8, 10, 1, tzinfo=timezone.utc),
            ),
            ParsedCommand(
                sequence_number=2,
                command="hostname",
                output="host1",
                executed_at=datetime(2026, 8, 8, 10, 2, tzinfo=timezone.utc),
            ),
        ]

        events = WarpgateEventMapper.map(session=session, commands=commands)

        self.assertEqual([event.event_type for event in events], [
            "session_started",
            "recording_attached",
            "command_executed",
            "command_executed",
            "session_ended",
        ])

        self.assertEqual(events[2].payload["sequence_number"], 1)
        self.assertEqual(events[3].payload["sequence_number"], 2)
        self.assertEqual(events[2].payload["command"], "whoami")


if __name__ == "__main__":
    unittest.main()
