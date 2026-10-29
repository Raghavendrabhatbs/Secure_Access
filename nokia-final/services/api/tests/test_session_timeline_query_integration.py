import sys
from pathlib import Path
import unittest

API_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = API_ROOT.parent.parent

if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.database import SessionLocal
from app.services.session_query_service import SessionQueryService


class SessionTimelineQueryIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        self.service = SessionQueryService(self.db)
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def tearDown(self):
        self.db.close()

    def test_query_timeline_contains_required_fields(self):
        timeline = self.service.query_session_timeline(self.risky_session_id)

        self.assertTrue(timeline)
        first = timeline[0]

        self.assertTrue(hasattr(first, "timestamp"))
        self.assertTrue(hasattr(first, "sequence_number"))
        self.assertTrue(hasattr(first, "event_type"))
        self.assertTrue(hasattr(first, "command"))
        self.assertTrue(hasattr(first, "output"))
        self.assertTrue(hasattr(first, "risk_findings"))

    def test_query_timeline_is_chronological(self):
        timeline = self.service.query_session_timeline(self.risky_session_id)

        for index in range(len(timeline) - 1):
            current = timeline[index]
            following = timeline[index + 1]
            if current.timestamp is None or following.timestamp is None:
                continue
            self.assertLessEqual(current.timestamp, following.timestamp)
            if current.timestamp == following.timestamp:
                self.assertLessEqual(
                    current.sequence_number or 10**9,
                    following.sequence_number or 10**9,
                )

    def test_query_timeline_command_filter_finds_sudo_commands(self):
        timeline = self.service.query_session_timeline(
            self.risky_session_id,
            command_contains="sudo",
        )

        self.assertTrue(timeline)
        commands = [entry.command for entry in timeline]
        self.assertIn("sudo su -", commands)
        self.assertIn("sudo useradd hacker123", commands)
        self.assertTrue(all("sudo" in (entry.command or "").lower() for entry in timeline))

    def test_query_timeline_command_filter_is_case_insensitive(self):
        lower = self.service.query_session_timeline(
            self.risky_session_id,
            command_contains="chmod",
        )
        upper = self.service.query_session_timeline(
            self.risky_session_id,
            command_contains="CHMOD",
        )

        self.assertEqual(lower, upper)

    def test_query_timeline_preserves_risk_and_output(self):
        timeline = self.service.query_session_timeline(
            self.risky_session_id,
            command_contains="chmod 777",
        )

        self.assertTrue(timeline)
        entry = next(item for item in timeline if item.command == "chmod 777 /etc/passwd")

        categories = {finding.category for finding in entry.risk_findings}
        self.assertIn("PERMISSION_MODIFICATION", categories)

        full_timeline = self.service.get_session_timeline(self.risky_session_id)
        source = next(item for item in full_timeline if item.sequence_number == entry.sequence_number)
        self.assertEqual(entry.output, source.output)

    def test_query_timeline_unknown_session_is_empty(self):
        timeline = self.service.query_session_timeline("00000000-0000-0000-0000-000000000000")
        self.assertEqual(timeline, [])

    def test_query_timeline_benign_session_has_no_risk(self):
        timeline = self.service.query_session_timeline(self.benign_session_id)

        self.assertTrue(timeline)
        commands = [entry.command for entry in timeline if entry.event_type == "COMMAND"]
        self.assertIn("whoami", commands)

        for entry in timeline:
            if entry.event_type == "COMMAND":
                self.assertEqual(entry.risk_findings, ())

    def test_query_timeline_supports_commands_and_events_composition(self):
        full_timeline = self.service.query_session_timeline(self.risky_session_id)
        commands_only = self.service.query_session_timeline(
            self.risky_session_id,
            include_events=False,
        )
        events_only = self.service.query_session_timeline(
            self.risky_session_id,
            include_commands=False,
        )

        command_count = len(self.service.get_command_evidence(self.risky_session_id))
        raw_events = self.service.get_events(self.risky_session_id)
        # command_executed events restate a command already in session_commands and
        # are excluded from the assembled timeline to avoid duplicate entries.
        non_echo_event_count = sum(
            1 for event in raw_events if (event.event_type or "").lower() != "command_executed"
        )

        self.assertEqual(len(commands_only), command_count)
        self.assertEqual(len(events_only), non_echo_event_count)
        self.assertEqual(len(full_timeline), command_count + non_echo_event_count)


if __name__ == "__main__":
    unittest.main()
