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


class SessionTimelineIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        self.service = SessionQueryService(self.db)

        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def tearDown(self):
        self.db.close()

    def test_risky_session_returns_timeline(self):
        timeline = self.service.get_session_timeline(self.risky_session_id)

        self.assertTrue(timeline)

        commands = [entry.command for entry in timeline]

        self.assertIn("sudo su -", commands)
        self.assertIn("sudo useradd hacker123", commands)
        self.assertIn("chmod 777 /etc/passwd", commands)

    def test_timeline_is_chronological(self):
        timeline = self.service.get_session_timeline(self.risky_session_id)

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

    def test_timeline_preserves_sequence_numbers(self):
        timeline = self.service.get_session_timeline(self.risky_session_id)

        command_entries = [entry for entry in timeline if entry.event_type == "COMMAND"]
        sequence_numbers = [entry.sequence_number for entry in command_entries if entry.sequence_number is not None]
        original_sequence_numbers = [
            item.sequence_number
            for item in self.service.get_command_evidence(self.risky_session_id)
            if item.sequence_number is not None
        ]

        self.assertTrue(sequence_numbers)
        self.assertEqual(sequence_numbers, sorted(sequence_numbers))
        self.assertEqual(sequence_numbers, original_sequence_numbers)

    def test_timeline_preserves_risk_findings(self):
        timeline = self.service.get_session_timeline(self.risky_session_id)

        sudo_entry = next(
            entry for entry in timeline
            if entry.command == "sudo su -"
        )
        chmod_entry = next(
            entry for entry in timeline
            if entry.command == "chmod 777 /etc/passwd"
        )

        self.assertTrue(sudo_entry.risk_findings)
        sudo_categories = {
            finding.category
            for finding in sudo_entry.risk_findings
        }
        self.assertIn("PRIVILEGE_ESCALATION", sudo_categories)

        chmod_categories = {
            finding.category
            for finding in chmod_entry.risk_findings
        }
        self.assertIn("PERMISSION_MODIFICATION", chmod_categories)

    def test_timeline_preserves_command_output(self):
        timeline = self.service.get_session_timeline(self.risky_session_id)

        original_evidence = self.service.get_command_evidence(
            self.risky_session_id
        )

        evidence_by_sequence = {
            item.sequence_number: item
            for item in original_evidence
        }

        for entry in timeline:
            if entry.event_type != "COMMAND":
                continue
            original = evidence_by_sequence[entry.sequence_number]
            self.assertEqual(
                entry.output,
                original.output or "",
            )

    def test_timeline_includes_all_retrieved_commands_and_events(self):
        timeline = self.service.get_session_timeline(self.risky_session_id)
        command_evidence = self.service.get_command_evidence(self.risky_session_id)
        events = self.service.get_events(self.risky_session_id)
        # command_executed events restate a command already in session_commands and
        # are excluded from the assembled timeline to avoid duplicate entries.
        non_echo_events = [
            event for event in events if (event.event_type or "").lower() != "command_executed"
        ]

        command_entries = [entry for entry in timeline if entry.event_type == "COMMAND"]

        self.assertEqual(len(command_entries), len(command_evidence))
        self.assertEqual(len(timeline), len(command_evidence) + len(non_echo_events))

    def test_benign_session_returns_timeline_without_risk(self):
        timeline = self.service.get_session_timeline(self.benign_session_id)

        self.assertTrue(timeline)

        commands = [entry.command for entry in timeline]

        self.assertIn("whoami", commands)

        whoami_entry = next(
            entry for entry in timeline
            if entry.command == "whoami"
        )

        self.assertEqual(whoami_entry.risk_findings, ())

    def test_unknown_session_returns_empty_timeline(self):
        timeline = self.service.get_session_timeline(
            "00000000-0000-0000-0000-000000000000"
        )

        self.assertEqual(timeline, [])

    def test_command_entries_have_command_event_type(self):
        timeline = self.service.get_session_timeline(self.risky_session_id)
        command_evidence = self.service.get_command_evidence(self.risky_session_id)

        self.assertTrue(timeline)

        timeline_by_sequence = {
            entry.sequence_number: entry
            for entry in timeline
            if entry.sequence_number is not None and entry.event_type == "COMMAND"
        }

        self.assertTrue(
            all(
                evidence.sequence_number in timeline_by_sequence
                for evidence in command_evidence
                if evidence.sequence_number is not None
            )
        )


if __name__ == "__main__":
    unittest.main()
