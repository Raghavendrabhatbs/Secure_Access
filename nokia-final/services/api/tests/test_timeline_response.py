import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.timeline_response import (
    find_timeline_anchor_index,
    format_first_risky_timeline_entry,
    format_last_command_entry,
    format_timeline_relative_to_command,
    format_timeline_relative_to_risk,
    format_timeline_summary,
    format_when_risk_occurred,
)


class TimelineResponseTest(unittest.TestCase):
    def setUp(self):
        self.timeline = [
            {
                "timestamp": "2026-08-10 10:01:01+00:00",
                "sequence_number": 1,
                "event_type": "COMMAND",
                "command": "whoami",
                "output": "admin",
                "risk_findings": [],
            },
            {
                "timestamp": "2026-08-10 10:01:05+00:00",
                "sequence_number": 2,
                "event_type": "COMMAND",
                "command": "sudo su -",
                "output": "",
                "risk_findings": [
                    {
                        "category": "PRIVILEGE_ESCALATION",
                        "severity": "HIGH",
                        "rule": "SUDO",
                    }
                ],
            },
            {
                "timestamp": "2026-08-10 10:01:08+00:00",
                "sequence_number": 3,
                "event_type": "COMMAND",
                "command": "sudo useradd hacker123",
                "output": "",
                "risk_findings": [
                    {
                        "category": "PRIVILEGE_ESCALATION",
                        "severity": "HIGH",
                        "rule": "SUDO",
                    },
                    {
                        "category": "ACCOUNT_MODIFICATION",
                        "severity": "MEDIUM",
                        "rule": "USERADD",
                    },
                ],
            },
        ]

        self.analysis = {
            "entry_count": 3,
            "command_count": 3,
            "event_count": 0,
            "overall_severity": "HIGH",
            "risk_categories": [
                "ACCOUNT_MODIFICATION",
                "PRIVILEGE_ESCALATION",
            ],
        }

    def test_empty_timeline_summary(self):
        result = format_timeline_summary([], {})
        self.assertIn("No timeline entries", result)

    def test_first_risky_entry_skips_benign_leading_command(self):
        result = format_first_risky_timeline_entry(self.timeline)

        self.assertIn("First risky action:", result)
        self.assertIn("Command: sudo su -", result)
        self.assertIn("Risk: HIGH", result)
        self.assertIn("Category: PRIVILEGE_ESCALATION", result)
        self.assertNotIn("whoami", result)

    def test_first_risky_entry_empty_timeline(self):
        result = format_first_risky_timeline_entry([])
        self.assertIn("No timeline entries", result)

    def test_first_risky_entry_no_findings_anywhere(self):
        benign_timeline = [
            {
                "timestamp": "2026-08-10 10:01:01+00:00",
                "sequence_number": 1,
                "event_type": "COMMAND",
                "command": "whoami",
                "output": "admin",
                "risk_findings": [],
            }
        ]

        result = format_first_risky_timeline_entry(benign_timeline)
        self.assertIn("No risky timeline entries", result)

    def test_when_risk_occurred_returns_all_matching_occurrences(self):
        result = format_when_risk_occurred(
            self.timeline,
            "PRIVILEGE_ESCALATION",
        )

        self.assertIn("PRIVILEGE_ESCALATION occurred at:", result)
        self.assertIn("2026-08-10 10:01:05+00:00", result)
        self.assertIn("2026-08-10 10:01:08+00:00", result)
        self.assertIn("Command: sudo su -", result)
        self.assertIn("Command: sudo useradd hacker123", result)
        self.assertEqual(
            result.count("Category: PRIVILEGE_ESCALATION"),
            2,
        )

    def test_when_risk_occurred_returns_single_matching_occurrence(self):
        result = format_when_risk_occurred(
            self.timeline,
            "ACCOUNT_MODIFICATION",
        )

        self.assertIn("ACCOUNT_MODIFICATION occurred at:", result)
        self.assertIn("2026-08-10 10:01:08+00:00", result)
        self.assertIn("Command: sudo useradd hacker123", result)
        self.assertIn("Risk: MEDIUM", result)
        self.assertEqual(
            result.count("Category: ACCOUNT_MODIFICATION"),
            1,
        )

    def test_when_risk_occurred_returns_all_matching_occurrences(self):
        result = format_when_risk_occurred(
            self.timeline,
            "PRIVILEGE_ESCALATION",
        )

        self.assertIn("PRIVILEGE_ESCALATION occurred at:", result)
        self.assertIn("2026-08-10 10:01:05+00:00", result)
        self.assertIn("2026-08-10 10:01:08+00:00", result)
        self.assertIn("Command: sudo su -", result)
        self.assertIn("Command: sudo useradd hacker123", result)
        self.assertIn("Risk: HIGH", result)

    def test_when_risk_occurred_unknown_category_does_not_fabricate(self):
        result = format_when_risk_occurred(
            self.timeline,
            "MALWARE_EXECUTION",
        )

        self.assertEqual(
            result,
            "No MALWARE_EXECUTION findings were found in this session.",
        )

    def test_when_risk_occurred_empty_timeline(self):
        result = format_when_risk_occurred(
            [],
            "PRIVILEGE_ESCALATION",
        )

        self.assertEqual(
            result,
            "No PRIVILEGE_ESCALATION findings were found in this session.",
        )

    def test_when_risk_occurred_unknown_category_does_not_fabricate(self):
        result = format_when_risk_occurred(
            self.timeline,
            "MALWARE_EXECUTION",
        )

        self.assertEqual(
            result,
            "No MALWARE_EXECUTION findings were found in this session.",
        )

    def test_last_command_entry_ignores_trailing_events(self):
        timeline_with_trailing_event = self.timeline + [
            {
                "timestamp": "2026-08-10 10:01:10+00:00",
                "sequence_number": None,
                "event_type": "session_ended",
                "command": "Session ended",
                "output": "",
                "risk_findings": [],
            }
        ]

        result = format_last_command_entry(timeline_with_trailing_event)

        self.assertEqual(
            result,
            "Last command:\n\nsudo useradd hacker123",
        )

    def test_last_command_entry_empty_timeline(self):
        result = format_last_command_entry([])
        self.assertIn("No timeline entries", result)

    def test_last_command_entry_no_commands(self):
        events_only = [
            {
                "timestamp": "2026-08-10 10:01:01+00:00",
                "sequence_number": None,
                "event_type": "session_started",
                "command": "Session started",
                "output": "",
                "risk_findings": [],
            }
        ]

        result = format_last_command_entry(events_only)
        self.assertIn("No commands were identified", result)

    def test_find_timeline_anchor_index_matches_command(self):
        index = find_timeline_anchor_index(
            self.timeline,
            "sudo su -",
        )

        self.assertEqual(index, 1)

    def test_find_timeline_anchor_index_unknown_command(self):
        index = find_timeline_anchor_index(
            self.timeline,
            "rm -rf /",
        )

        self.assertIsNone(index)

    def test_after_command_anchor(self):
        result = format_timeline_relative_to_command(
            self.timeline,
            "sudo su -",
            "after",
        )

        self.assertIn(
            'Entries after "sudo su -":',
            result,
        )
        self.assertIn(
            "sudo useradd hacker123",
            result,
        )
        self.assertNotIn(
            "whoami",
            result,
        )

    def test_before_command_anchor(self):
        result = format_timeline_relative_to_command(
            self.timeline,
            "sudo useradd hacker123",
            "before",
        )

        self.assertIn(
            'Entries before "sudo useradd hacker123":',
            result,
        )
        self.assertIn(
            "whoami",
            result,
        )
        self.assertIn(
            "sudo su -",
            result,
        )
        self.assertNotIn(
            "hacker123",
            result.split(":", 1)[-1],
        )

    def test_before_first_command_returns_no_entries_message(self):
        result = format_timeline_relative_to_command(
            self.timeline,
            "whoami",
            "before",
        )

        self.assertEqual(
            result,
            'No entries occurred before "whoami".',
        )

    def test_after_last_command_returns_no_entries_message(self):
        result = format_timeline_relative_to_command(
            self.timeline,
            "sudo useradd hacker123",
            "after",
        )

        self.assertEqual(
            result,
            'No entries occurred after "sudo useradd hacker123".',
        )

    def test_unknown_command_anchor_does_not_fabricate(self):
        result = format_timeline_relative_to_command(
            self.timeline,
            "rm -rf /",
            "after",
        )

        self.assertEqual(
            result,
            'I couldn\'t find the command "rm -rf /" in this session timeline.',
        )

    def test_relative_to_command_empty_timeline(self):
        result = format_timeline_relative_to_command(
            [],
            "sudo su -",
            "after",
        )

        self.assertIn(
            "No timeline entries",
            result,
        )

    def test_summary_contains_commands_and_overall_risk(self):
        result = format_timeline_summary(
            self.timeline,
            self.analysis,
        )

        self.assertIn(
            "Session timeline:",
            result,
        )
        self.assertIn(
            "whoami",
            result,
        )
        self.assertIn(
            "sudo su -",
            result,
        )
        self.assertIn(
            "Overall risk: HIGH",
            result,
        )

    def test_summary_contains_risk_labels(self):
        result = format_timeline_summary(
            self.timeline,
            self.analysis,
        )

        self.assertIn(
            "PRIVILEGE_ESCALATION / HIGH",
            result,
        )
        self.assertIn(
            "ACCOUNT_MODIFICATION / MEDIUM",
            result,
        )

    def test_before_risk_category_returns_prior_entries(self):
        result = format_timeline_relative_to_risk(
            self.timeline,
            self.analysis,
            "PRIVILEGE_ESCALATION",
            "before",
        )

        self.assertIn(
            "before the first PRIVILEGE_ESCALATION",
            result,
        )
        self.assertIn(
            "whoami",
            result,
        )
        self.assertNotIn(
            "sudo useradd hacker123",
            result,
        )

    def test_after_risk_category_returns_following_entries(self):
        result = format_timeline_relative_to_risk(
            self.timeline,
            self.analysis,
            "PRIVILEGE_ESCALATION",
            "after",
        )

        self.assertIn(
            "after the first PRIVILEGE_ESCALATION",
            result,
        )
        self.assertIn(
            "sudo useradd hacker123",
            result,
        )
        self.assertNotIn(
            "whoami",
            result,
        )

    def test_missing_category_message(self):
        result = format_timeline_relative_to_risk(
            self.timeline,
            self.analysis,
            "DESTRUCTIVE_OPERATION",
            "before",
        )

        self.assertIn(
            "No timeline entries with DESTRUCTIVE_OPERATION",
            result,
        )

    def test_no_entries_before_category_message(self):
        result = format_timeline_relative_to_risk(
            self.timeline[1:],
            self.analysis,
            "PRIVILEGE_ESCALATION",
            "before",
        )

        self.assertIn(
            "No timeline entries occurred before",
            result,
        )

    def test_deterministic_output(self):
        one = format_timeline_summary(
            self.timeline,
            self.analysis,
        )
        two = format_timeline_summary(
            self.timeline,
            self.analysis,
        )

        self.assertEqual(
            one,
            two,
        )


if __name__ == "__main__":
    unittest.main()