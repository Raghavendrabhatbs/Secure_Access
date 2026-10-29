import sys
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.risk_classifier import RiskFinding
from app.services.timeline import TimelineEntry
from app.services.timeline_analyzer import analyze_timeline


def _entry(
    timestamp,
    sequence_number,
    event_type,
    command,
    output="",
    risk_findings=None,
):
    return TimelineEntry(
        timestamp=timestamp,
        sequence_number=sequence_number,
        event_type=event_type,
        command=command,
        output=output,
        risk_findings=risk_findings,
    )


class TestTimelineAnalyzer(unittest.TestCase):
    def test_empty_timeline(self):
        analysis = analyze_timeline([])
        self.assertEqual(analysis.entry_count, 0)
        self.assertEqual(analysis.command_count, 0)
        self.assertEqual(analysis.event_count, 0)
        self.assertIsNone(analysis.first_timestamp)
        self.assertIsNone(analysis.last_timestamp)
        self.assertEqual(analysis.commands, ())
        self.assertEqual(analysis.event_types, ())
        self.assertEqual(analysis.risk_findings, ())
        self.assertEqual(analysis.high_count, 0)
        self.assertEqual(analysis.medium_count, 0)
        self.assertEqual(analysis.low_count, 0)
        self.assertEqual(analysis.risk_categories, ())

    def test_single_command(self):
        entries = [
            _entry(
                datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc),
                1,
                "COMMAND",
                "whoami",
                "admin",
                [],
            )
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(analysis.entry_count, 1)
        self.assertEqual(analysis.command_count, 1)
        self.assertEqual(analysis.event_count, 0)
        self.assertEqual(analysis.commands, ("whoami",))

    def test_single_event(self):
        entries = [
            _entry(
                datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc),
                None,
                "SESSION_STARTED",
                "Session started",
                "",
                (),
            )
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(analysis.entry_count, 1)
        self.assertEqual(analysis.command_count, 0)
        self.assertEqual(analysis.event_count, 1)
        self.assertEqual(analysis.event_types, ("SESSION_STARTED",))

    def test_mixed_commands_and_events(self):
        entries = [
            _entry(datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc), None, "SESSION_STARTED", "start"),
            _entry(datetime(2026, 8, 10, 12, 2, tzinfo=timezone.utc), 1, "COMMAND", "whoami"),
            _entry(datetime(2026, 8, 10, 12, 3, tzinfo=timezone.utc), 2, "COMMAND", "sudo su -"),
            _entry(datetime(2026, 8, 10, 12, 4, tzinfo=timezone.utc), None, "SESSION_ENDED", "end"),
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(analysis.entry_count, 4)
        self.assertEqual(analysis.command_count, 2)
        self.assertEqual(analysis.event_count, 2)

    def test_chronological_ordering_applied(self):
        entries = [
            _entry(datetime(2026, 8, 10, 12, 4, tzinfo=timezone.utc), 4, "COMMAND", "chmod 777 /etc/passwd"),
            _entry(datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc), 1, "COMMAND", "whoami"),
            _entry(datetime(2026, 8, 10, 12, 2, tzinfo=timezone.utc), 2, "COMMAND", "sudo su -"),
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(
            analysis.commands,
            ("whoami", "sudo su -", "chmod 777 /etc/passwd"),
        )

    def test_first_timestamp(self):
        entries = [
            _entry(datetime(2026, 8, 10, 12, 5, tzinfo=timezone.utc), 2, "COMMAND", "b"),
            _entry(datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc), 1, "COMMAND", "a"),
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(analysis.first_timestamp, datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc))

    def test_last_timestamp(self):
        entries = [
            _entry(datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc), 1, "COMMAND", "a"),
            _entry(datetime(2026, 8, 10, 12, 5, tzinfo=timezone.utc), 2, "COMMAND", "b"),
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(analysis.last_timestamp, datetime(2026, 8, 10, 12, 5, tzinfo=timezone.utc))

    def test_high_risk_count(self):
        entries = [
            _entry(
                datetime(2026, 8, 10, 12, 2, tzinfo=timezone.utc),
                1,
                "COMMAND",
                "sudo su -",
                risk_findings=(
                    RiskFinding("PRIVILEGE_ESCALATION", "HIGH", "SUDO"),
                ),
            )
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(analysis.high_count, 1)
        self.assertEqual(analysis.overall_severity, "HIGH")

    def test_mixed_severity_counts(self):
        entries = [
            _entry(
                datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc),
                1,
                "COMMAND",
                "c1",
                risk_findings=(RiskFinding("A", "HIGH", "R1"),),
            ),
            _entry(
                datetime(2026, 8, 10, 12, 2, tzinfo=timezone.utc),
                2,
                "COMMAND",
                "c2",
                risk_findings=(RiskFinding("B", "MEDIUM", "R2"),),
            ),
            _entry(
                datetime(2026, 8, 10, 12, 3, tzinfo=timezone.utc),
                3,
                "COMMAND",
                "c3",
                risk_findings=(RiskFinding("C", "LOW", "R3"),),
            ),
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(analysis.high_count, 1)
        self.assertEqual(analysis.medium_count, 1)
        self.assertEqual(analysis.low_count, 1)

    def test_multiple_findings_on_one_command_preserved(self):
        entries = [
            _entry(
                datetime(2026, 8, 10, 12, 3, tzinfo=timezone.utc),
                3,
                "COMMAND",
                "sudo useradd hacker123",
                risk_findings=(
                    RiskFinding("PRIVILEGE_ESCALATION", "HIGH", "SUDO"),
                    RiskFinding("ACCOUNT_MODIFICATION", "MEDIUM", "USERADD"),
                ),
            )
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(len(analysis.risk_findings), 2)
        categories = {finding.category for finding in analysis.risk_findings}
        self.assertIn("PRIVILEGE_ESCALATION", categories)
        self.assertIn("ACCOUNT_MODIFICATION", categories)

    def test_category_deduplication(self):
        entries = [
            _entry(
                datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc),
                1,
                "COMMAND",
                "a",
                risk_findings=(RiskFinding("PRIVILEGE_ESCALATION", "HIGH", "R1"),),
            ),
            _entry(
                datetime(2026, 8, 10, 12, 2, tzinfo=timezone.utc),
                2,
                "COMMAND",
                "b",
                risk_findings=(
                    RiskFinding("PRIVILEGE_ESCALATION", "HIGH", "R2"),
                    RiskFinding("ACCOUNT_MODIFICATION", "MEDIUM", "R3"),
                ),
            ),
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(
            analysis.risk_categories,
            ("ACCOUNT_MODIFICATION", "PRIVILEGE_ESCALATION"),
        )

    def test_no_risk_fabrication(self):
        entries = [
            _entry(datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc), 1, "COMMAND", "whoami"),
            _entry(datetime(2026, 8, 10, 12, 2, tzinfo=timezone.utc), 2, "COMMAND", "pwd"),
            _entry(datetime(2026, 8, 10, 12, 3, tzinfo=timezone.utc), 3, "COMMAND", "ls"),
            _entry(datetime(2026, 8, 10, 12, 4, tzinfo=timezone.utc), 4, "COMMAND", "date"),
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(analysis.high_count, 0)
        self.assertEqual(analysis.medium_count, 0)
        self.assertEqual(analysis.low_count, 0)
        self.assertEqual(analysis.risk_categories, ())

    def test_analysis_is_frozen(self):
        analysis = analyze_timeline([])
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            analysis.entry_count = 99

    def test_deterministic_repeated_analysis(self):
        entries = [
            _entry(datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc), 1, "COMMAND", "whoami"),
            _entry(datetime(2026, 8, 10, 12, 2, tzinfo=timezone.utc), 2, "COMMAND", "sudo su -"),
        ]
        first = analyze_timeline(entries)
        second = analyze_timeline(entries)
        self.assertEqual(first, second)

    def test_command_order_preserved(self):
        entries = [
            _entry(datetime(2026, 8, 10, 12, 3, tzinfo=timezone.utc), 3, "COMMAND", "chmod 777 /etc/passwd"),
            _entry(datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc), 1, "COMMAND", "whoami"),
            _entry(datetime(2026, 8, 10, 12, 2, tzinfo=timezone.utc), 2, "COMMAND", "sudo su -"),
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(analysis.commands, ("whoami", "sudo su -", "chmod 777 /etc/passwd"))

    def test_event_order_preserved(self):
        entries = [
            _entry(datetime(2026, 8, 10, 12, 2, tzinfo=timezone.utc), None, "SESSION_ENDED", "end"),
            _entry(datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc), None, "SESSION_STARTED", "start"),
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(analysis.event_types, ("SESSION_STARTED", "SESSION_ENDED"))

    def test_missing_timestamp_handled(self):
        entries = [
            _entry(None, 2, "COMMAND", "no-ts"),
            _entry(datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc), 1, "COMMAND", "with-ts"),
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(analysis.entry_count, 2)
        self.assertEqual(analysis.first_timestamp, datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc))
        self.assertEqual(analysis.last_timestamp, datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc))

    def test_missing_risk_findings_handled(self):
        entries = [
            _entry(
                datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc),
                1,
                "COMMAND",
                "whoami",
                risk_findings=None,
            )
        ]
        analysis = analyze_timeline(entries)
        self.assertEqual(analysis.risk_findings, ())

    def test_large_realistic_timeline(self):
        entries = [
            _entry(datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc), None, "SESSION_STARTED", "start"),
            _entry(datetime(2026, 8, 10, 12, 1, tzinfo=timezone.utc), 1, "COMMAND", "whoami", "admin"),
            _entry(datetime(2026, 8, 10, 12, 2, tzinfo=timezone.utc), 2, "COMMAND", "hostname", "lab1"),
            _entry(datetime(2026, 8, 10, 12, 3, tzinfo=timezone.utc), 3, "COMMAND", "pwd", "/home/admin"),
            _entry(datetime(2026, 8, 10, 12, 4, tzinfo=timezone.utc), 4, "COMMAND", "sudo su -", risk_findings=(RiskFinding("PRIVILEGE_ESCALATION", "HIGH", "SUDO"),)),
            _entry(datetime(2026, 8, 10, 12, 5, tzinfo=timezone.utc), 5, "COMMAND", "whoami", "root"),
            _entry(datetime(2026, 8, 10, 12, 6, tzinfo=timezone.utc), 6, "COMMAND", "sudo useradd hacker123", risk_findings=(RiskFinding("PRIVILEGE_ESCALATION", "HIGH", "SUDO"), RiskFinding("ACCOUNT_MODIFICATION", "MEDIUM", "USERADD"))),
            _entry(datetime(2026, 8, 10, 12, 7, tzinfo=timezone.utc), 7, "COMMAND", "chmod 777 /etc/passwd", risk_findings=(RiskFinding("PERMISSION_MODIFICATION", "HIGH", "CHMOD_777"),)),
            _entry(datetime(2026, 8, 10, 12, 8, tzinfo=timezone.utc), None, "AUTHENTICATION", "reauth"),
            _entry(datetime(2026, 8, 10, 12, 9, tzinfo=timezone.utc), 8, "COMMAND", "date"),
            _entry(datetime(2026, 8, 10, 12, 10, tzinfo=timezone.utc), None, "SESSION_ENDED", "end"),
        ]

        analysis = analyze_timeline(entries)

        self.assertEqual(analysis.entry_count, 11)
        self.assertEqual(analysis.command_count, 8)
        self.assertEqual(analysis.event_count, 3)
        self.assertEqual(analysis.high_count, 3)
        self.assertEqual(analysis.medium_count, 1)
        self.assertEqual(analysis.low_count, 0)
        self.assertEqual(
            analysis.risk_categories,
            (
                "ACCOUNT_MODIFICATION",
                "PERMISSION_MODIFICATION",
                "PRIVILEGE_ESCALATION",
            ),
        )
        self.assertEqual(
            analysis.significant_events,
            ("SESSION_STARTED", "AUTHENTICATION", "SESSION_ENDED"),
        )


if __name__ == "__main__":
    unittest.main()
